import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from nulara.core.errors import ThreadExpectationError, ThreadProtocolError

ERROR_TYPES = frozenset({"RUN_ERROR", "STREAM_ERROR"})
TERMINAL_TYPES = frozenset(
    {
        "CANCELLED",
        "COMPLETE",
        "RUN_FINISHED",
        "RUN_INTERRUPTED",
        "RUN_ERROR",
        "STREAM_ERROR",
    }
)
SECRET_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "cookie",
        "password",
        "session_token",
        "set-cookie",
        "token",
    }
)


def parse_sse(lines: Iterable[str]) -> Iterable[dict[str, Any]]:
    data_lines: list[str] = []
    for line in lines:
        if line == "":
            if data_lines:
                yield _parse_event(data_lines)
                data_lines.clear()
            continue
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if field == "data":
            data_lines.append(
                value[1:] if separator and value.startswith(" ") else value
            )
    if data_lines:
        yield _parse_event(data_lines)


def _parse_event(data_lines: list[str]) -> dict[str, Any]:
    raw = "\n".join(data_lines)
    try:
        event = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ThreadProtocolError(f"Invalid SSE JSON: {exc.msg}") from exc
    if not isinstance(event, dict) or not isinstance(event.get("type"), str):
        raise ThreadProtocolError("SSE event must be an object with a string `type`")
    return event


@dataclass(frozen=True)
class ThreadRunSummary:
    test_run_id: str
    status: str
    terminal_type: str | None
    thread_id: str | None
    event_count: int
    event_types: dict[str, int]
    tool_names: list[str]
    errors: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def summarize_run(events: list[dict[str, Any]], test_run_id: str) -> ThreadRunSummary:
    event_types = Counter(str(event["type"]) for event in events)
    terminal_types = [
        str(event["type"]) for event in events if event["type"] in TERMINAL_TYPES
    ]
    # The backend closes an interrupted run with COMPLETE after RUN_INTERRUPTED
    # (thread_backend.agents.streaming); the interrupt is the run's outcome.
    if "RUN_INTERRUPTED" in terminal_types:
        terminal_type: str | None = "RUN_INTERRUPTED"
    else:
        terminal_type = terminal_types[-1] if terminal_types else None
    thread_id = next(
        (
            str(event["thread_id"])
            for event in reversed(events)
            if event.get("thread_id")
        ),
        None,
    )
    errors = [redact_secrets(event) for event in events if event["type"] in ERROR_TYPES]
    if errors or terminal_type in ERROR_TYPES:
        status = "error"
    elif terminal_type == "RUN_INTERRUPTED":
        status = "interrupted"
    elif terminal_type == "CANCELLED":
        status = "cancelled"
    elif terminal_type in {"COMPLETE", "RUN_FINISHED"}:
        status = "completed"
    else:
        status = "incomplete"
    tools = sorted(
        {str(event["tool_name"]) for event in events if event.get("tool_name")}
    )
    return ThreadRunSummary(
        test_run_id=test_run_id,
        status=status,
        terminal_type=terminal_type,
        thread_id=thread_id,
        event_count=len(events),
        event_types=dict(sorted(event_types.items())),
        tool_names=tools,
        errors=errors,
    )


def assistant_text(events: Iterable[Mapping[str, Any]]) -> str:
    """Join model text deltas without treating tool or status events as content."""
    return "".join(
        str(event["delta"])
        for event in events
        if event.get("type") == "MESSAGE_DELTA" and event.get("delta") is not None
    )


def latest_interrupt(events: Iterable[Mapping[str, Any]]) -> dict[str, Any] | None:
    """Return the newest validated HITL payload from a stream."""
    for event in reversed(list(events)):
        if event.get("type") != "RUN_INTERRUPTED":
            continue
        payload = event.get("interrupt_data")
        if not isinstance(payload, dict):
            raise ThreadProtocolError("RUN_INTERRUPTED is missing `interrupt_data`")
        requests = payload.get("action_requests")
        if not isinstance(requests, list) or not requests:
            raise ThreadProtocolError(
                "RUN_INTERRUPTED must contain at least one action request"
            )
        return payload
    return None


def redact_secrets(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]"
            if str(key).lower() in SECRET_KEYS
            else redact_secrets(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return value


def write_artifacts(
    directory: Path,
    events: list[dict[str, Any]],
    summary: ThreadRunSummary,
    interactions: Any = None,
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    safe_events = [redact_secrets(event) for event in events]
    event_text = "".join(
        f"{json.dumps(event, ensure_ascii=False, separators=(',', ':'))}\n"
        for event in safe_events
    )
    (directory / "events.jsonl").write_text(event_text, encoding="utf-8")
    _write_json(directory / "summary.json", summary.to_dict())
    if interactions is not None:
        _write_json(
            directory / "persisted-interactions.json", redact_secrets(interactions)
        )


def assert_expectations(
    summary: ThreadRunSummary,
    *,
    terminal_type: str | None = None,
    required_event_types: Iterable[str] = (),
    forbidden_event_types: Iterable[str] = (),
    required_tools: Iterable[str] = (),
    require_persisted_interactions: bool = False,
    interactions: Any = None,
) -> None:
    failures: list[str] = []
    if summary.status == "incomplete":
        failures.append("stream has no terminal event")
    if terminal_type and summary.terminal_type != terminal_type:
        failures.append(
            f"terminal event is {summary.terminal_type!r}, expected {terminal_type!r}"
        )
    for event_type in required_event_types:
        if event_type not in summary.event_types:
            failures.append(f"missing event type {event_type!r}")
    for event_type in forbidden_event_types:
        if event_type in summary.event_types:
            failures.append(f"unexpected event type {event_type!r}")
    for tool_name in required_tools:
        if tool_name not in summary.tool_names:
            failures.append(f"missing tool {tool_name!r}")
    if summary.errors:
        failures.append("stream contains an error event")
    if require_persisted_interactions and not _has_interactions(interactions):
        failures.append("no persisted interactions were returned")
    if failures:
        raise ThreadExpectationError(
            "Thread expectations failed: " + "; ".join(failures)
        )


def _has_interactions(payload: Any) -> bool:
    if isinstance(payload, list):
        return bool(payload)
    if isinstance(payload, dict):
        items = payload.get("interactions")
        return isinstance(items, list) and bool(items)
    return False


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

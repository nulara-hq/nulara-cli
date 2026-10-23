import json

import pytest

from nulara.core.errors import ThreadExpectationError, ThreadProtocolError
from nulara.core.thread import (
    assert_expectations,
    assistant_text,
    latest_interrupt,
    parse_sse,
    redact_secrets,
    summarize_run,
    write_artifacts,
)


def test_parser_handles_comments_multiline_and_final_event() -> None:
    lines = [
        ": keepalive",
        "",
        "event: ignored",
        'data: {"type":',
        'data: "MESSAGE_START"}',
        "",
        'data:{"type":"COMPLETE","thread_id":"thread-1"}',
    ]
    assert list(parse_sse(lines)) == [
        {"type": "MESSAGE_START"},
        {"type": "COMPLETE", "thread_id": "thread-1"},
    ]


@pytest.mark.parametrize(
    "line,match",
    [
        ("data: nope", "Invalid SSE JSON"),
        ("data: []", "must be an object"),
        ("data: {}", "must be an object"),
    ],
)
def test_parser_rejects_invalid_events(line: str, match: str) -> None:
    with pytest.raises(ThreadProtocolError, match=match):
        list(parse_sse([line, ""]))


def test_summary_artifacts_and_expectations(tmp_path) -> None:
    events = [
        {"type": "RUN_STARTED", "thread_id": "thread-1"},
        {"type": "TOOL_START", "tool_name": "search", "token": "secret"},
        {"type": "TOOL_RESULT", "tool_name": "search"},
        {"type": "COMPLETE", "thread_id": "thread-1"},
    ]
    summary = summarize_run(events, "run-1")
    assert summary.status == "completed"
    assert summary.event_types["TOOL_START"] == 1
    assert summary.tool_names == ["search"]

    interrupted = summarize_run(
        [
            {"type": "RUN_STARTED", "thread_id": "thread-1"},
            {
                "type": "RUN_INTERRUPTED",
                "thread_id": "thread-1",
                "interrupt_data": {"action_requests": [{"id": "a1"}]},
            },
            {"type": "COMPLETE", "thread_id": "thread-1"},
        ],
        "run-2",
    )
    assert interrupted.status == "interrupted"
    assert interrupted.terminal_type == "RUN_INTERRUPTED"

    interactions = {"interactions": [{"id": "one", "password": "secret"}]}
    write_artifacts(tmp_path, events, summary, interactions)
    write_artifacts(tmp_path / "without-interactions", events, summary)
    assert json.loads((tmp_path / "summary.json").read_text())["status"] == "completed"
    assert (
        json.loads((tmp_path / "events.jsonl").read_text().splitlines()[1])["token"]
        == "[REDACTED]"
    )
    assert "secret" not in (tmp_path / "persisted-interactions.json").read_text()
    assert_expectations(
        summary,
        terminal_type="COMPLETE",
        required_event_types=["RUN_STARTED"],
        forbidden_event_types=["STREAM_ERROR"],
        required_tools=["search"],
        require_persisted_interactions=True,
        interactions=interactions,
    )


def test_error_interrupted_and_incomplete_summaries_fail_as_expected() -> None:
    interrupted = summarize_run(
        [{"type": "RUN_INTERRUPTED", "thread_id": "thread"}], "run"
    )
    assert interrupted.status == "interrupted"
    assert_expectations(interrupted)
    assert summarize_run([{"type": "CANCELLED"}], "run").status == "cancelled"

    failed = summarize_run(
        [{"type": "STREAM_ERROR", "detail": "bad", "authorization": "secret"}],
        "run",
    )
    assert failed.status == "error"
    assert failed.errors[0]["authorization"] == "[REDACTED]"
    with pytest.raises(ThreadExpectationError, match="error event"):
        assert_expectations(failed)

    incomplete = summarize_run([], "run")
    with pytest.raises(ThreadExpectationError, match="no terminal"):
        assert_expectations(incomplete)


def test_expectation_failure_lists_all_missing_invariants() -> None:
    summary = summarize_run([{"type": "COMPLETE"}], "run")
    with pytest.raises(ThreadExpectationError) as error:
        assert_expectations(
            summary,
            terminal_type="RUN_INTERRUPTED",
            required_event_types=["TOOL_START"],
            forbidden_event_types=["COMPLETE"],
            required_tools=["search"],
            require_persisted_interactions=True,
            interactions=[],
        )
    message = str(error.value)
    assert "terminal event" in message
    assert "missing event type" in message
    assert "unexpected event type" in message
    assert "missing tool" in message
    assert "no persisted interactions" in message


def test_redaction_supports_nested_lists_and_non_mapping_values() -> None:
    assert redact_secrets([{"cookie": "x"}, "safe"]) == [
        {"cookie": "[REDACTED]"},
        "safe",
    ]
    with pytest.raises(ThreadExpectationError, match="no persisted"):
        assert_expectations(
            summarize_run([{"type": "COMPLETE"}], "run"),
            require_persisted_interactions=True,
            interactions=None,
        )


def test_agent_text_and_interrupt_extraction() -> None:
    interrupt = {
        "action_requests": [
            {"id": "call-1", "name": "send_email", "args": {"to": ["a@b.test"]}}
        ],
        "review_configs": [],
    }
    events = [
        {"type": "MESSAGE_DELTA", "delta": "Hello "},
        {"type": "TOOL_START", "tool_name": "find_emails"},
        {"type": "MESSAGE_DELTA", "delta": "world"},
        {"type": "RUN_INTERRUPTED", "interrupt_data": interrupt},
    ]
    assert assistant_text(events) == "Hello world"
    assert latest_interrupt(events) == interrupt


@pytest.mark.parametrize(
    "event",
    [
        {"type": "RUN_INTERRUPTED"},
        {"type": "RUN_INTERRUPTED", "interrupt_data": {}},
    ],
)
def test_interrupt_extraction_rejects_incomplete_payloads(event) -> None:
    with pytest.raises(ThreadProtocolError, match="RUN_INTERRUPTED"):
        latest_interrupt([event])

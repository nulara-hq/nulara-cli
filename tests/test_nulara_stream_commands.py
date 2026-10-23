"""Synthetic Nulara streams exercise CLI completion, refusal and artifacts."""

import json

import httpx
import pytest
from support import NULARA_DEV

from nulara.core import main
from nulara.core.client import ApiClient
from nulara.core.config import Surface
from nulara.core.errors import CliError, ThreadProtocolError
from nulara.core.thread import latest_interrupt


@pytest.fixture
def app(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NULARA_API_TOKEN", "synthetic-token")
    monkeypatch.delenv("NULARA_API_URL", raising=False)
    return main.build_app(NULARA_DEV, Surface.DEVELOPMENT)


def install_transport(monkeypatch, batches, interactions=None, failure=None):
    calls = []

    def handle(request):
        calls.append(request)
        if request.url.path.endswith("/interactions"):
            return httpx.Response(
                500 if failure == "interactions" else 200,
                json=interactions
                or {"interactions": [{"id": "synthetic-interaction"}]},
            )
        events = batches.pop(0)
        content = "".join(f"data: {json.dumps(event)}\n\n" for event in events)
        if failure == "stream":
            content += "data: broken\n\n"
        return httpx.Response(
            200, text=content, headers={"Content-Type": "text/event-stream"}
        )

    monkeypatch.setattr(
        main,
        "ApiClient",
        lambda c, t: ApiClient(c, t, transport=httpx.MockTransport(handle)),
    )
    return calls


def invoke(app, args):
    with pytest.raises(SystemExit) as result:
        app(args, exit_on_error=False)
    assert result.value.code == 0


@pytest.mark.parametrize("json_output", [False, True])
@pytest.mark.parametrize("text", ["Synthetic answer", ""])
def test_agent_completion_output(app, monkeypatch, capsys, json_output, text):
    calls = install_transport(
        monkeypatch,
        [
            [
                {"type": "MESSAGE_DELTA", "delta": text},
                {"type": "COMPLETE", "thread_id": "one"},
            ]
        ],
    )
    invoke(
        app,
        [
            "agent",
            "run",
            "Synthetic request",
            "--thread-id",
            "one",
            "--model",
            "synthetic-model",
            *(["--json"] if json_output else []),
        ],
    )
    body = json.loads(calls[0].content)
    assert body["thread_id"] == "one" and body["model"] == "synthetic-model"
    output = capsys.readouterr().out
    if json_output:
        result = json.loads(output)
        assert result["status"] == "completed"
        assert result["message"] == text
        assert result["pending_actions"] == []
    else:
        assert (text or "Completed") in output


@pytest.mark.parametrize(
    "events", [[], [{"type": "RUN_ERROR", "message": "synthetic error"}]]
)
def test_agent_incomplete_or_error_is_failure(app, monkeypatch, events):
    install_transport(monkeypatch, [events])
    with pytest.raises(CliError, match="ended with status"):
        app(["agent", "run", "Synthetic request", "--json"], exit_on_error=False)


def interruption(thread_id: str | None = "one"):
    return {
        "type": "RUN_INTERRUPTED",
        **({"thread_id": thread_id} if thread_id else {}),
        "interrupt_data": {
            "action_requests": [
                {
                    "id": "action-one",
                    "name": "create_location",
                    "args": {"name": "Synthetic"},
                }
            ]
        },
    }


def test_json_interrupt_never_prompts_or_resumes(app, monkeypatch, capsys):
    calls = install_transport(monkeypatch, [[interruption()]])
    monkeypatch.setattr(
        main.Confirm, "ask", lambda *a, **k: pytest.fail("JSON must not prompt")
    )
    invoke(app, ["agent", "run", "Synthetic request", "--json"])
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "interrupted"
    assert result["pending_actions"][0]["id"] == "action-one"
    assert len(calls) == 1


def test_human_refusal_is_sent_as_reject(app, monkeypatch):
    calls = install_transport(
        monkeypatch, [[interruption()], [{"type": "COMPLETE", "thread_id": "one"}]]
    )

    def refuse(prompt, default):
        assert default is False
        return False

    monkeypatch.setattr(main.Confirm, "ask", refuse)
    invoke(app, ["agent", "run", "Synthetic request"])
    assert calls[1].url.path == "/v1/app/threads/one/resume"
    assert json.loads(calls[1].content)["decisions"] == [
        {"type": "reject", "action_request_id": "action-one"}
    ]


def test_interrupt_requires_thread_id(app, monkeypatch):
    install_transport(monkeypatch, [[interruption(None)]])
    with pytest.raises(CliError, match="without a thread ID"):
        app(["agent", "run", "Synthetic request", "--json"], exit_on_error=False)


@pytest.mark.parametrize("action_request", [None, {}, {"id": "one", "name": 5}])
def test_malformed_approval_request_is_rejected_before_prompt(
    monkeypatch, action_request
):
    monkeypatch.setattr(
        main.Confirm, "ask", lambda *a, **k: pytest.fail("invalid request")
    )
    with pytest.raises(CliError, match="approval request"):
        main._prompt_agent_decisions({"action_requests": [action_request]})


@pytest.mark.parametrize(
    "event",
    [
        {"type": "RUN_INTERRUPTED"},
        {"type": "RUN_INTERRUPTED", "interrupt_data": {"action_requests": []}},
    ],
)
def test_invalid_interrupt_fails_protocol(event):
    with pytest.raises(ThreadProtocolError):
        latest_interrupt([event])


@pytest.mark.parametrize("json_output", [False, True])
def test_thread_harness_writes_redacted_artifacts(
    app, monkeypatch, tmp_path, capsys, json_output
):
    calls = install_transport(
        monkeypatch,
        [
            [
                {
                    "type": "TOOL_CALL_END",
                    "tool_name": "list_locations",
                    "token": "synthetic-sensitive",
                },
                {"type": "COMPLETE", "thread_id": "one"},
            ]
        ],
    )
    output = tmp_path / "artifacts"
    invoke(
        app,
        [
            "thread",
            "run",
            "Synthetic request",
            "--thread-id",
            "one",
            "--model",
            "synthetic-model",
            "--artifact-dir",
            str(output),
            "--expect-terminal",
            "COMPLETE",
            "--require-event",
            "TOOL_CALL_END",
            "--require-tool",
            "list_locations",
            "--forbid-event",
            "RUN_ERROR",
            *(["--json"] if json_output else []),
        ],
    )
    assert calls[0].headers["X-Test-Run-ID"]
    assert json.loads((output / "summary.json").read_text())["status"] == "completed"
    assert "synthetic-sensitive" not in (output / "events.jsonl").read_text()
    assert (output / "persisted-interactions.json").exists()
    printed = capsys.readouterr().out
    assert (
        (json.loads(printed)["artifact_dir"] == str(output))
        if json_output
        else "Completed" in printed
    )


@pytest.mark.parametrize("failure", ["stream", "interactions"])
def test_thread_failure_preserves_partial_artifacts(
    app, monkeypatch, tmp_path, failure
):
    install_transport(
        monkeypatch, [[{"type": "COMPLETE", "thread_id": "one"}]], failure=failure
    )
    output = tmp_path / "artifacts"
    with pytest.raises(CliError):
        app(
            ["thread", "run", "Synthetic request", "--artifact-dir", str(output)],
            exit_on_error=False,
        )
    assert (output / "events.jsonl").exists()
    assert (output / "summary.json").exists()


def test_thread_without_id_can_verify_nonpersisted_stream(app, monkeypatch, tmp_path):
    install_transport(monkeypatch, [[{"type": "COMPLETE"}]])
    invoke(
        app,
        ["thread", "run", "Synthetic request", "--no-require-persisted-interactions"],
    )
    assert (
        len(list((tmp_path / "test-results/thread-runs").glob("*/summary.json"))) == 1
    )

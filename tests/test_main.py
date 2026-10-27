import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

import pytest
from cyclopts import App
from cyclopts.exceptions import UnknownOptionError
from rich.console import Console
from support import NULARA, NULARA_DEV

import nulara
from nulara.core import main as main_module
from nulara.core.client import ApiClient
from nulara.core.config import (
    Product,
    ProductConfig,
    Surface,
    WorkspaceRef,
    active_workspace_id,
    known_workspaces,
    product_config,
    remember_workspace,
)
from nulara.core.errors import AuthenticationError, CliError, ConfigurationError
from nulara.core.main import _parse_params, _resource_params, build_app
from nulara.core.oauth import LoginResult

DEV = Surface.DEVELOPMENT
WORKSPACE_A = "01a061db-5513-70f1-8f7e-000000000001"
WORKSPACE_B = "01a061db-5513-70f1-8f7e-000000000002"

CATALOG = {
    "operations": [
        {
            "operation_id": "list_tasks",
            "method": "get",
            "path": "/tasks",
            "summary": "List tasks",
            "metadata": {
                "resource": "tasks",
                "mode": "read",
                "approval": "none",
            },
        }
    ]
}
METADATA = {
    "token_prefix": "nulara_sk_test",
    "expires_at": "2030-01-01T00:00:00Z",
    "scopes": ["read", "write"],
    "workspace_id": WORKSPACE_A,
}
WORKSPACES = [
    {"id": WORKSPACE_A, "name": "Acme"},
    {"id": WORKSPACE_B, "name": "Globex"},
]


class FakeApiClient:
    stream_error: CliError | None = None
    interaction_error: CliError | None = None
    last_request: tuple[str, str, object] | None = None
    last_stream_payload: dict[str, object] | None = None
    agent_events: list[list[dict[str, object]]] = []
    resume_payloads: list[tuple[str, dict[str, object]]] = []

    def __init__(self, config: ProductConfig, token: str):
        self.config = config
        self.token = token

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def current_api_key(self) -> dict[str, object]:
        return dict(METADATA)

    def list_workspaces(self) -> list[dict[str, object]]:
        return [dict(workspace) for workspace in WORKSPACES]

    def operation_catalog(self) -> dict[str, Any]:
        return CATALOG

    def request(
        self, method: str, path: str, *, params: object
    ) -> list[dict[str, int]]:
        type(self).last_request = (method, path, params)
        return [{"id": 1}]

    def stream_thread(self, payload: dict[str, object], *, test_run_id: str):
        type(self).last_stream_payload = payload
        if self.stream_error:
            raise self.stream_error
        yield {
            "type": "COMPLETE",
            "thread_id": "thread-1",
            "test_run_id": test_run_id,
        }

    def stream_agent(self, payload: dict[str, object]):
        type(self).last_stream_payload = payload
        batch = type(self).agent_events.pop(0)
        yield from batch

    def resume_agent(self, thread_id: str, payload: dict[str, object]):
        type(self).resume_payloads.append((thread_id, payload))
        batch = type(self).agent_events.pop(0)
        yield from batch

    def thread_interactions(self, _thread_id: str) -> dict[str, object]:
        if self.interaction_error:
            raise self.interaction_error
        return {"interactions": [{"id": "interaction-1"}]}


@pytest.fixture(autouse=True)
def reset_fakes() -> None:
    FakeApiClient.stream_error = None
    FakeApiClient.interaction_error = None
    FakeApiClient.last_request = None
    FakeApiClient.last_stream_payload = None
    FakeApiClient.agent_events = []
    FakeApiClient.resume_payloads = []


@pytest.fixture
def cli_mocks(monkeypatch):
    rendered_json: list[object] = []
    rendered_rows: list[object] = []
    printed: list[str] = []
    stored: list[tuple[ProductConfig, str, str]] = []
    stored_logins: list[dict[str, object]] = []
    monkeypatch.setattr(main_module, "ApiClient", FakeApiClient)
    monkeypatch.setattr(main_module, "get_token", lambda _config: ("token", "test"))
    monkeypatch.setattr(
        main_module,
        "store_token",
        lambda config, token, workspace_id, **login: (
            stored.append((config, token, workspace_id)),
            stored_logins.append(login),
        ),
    )
    monkeypatch.setattr(main_module, "render_json", rendered_json.append)
    monkeypatch.setattr(main_module, "render_rows", rendered_rows.append)
    monkeypatch.setattr(
        main_module.console,
        "print",
        lambda value="", **_kwargs: printed.append(value),
    )
    return SimpleNamespace(
        rendered_json=rendered_json,
        rendered_rows=rendered_rows,
        printed=printed,
        stored=stored,
        stored_logins=stored_logins,
    )


def invoke(
    *tokens: str, product: Product = NULARA_DEV, surface: Surface = DEV
) -> object:
    try:
        return build_app(product, surface)(tokens, exit_on_error=False)
    except SystemExit as exc:
        if exc.code != 0:
            raise
        return None


def test_parameter_parsing_and_default_limit() -> None:
    assert _parse_params(["active=true", "label=plain", "count=2"]) == [
        ("active", True),
        ("label", "plain"),
        ("count", 2),
    ]
    with pytest.raises(CliError, match="expected key=value"):
        _parse_params(["invalid"])
    assert _resource_params([]) == [("limit", 100)]
    assert _resource_params(["limit=20", "status=open"]) == [
        ("limit", 20),
        ("status", "open"),
    ]


def test_pasted_pat_login(cli_mocks, monkeypatch) -> None:
    monkeypatch.setattr(main_module.getpass, "getpass", lambda _prompt: "remote-token")
    invoke("auth", "login")
    assert cli_mocks.stored[-1][1] == "remote-token"
    assert "Authenticated" in cli_mocks.printed[-1]

    monkeypatch.setattr(main_module.getpass, "getpass", lambda _prompt: "   ")
    with pytest.raises(CliError, match="No token provided"):
        invoke("auth", "login")


def test_browser_login_stores_token_and_verifies_it(cli_mocks, monkeypatch) -> None:
    announced: list[str] = []

    def fake_browser_login(config, *, open_browser, timeout_seconds, announce):
        assert open_browser is False
        assert timeout_seconds == 12.0
        announce("https://app.example.test/cli/authorize?state=x")
        return LoginResult(
            token="nulara_sk_browser",
            token_prefix="nulara_sk",
            scopes=["read", "write"],
            expires_in=3600,
            workspace_id=WORKSPACE_A,
            refresh_token="nulara_rt_browser",
        )

    monkeypatch.setattr(main_module, "browser_is_available", lambda: True)
    monkeypatch.setattr(main_module, "run_browser_login", fake_browser_login)
    monkeypatch.setattr(main_module.time, "time", lambda: 1_000.0)
    monkeypatch.setattr(
        main_module.console, "print", lambda value: announced.append(str(value))
    )
    invoke("login", "--no-open-browser", "--timeout", "12")

    assert cli_mocks.stored[-1][1] == "nulara_sk_browser"
    # The refresh token and the bearer token's deadline go into the same entry.
    assert cli_mocks.stored_logins[-1] == {
        "refresh_token": "nulara_rt_browser",
        "access_expires_at": 4_600.0,
    }
    assert any("cli/authorize" in line for line in announced)
    assert any("Authenticated" in line for line in announced)


def test_login_falls_back_to_the_device_flow_without_a_browser(
    cli_mocks, monkeypatch
) -> None:
    # On a remote shell the loopback redirect would land on a port only that host
    # can see, so the flow is chosen by whether a browser is reachable at all.
    announced: list[str] = []

    def fake_device_login(config, *, open_browser, announce):
        announce(
            SimpleNamespace(
                verification_uri="https://app.example.test/cli/device",
                user_code="BCDF-GHJK",
            )
        )
        return LoginResult(
            token="nulara_sk_device",
            token_prefix="nulara_sk",
            scopes=["read", "write"],
            expires_in=90 * 24 * 3600,
            workspace_id=WORKSPACE_A,
        )

    monkeypatch.setattr(main_module, "browser_is_available", lambda: False)
    monkeypatch.setattr(main_module, "run_device_login", fake_device_login)
    monkeypatch.setattr(
        main_module,
        "run_browser_login",
        lambda *_args, **_kwargs: pytest.fail("must not use the loopback flow"),
    )
    monkeypatch.setattr(
        main_module.console, "print", lambda value: announced.append(str(value))
    )

    invoke("login")

    assert cli_mocks.stored[-1][1] == "nulara_sk_device"
    assert any("BCDF-GHJK" in line for line in announced)


def test_login_can_be_forced_onto_either_flow(cli_mocks, monkeypatch) -> None:
    used: list[str] = []
    result = LoginResult(
        token="nulara_sk_forced",
        token_prefix="nulara_sk",
        scopes=["read"],
        expires_in=1,
        workspace_id=WORKSPACE_A,
    )
    monkeypatch.setattr(
        main_module,
        "run_device_login",
        lambda *_a, **_k: (used.append("device"), result)[1],
    )
    monkeypatch.setattr(
        main_module,
        "run_browser_login",
        lambda *_a, **_k: (used.append("loopback"), result)[1],
    )
    monkeypatch.setattr(main_module.console, "print", lambda _value: None)

    monkeypatch.setattr(main_module, "browser_is_available", lambda: True)
    invoke("login", "--device")
    monkeypatch.setattr(main_module, "browser_is_available", lambda: False)
    invoke("login", "--no-device")

    assert used == ["device", "loopback"]


def test_browser_login_propagates_failures(cli_mocks, monkeypatch) -> None:
    def failing_login(_config, **_kwargs):
        raise AuthenticationError("Consent was not granted (access_denied)")

    monkeypatch.setattr(main_module, "browser_is_available", lambda: True)
    monkeypatch.setattr(main_module, "run_browser_login", failing_login)
    with pytest.raises(AuthenticationError, match="access_denied"):
        invoke("login")
    assert cli_mocks.stored == []


def test_pat_login_requires_a_pasted_token(cli_mocks, monkeypatch) -> None:
    monkeypatch.setattr(main_module.getpass, "getpass", lambda _prompt: "")
    with pytest.raises(CliError, match="No token provided"):
        invoke("auth", "login")
    assert cli_mocks.stored == []


def test_password_login_is_gone(cli_mocks) -> None:
    # ROPC was removed (RFC 9700 forbids it); the browser flow replaced it.
    with pytest.raises(UnknownOptionError):
        invoke("auth", "login", "--local", "--email", "dev@example.com")


def test_remote_login_rejects_project_config_only_endpoint(
    cli_mocks, monkeypatch, tmp_path: Path
) -> None:
    config_file = tmp_path / ".nulara.toml"
    config_file.write_text('api_url = "https://api.example.test/v1/app"\n')
    getpass = Mock(return_value="must-not-be-read")
    monkeypatch.setattr(main_module.getpass, "getpass", getpass)
    with pytest.raises(CliError, match="Refusing.*pasted PAT"):
        invoke("auth", "login", "--config", str(config_file))
    getpass.assert_not_called()


def test_browser_login_rejects_project_config_only_endpoint(
    cli_mocks, monkeypatch, tmp_path: Path
) -> None:
    # A checked-in .nulara.toml must not choose where the login mints a token:
    # that API's discovery document names the consent page the browser opens.
    config_file = tmp_path / ".nulara.toml"
    config_file.write_text('api_url = "https://api.example.test/v1/app"\n')
    browser_login = Mock()
    monkeypatch.setattr(main_module, "run_browser_login", browser_login)
    with pytest.raises(CliError, match="Refusing.*browser login"):
        invoke("login", "--config", str(config_file))
    browser_login.assert_not_called()
    assert cli_mocks.stored == []


def test_status_logout_and_operation_rendering(cli_mocks, monkeypatch) -> None:
    config = product_config(NULARA_DEV, surface=DEV)
    remember_workspace(config, WorkspaceRef(id=WORKSPACE_A, name="Acme"))

    invoke("auth", "status", "--json")
    status = cli_mocks.rendered_json[-1]
    assert status["credential_source"] == "test"
    assert status["base_url_source"] == "default"
    assert status["workspaces"] == [{"id": WORKSPACE_A, "name": "Acme", "active": True}]

    invoke("auth", "status")
    assert "Scopes: read, write" in cli_mocks.printed[-1]
    assert "Acme" in cli_mocks.printed[-1]

    monkeypatch.setattr(
        main_module, "delete_token", lambda _config, _workspace_id: True
    )
    invoke("auth", "logout")
    assert "removed" in cli_mocks.printed[-1]
    # The state entry went with it, so a second logout has nothing to remove.
    assert known_workspaces(config) == []
    invoke("auth", "logout")
    assert "No saved" in cli_mocks.printed[-1]

    invoke("operations", "list", "--json")
    assert cli_mocks.rendered_json[-1][0]["operation_id"] == "list_tasks"
    invoke("operations", "list")
    assert cli_mocks.rendered_rows[-1][0]["operation_id"] == "list_tasks"


def test_resource_read_honors_params_and_output_modes(cli_mocks) -> None:
    invoke("resource", "list", "tasks", "--param", "limit=25", "--json")
    assert FakeApiClient.last_request == ("GET", "/tasks", [("limit", 25)])
    assert cli_mocks.rendered_json[-1] == [{"id": 1}]
    invoke("resource", "list", "tasks")
    assert cli_mocks.rendered_rows[-1] == [{"id": 1}]


def test_customer_agent_run_streams_and_returns_json(cli_mocks) -> None:
    FakeApiClient.agent_events = [
        [
            {"type": "MESSAGE_DELTA", "delta": "Found it."},
            {"type": "COMPLETE", "thread_id": "thread-1"},
        ]
    ]

    invoke("agent", "run", "Find the record", "--json", surface=Surface.CUSTOMER)

    assert FakeApiClient.last_stream_payload is not None
    assert FakeApiClient.last_stream_payload["message"] == "Find the record"
    assert cli_mocks.rendered_json[-1] == {
        "status": "completed",
        "terminal_type": "COMPLETE",
        "thread_id": "thread-1",
        "message": "Found it.",
        "pending_actions": [],
    }


def test_json_agent_run_never_approves_an_interrupt(cli_mocks, monkeypatch) -> None:
    FakeApiClient.agent_events = [
        [
            {
                "type": "RUN_INTERRUPTED",
                "thread_id": "thread-1",
                "interrupt_data": {
                    "action_requests": [
                        {"id": "call-1", "name": "send_email", "args": {}}
                    ],
                    "review_configs": [],
                    "steps": [],
                },
            }
        ]
    ]
    confirm = Mock(side_effect=AssertionError("JSON mode must not prompt"))
    monkeypatch.setattr(main_module.Confirm, "ask", confirm)

    invoke("agent", "run", "Send it", "--json", surface=Surface.CUSTOMER)

    confirm.assert_not_called()
    assert FakeApiClient.resume_payloads == []
    assert cli_mocks.rendered_json[-1]["status"] == "interrupted"
    assert cli_mocks.rendered_json[-1]["pending_actions"][0]["id"] == "call-1"


def test_agent_run_resumes_only_after_explicit_confirmation(
    cli_mocks, monkeypatch
) -> None:
    FakeApiClient.agent_events = [
        [
            {
                "type": "RUN_INTERRUPTED",
                "thread_id": "thread-1",
                "interrupt_data": {
                    "action_requests": [
                        {"id": "call-1", "name": "send_email", "args": {}}
                    ],
                    "review_configs": [],
                    "steps": [],
                    "execution_time_ms": 2,
                    "thinking_time_ms": 3,
                },
            }
        ],
        [
            {"type": "MESSAGE_DELTA", "delta": "Queued."},
            {"type": "COMPLETE", "thread_id": "thread-1"},
        ],
    ]
    monkeypatch.setattr(main_module.Confirm, "ask", lambda *_a, **_k: True)

    invoke("agent", "run", "Send it", surface=Surface.CUSTOMER)

    assert FakeApiClient.resume_payloads[0][0] == "thread-1"
    assert FakeApiClient.resume_payloads[0][1]["decisions"] == [
        {"type": "approve", "action_request_id": "call-1"}
    ]


def test_agent_run_rejects_an_interrupt_without_a_thread_id(cli_mocks) -> None:
    FakeApiClient.agent_events = [
        [
            {
                "type": "RUN_INTERRUPTED",
                "interrupt_data": {
                    "action_requests": [
                        {"id": "call-1", "name": "send_email", "args": {}}
                    ]
                },
            }
        ]
    ]

    with pytest.raises(CliError, match="without a thread ID"):
        invoke("agent", "run", "Send it", surface=Surface.CUSTOMER)


@pytest.mark.parametrize(
    ("events", "status"),
    [
        ([{"type": "STREAM_ERROR", "detail": "EXECUTION_ERROR"}], "error"),
        ([{"type": "MESSAGE_DELTA", "delta": "partial"}], "incomplete"),
    ],
)
def test_agent_run_rejects_nonterminal_or_error_results(
    cli_mocks,
    events: list[dict[str, object]],
    status: str,
) -> None:
    FakeApiClient.agent_events = [events]

    with pytest.raises(CliError, match=f"status {status}"):
        invoke("agent", "run", "Check it", surface=Surface.CUSTOMER)


def test_agent_run_prints_terminal_status_without_assistant_text(cli_mocks) -> None:
    FakeApiClient.agent_events = [[{"type": "COMPLETE", "thread_id": "thread-1"}]]

    invoke("agent", "run", "Check it", surface=Surface.CUSTOMER)

    assert "Completed" in cli_mocks.printed[-1]


@pytest.mark.parametrize(
    "action_requests",
    [["invalid"], [{"id": "call-1"}], [{"name": "send_email"}]],
)
def test_agent_decisions_reject_malformed_requests(
    action_requests: list[object],
) -> None:
    with pytest.raises(CliError, match="invalid approval|missing id or name"):
        main_module._prompt_agent_decisions({"action_requests": action_requests})


def test_agent_decisions_preserve_rejections(cli_mocks, monkeypatch) -> None:
    monkeypatch.setattr(main_module.Confirm, "ask", lambda *_a, **_k: False)
    request = {"id": "call-1", "name": "send_email", "args": {"to": "a@b.test"}}

    result = main_module._prompt_agent_decisions({"action_requests": [request]})

    assert result == {
        "decisions": [{"type": "reject", "action_request_id": "call-1"}],
    }


def test_thread_run_writes_evidence_and_supports_all_assertions(
    cli_mocks, tmp_path: Path
) -> None:
    artifact_dir = tmp_path / "evidence"
    invoke(
        "thread",
        "run",
        "hello",
        "--thread-id",
        "existing",
        "--model",
        "model-1",
        "--artifact-dir",
        str(artifact_dir),
        "--expect-terminal",
        "COMPLETE",
        "--require-event",
        "COMPLETE",
        "--forbid-event",
        "STREAM_ERROR",
        "--json",
    )
    assert FakeApiClient.last_stream_payload is not None
    assert FakeApiClient.last_stream_payload["thread_id"] == "existing"
    assert FakeApiClient.last_stream_payload["model"] == "model-1"
    assert (artifact_dir / "events.jsonl").is_file()
    assert cli_mocks.rendered_json[-1]["status"] == "completed"

    second_dir = tmp_path / "human"
    invoke(
        "thread",
        "run",
        "hello",
        "--artifact-dir",
        str(second_dir),
        "--no-require-persisted-interactions",
    )
    assert "Completed" in cli_mocks.printed[-1]


def test_thread_run_preserves_stream_and_interaction_errors(
    cli_mocks, tmp_path: Path
) -> None:
    FakeApiClient.stream_error = CliError("stream broke")
    with pytest.raises(CliError, match="stream broke"):
        invoke("thread", "run", "hello", "--artifact-dir", str(tmp_path / "stream"))

    FakeApiClient.stream_error = None
    FakeApiClient.interaction_error = CliError("interaction broke")
    with pytest.raises(CliError, match="interaction broke"):
        invoke(
            "thread",
            "run",
            "hello",
            "--artifact-dir",
            str(tmp_path / "interaction"),
        )


def test_doctor_and_global_connection_options(cli_mocks, tmp_path: Path) -> None:
    config_file = tmp_path / "settings.toml"
    config_file.write_text('api_url = "https://file.example/v1/app"\n')
    invoke("doctor", "--config", str(config_file), "--json")
    result = cli_mocks.rendered_json[-1]
    assert result["status"] == "ok"
    assert result["operation_count"] == 1
    assert result["base_url_source"] == str(config_file)

    invoke("doctor", "--api-url", "https://flag.example/v1/app")
    assert "Ready" in cli_mocks.printed[-1]
    assert "--api-url" in cli_mocks.printed[-1]


def test_completion_command_bypasses_runtime_config(monkeypatch) -> None:
    installed: list[bool] = []
    monkeypatch.setattr(
        App,
        "install_completion",
        lambda *_args, **_kwargs: installed.append(True)
        or Path("/tmp/nulara-completion"),
    )
    invoke(
        "--install-completion", "--shell", "fish", "--output", "/tmp/nulara-completion"
    )
    assert installed == [True]


def test_api_command_help_includes_connection_options() -> None:
    output = Console(record=True, width=120)
    build_app(NULARA_DEV, DEV).help_print(["doctor"], console=output)
    help_text = output.export_text()
    assert "--api-url" in help_text
    assert "--config" in help_text


def test_customer_surface_ships_only_the_api_commands() -> None:
    # A customer has no repository checkout, so a repository task could only fail;
    # `thread run` is a verification harness that writes test artifacts.
    output = Console(record=True, width=120)
    build_app(NULARA, Surface.CUSTOMER).help_print([], console=output)
    help_text = output.export_text()
    for absent in ("db-reset", "seed", "test-backend", "migrate", "│ thread "):
        assert absent not in help_text
    for present in (
        "login",
        "auth",
        "operations",
        "resource",
        "agent",
        "api",
        "doctor",
        "locations",
    ):
        assert present in help_text


def test_surface_decides_the_default_api(cli_mocks) -> None:
    invoke("doctor", "--json", product=NULARA, surface=Surface.CUSTOMER)
    assert cli_mocks.rendered_json[-1]["base_url"] == "https://api.nulara.de/v1/app"
    assert cli_mocks.rendered_json[-1]["surface"] == "customer"

    invoke("doctor", "--json", product=NULARA_DEV, surface=DEV)
    assert cli_mocks.rendered_json[-1]["base_url"] == "http://localhost:5710/v1/app"
    assert cli_mocks.rendered_json[-1]["surface"] == "development"


def test_entrypoint_and_error_mapping(monkeypatch, capsys) -> None:
    calls: list[object] = []
    monkeypatch.setattr(nulara, "run", calls.append)
    nulara.main()
    built = calls[0]
    assert callable(built)
    monkeypatch.setattr(nulara, "build_app", lambda *args: args)
    assert built() == (NULARA, Surface.CUSTOMER)

    fake_app = Mock()
    fake_app.side_effect = CliError("broken")
    printed = Mock()
    monkeypatch.setattr(main_module.error_console, "print", printed)
    with pytest.raises(SystemExit) as error:
        main_module.run(lambda: fake_app)
    assert error.value.code == 1
    printed.assert_called_once()

    fake_app.side_effect = AuthenticationError(
        "bad token", status_code=401, detail="UNAUTHORIZED"
    )
    monkeypatch.setattr(main_module.sys, "argv", ["nulara", "doctor", "--json"])
    printed.reset_mock()
    with pytest.raises(SystemExit) as error:
        main_module.run(lambda: fake_app)
    assert error.value.code == 3
    printed.assert_not_called()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert len(captured.err.splitlines()) == 1
    rendered = json.loads(captured.err)
    assert rendered == {
        "detail": "UNAUTHORIZED",
        "error": "authentication_error",
        "exit_code": 3,
        "message": "bad token",
        "status_code": 401,
    }


def test_a_failing_build_is_reported_like_a_failing_command(monkeypatch) -> None:
    printed = Mock()
    monkeypatch.setattr(main_module.error_console, "print", printed)

    def build() -> App:
        raise ConfigurationError("broken manifest")

    with pytest.raises(SystemExit) as error:
        main_module.run(build)
    assert error.value.code == 2
    printed.assert_called_once()


def test_workspace_use_switches_locally_without_a_server_call(
    cli_mocks, monkeypatch
) -> None:
    config = product_config(NULARA_DEV, surface=DEV)
    remember_workspace(config, WorkspaceRef(id=WORKSPACE_A, name="Acme"))
    remember_workspace(config, WorkspaceRef(id=WORKSPACE_B, name="Globex"))
    assert active_workspace_id(config) == WORKSPACE_B

    # The whole point of the local switch: no HTTP client is ever built.
    monkeypatch.setattr(
        main_module,
        "ApiClient",
        lambda *_args, **_kwargs: pytest.fail("workspace use must not call the API"),
    )
    invoke("workspace", "use", "Acme")

    assert active_workspace_id(config) == WORKSPACE_A
    assert "Acme" in cli_mocks.printed[-1]


def test_workspace_use_reports_an_unknown_workspace(cli_mocks) -> None:
    config = product_config(NULARA_DEV, surface=DEV)
    remember_workspace(config, WorkspaceRef(id=WORKSPACE_A, name="Acme"))
    with pytest.raises(ConfigurationError, match="Unknown workspace"):
        invoke("workspace", "use", "Initech")


def test_workspace_selection_creates_the_group_when_the_manifest_lacks_it() -> None:
    # The command must survive a manifest that carries no workspace module, so
    # regenerating the contract can never silently drop the local switch.
    app = App(name="nulara-dev")
    main_module._register_workspace_selection(app, {}, NULARA, DEV)
    assert "workspace" in app


def test_workspace_name_falls_back_to_the_id() -> None:
    class Unlisted(FakeApiClient):
        def list_workspaces(self) -> list[dict[str, object]]:
            return [{"id": WORKSPACE_B, "name": "Globex"}, {"id": WORKSPACE_A}]

    client = cast(ApiClient, Unlisted(product_config(NULARA_DEV, surface=DEV), "token"))
    assert main_module._workspace_ref(client, WORKSPACE_A) == WorkspaceRef(
        id=WORKSPACE_A, name=WORKSPACE_A
    )


def test_login_records_the_workspace_it_was_granted(cli_mocks, monkeypatch) -> None:
    monkeypatch.setattr(main_module.getpass, "getpass", lambda _prompt: "pasted-token")
    invoke("auth", "login")

    config = product_config(NULARA_DEV, surface=DEV)
    assert cli_mocks.stored[-1][2] == WORKSPACE_A
    assert known_workspaces(config) == [WorkspaceRef(id=WORKSPACE_A, name="Acme")]
    assert "Acme" in cli_mocks.printed[-1]


def test_pasted_pat_without_a_workspace_is_refused(cli_mocks, monkeypatch) -> None:
    class NoWorkspace(FakeApiClient):
        def current_api_key(self) -> dict[str, object]:
            return {"token_prefix": "nulara_sk", "expires_at": "2030-01-01T00:00:00Z"}

    monkeypatch.setattr(main_module, "ApiClient", NoWorkspace)
    monkeypatch.setattr(main_module.getpass, "getpass", lambda _prompt: "pasted-token")
    with pytest.raises(CliError, match="did not name a workspace"):
        invoke("auth", "login")
    assert cli_mocks.stored == []

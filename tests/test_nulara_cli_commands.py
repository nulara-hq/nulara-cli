"""Nulara CLI dispatch and local state."""

import json

import httpx
import pytest
from support import NULARA, NULARA_DEV

import nulara
from nulara.core import main
from nulara.core.client import ApiClient
from nulara.core.config import (
    Surface,
    WorkspaceRef,
    product_config,
    remember_workspace,
)
from nulara.core.errors import CliError, ConfigurationError


@pytest.fixture
def app(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NULARA_API_URL", raising=False)
    monkeypatch.setenv("NULARA_API_TOKEN", "synthetic-nulara-token")
    return main.build_app(NULARA_DEV, Surface.DEVELOPMENT)


def invoke(app, args):
    with pytest.raises(SystemExit) as result:
        app(args, exit_on_error=False)
    assert result.value.code == 0


@pytest.mark.parametrize("json_output", [False, True])
@pytest.mark.parametrize("command", ["doctor", "operations", "resource", "status"])
def test_read_commands_use_nulara_catalog(
    app, monkeypatch, capsys, command, json_output
):
    paths = []
    metadata = {
        "token_prefix": "synthetic-prefix",
        "workspace_id": "workspace-one",
        "scopes": ["read"],
        "expires_at": "2030-01-01",
    }
    catalog = {
        "operations": [
            {
                "operation_id": "list_locations",
                "metadata": {
                    "resource": "locations",
                    "mode": "read",
                    "approval": "none",
                },
                "method": "GET",
                "path": "/locations",
                "description": "Locations",
            }
        ]
    }

    def handle(request):
        paths.append(request.url.path)
        assert request.headers["authorization"] == "Bearer synthetic-nulara-token"
        if request.url.path.endswith("/current"):
            return httpx.Response(200, json=metadata)
        if request.url.path.endswith("/agent-operations"):
            return httpx.Response(200, json=catalog)
        assert request.url.params["limit"] == "100"
        assert request.url.params["search"] == "synthetic"
        return httpx.Response(200, json=[{"name": "Synthetic location"}])

    monkeypatch.setattr(
        main,
        "ApiClient",
        lambda c, t: ApiClient(c, t, transport=httpx.MockTransport(handle)),
    )
    config = product_config(NULARA_DEV, surface=Surface.DEVELOPMENT)
    remember_workspace(config, WorkspaceRef("workspace-one", "Synthetic workspace"))
    args = {
        "doctor": ["doctor"],
        "operations": ["operations", "list"],
        "resource": ["resource", "list", "locations", "--param", "search=synthetic"],
        "status": ["auth", "status"],
    }[command]
    invoke(app, [*args, *(["--json"] if json_output else [])])
    output = capsys.readouterr().out
    assert paths
    assert "synthetic-nulara-token" not in output
    if json_output:
        assert isinstance(json.loads(output), (dict, list))


@pytest.mark.parametrize("all_workspaces", [False, True])
@pytest.mark.parametrize("token_present", [False, True])
def test_logout_clears_stale_or_stored_workspace(
    app, monkeypatch, capsys, all_workspaces, token_present
):
    config = product_config(NULARA_DEV, surface=Surface.DEVELOPMENT)
    remember_workspace(config, WorkspaceRef("one", "One"))
    calls = []
    monkeypatch.setattr(
        main, "delete_token", lambda c, w: calls.append(w) or token_present
    )
    invoke(app, ["auth", "logout", *(["--all"] if all_workspaces else [])])
    assert calls == ["one"]
    assert not main.known_workspaces(config)
    assert ("Token removed" if token_present else "No saved") in capsys.readouterr().out
    invoke(app, ["auth", "logout"])
    assert calls == ["one"]


def test_workspace_use_is_local(app, monkeypatch, capsys):
    config = product_config(NULARA_DEV, surface=Surface.DEVELOPMENT)
    remember_workspace(config, WorkspaceRef("one", "One"))
    remember_workspace(config, WorkspaceRef("two", "Two"))
    invoke(app, ["workspace", "use", "One"])
    selected = main.resolve_workspace(config)
    assert selected is not None and selected.id == "one"
    assert "Now using" in capsys.readouterr().out


@pytest.mark.parametrize(
    "workspaces", [[], [{"id": "one", "name": ""}], [{"id": "other", "name": "Other"}]]
)
def test_login_workspace_name_falls_back_to_granted_id(workspaces):
    config = product_config(NULARA_DEV, surface=Surface.DEVELOPMENT)
    with ApiClient(
        config,
        "synthetic-token",
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=workspaces)),
    ) as client:
        assert main._workspace_ref(client, "one") == WorkspaceRef("one", "one")


@pytest.mark.parametrize("value", ["invalid", "=bad"])
def test_resource_query_rejects_missing_keys(value):
    with pytest.raises(CliError, match="expected key=value"):
        main._resource_params([value])


def test_resource_query_preserves_explicit_limit_and_repeat_keys():
    assert main._resource_params(["limit=2", "name=a", "name=b", "active=true"]) == [
        ("limit", 2),
        ("name", "a"),
        ("name", "b"),
        ("active", True),
    ]


@pytest.mark.parametrize(
    "token,metadata,error",
    [
        ("", {}, "No token provided"),
        ("synthetic-pasted", {}, "did not name a workspace"),
        (
            "synthetic-pasted",
            {"workspace_id": "one", "token_prefix": "prefix", "expires_at": "2030"},
            None,
        ),
    ],
)
def test_pasted_pat_login_validates_before_storage(
    app, monkeypatch, token, metadata, error
):
    stored = []
    monkeypatch.setattr(main.getpass, "getpass", lambda _: token)
    monkeypatch.setattr(main, "store_token", lambda *args: stored.append(args))

    def handle(request):
        assert request.headers["authorization"] == "Bearer synthetic-pasted"
        return httpx.Response(
            200,
            json=[{"id": "one", "name": "One"}]
            if request.url.path.endswith("/workspace")
            else metadata,
        )

    monkeypatch.setattr(
        main,
        "ApiClient",
        lambda c, t: ApiClient(c, t, transport=httpx.MockTransport(handle)),
    )
    if error:
        with pytest.raises(CliError, match=error):
            app(["auth", "login"], exit_on_error=False)
        assert stored == []
    else:
        invoke(app, ["auth", "login"])
        assert stored[0][1:] == ("synthetic-pasted", "one")


@pytest.mark.parametrize("json_output", [False, True])
def test_entrypoint_errors_have_stable_exit_and_machine_output(
    monkeypatch, capsys, json_output
):
    def build(product, surface):
        assert product is NULARA
        assert surface is Surface.CUSTOMER

        def fail():
            raise ConfigurationError("synthetic invalid configuration")

        return fail

    monkeypatch.setattr(nulara, "build_app", build)
    monkeypatch.setattr(
        main.sys, "argv", ["nulara", *(["--json"] if json_output else [])]
    )
    with pytest.raises(SystemExit) as result:
        nulara.main()
    assert result.value.code == 2
    captured = capsys.readouterr()
    assert not captured.out
    if json_output:
        assert json.loads(captured.err) == {
            "error": "configuration_error",
            "exit_code": 2,
            "message": "synthetic invalid configuration",
        }
    else:
        assert "synthetic invalid configuration" in captured.err


def test_raw_api_parser_forwards_query_and_redacted_preview(app, capsys):
    invoke(
        app,
        [
            "api",
            "/locations",
            "--method",
            "POST",
            "--field",
            "name=synthetic",
            "--param",
            "limit=2",
            "--dry-run",
            "--json",
        ],
    )
    result = json.loads(capsys.readouterr().out)
    assert result["method"] == "POST"
    assert result["params"] == [["limit", 2]]
    assert result["body"] == "<redacted>"


def test_auth_status_without_local_workspace_still_accepts_env_token(
    app, monkeypatch, capsys
):
    metadata = {
        "token_prefix": "prefix",
        "workspace_id": "one",
        "expires_at": "2030",
        "scopes": ["read"],
    }
    monkeypatch.setattr(
        main,
        "ApiClient",
        lambda c, t: ApiClient(
            c,
            t,
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=metadata)),
        ),
    )
    invoke(app, ["auth", "status", "--json"])
    result = json.loads(capsys.readouterr().out)
    assert result["workspaces"] == []
    assert "workspace_name" not in result

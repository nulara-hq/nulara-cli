from contextlib import nullcontext
from dataclasses import replace
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest
from support import NULARA

from nulara.core import config as config_module
from nulara.core import main as main_module
from nulara.core.config import ProductConfig, Surface, WorkspaceRef
from nulara.core.errors import AuthenticationError
from nulara.core.oauth import (
    LoginResult,
    exchange_code,
    request_device_authorization,
    run_device_login,
)
from nulara.core.tokens import get_token

CONFIG = ProductConfig(
    product=NULARA,
    surface=Surface.DEVELOPMENT,
    base_url="http://localhost:5710/v1/app",
    token_env="NULARA_TOKEN",
    keyring_service="nulara-cli",
)
TOKEN_ENDPOINT = f"{CONFIG.base_url}/auth/cli/token"
DEVICE_ENDPOINT = f"{CONFIG.base_url}/auth/cli/device"
TOKEN_BODY = {
    "access_token": "synthetic-nulara-token",
    "workspace_id": "workspace-one",
    "scopes": ["read", "write"],
    "expires_in": 600,
}
DEVICE_BODY = {
    "device_code": "synthetic-device-code",
    "user_code": "BCDF-GHJK",
    "verification_uri": "http://localhost:5700/cli/device",
    "expires_in": 600,
    "interval": 1,
}


@pytest.mark.parametrize("entrypoint", ["token", "device"])
def test_successful_login_response_with_invalid_json_is_an_auth_error(entrypoint):
    transport = httpx.MockTransport(lambda _: httpx.Response(200, text="{broken"))

    with pytest.raises(AuthenticationError, match="Unexpected"):
        if entrypoint == "token":
            exchange_code(
                CONFIG,
                token_endpoint=TOKEN_ENDPOINT,
                code="synthetic-code",
                code_verifier="synthetic-verifier",
                redirect_uri="http://127.0.0.1:49152/callback",
                transport=transport,
            )
        else:
            request_device_authorization(
                CONFIG, endpoint=DEVICE_ENDPOINT, transport=transport
            )


@pytest.mark.parametrize(
    "invalid",
    [
        {"access_token": ""},
        {"access_token": "  "},
        {"scopes": None},
        {"scopes": "read"},
        {"scopes": ["read", None]},
        {"expires_in": "invalid"},
        {"expires_in": "Infinity"},
    ],
)
def test_invalid_token_fields_never_become_a_login_result(invalid):
    transport = httpx.MockTransport(
        lambda _: httpx.Response(200, json=TOKEN_BODY | invalid)
    )

    with pytest.raises(AuthenticationError, match="Unexpected"):
        exchange_code(
            CONFIG,
            token_endpoint=TOKEN_ENDPOINT,
            code="synthetic-code",
            code_verifier="synthetic-verifier",
            redirect_uri="http://127.0.0.1:49152/callback",
            transport=transport,
        )


@pytest.mark.parametrize("invalid", [{"interval": None}, {"expires_in": "invalid"}])
def test_invalid_device_timing_is_an_auth_error(invalid):
    transport = httpx.MockTransport(
        lambda _: httpx.Response(200, json=DEVICE_BODY | invalid)
    )

    with pytest.raises(AuthenticationError, match="Unexpected"):
        request_device_authorization(
            CONFIG, endpoint=DEVICE_ENDPOINT, transport=transport
        )


def test_nulara_device_login_rejects_invalid_token_json_after_consent():
    def handle(request):
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "authorization_endpoint": "http://localhost:5700/cli/authorize",
                    "token_endpoint": TOKEN_ENDPOINT,
                    "device_authorization_endpoint": DEVICE_ENDPOINT,
                },
            )
        if str(request.url) == DEVICE_ENDPOINT:
            return httpx.Response(200, json=DEVICE_BODY)
        return httpx.Response(200, text="{broken")

    with pytest.raises(AuthenticationError, match="Unexpected token exchange response"):
        run_device_login(
            CONFIG,
            transport=httpx.MockTransport(handle),
            open_browser=False,
            sleep=lambda _: None,
        )


def test_nulara_device_login_preserves_workspace_and_poll_backoff():
    polls = 0
    waits = []
    announced = []

    def handle(request):
        nonlocal polls
        if request.method == "GET":
            assert request.url.path == "/v1/app/auth/cli/metadata"
            return httpx.Response(
                200,
                json={
                    "authorization_endpoint": "http://localhost:5700/cli/authorize",
                    "token_endpoint": TOKEN_ENDPOINT,
                    "device_authorization_endpoint": DEVICE_ENDPOINT,
                },
            )
        fields = parse_qs(request.content.decode())
        assert fields["client_id"] == ["nulara-cli"]
        if str(request.url) == DEVICE_ENDPOINT:
            return httpx.Response(200, json=DEVICE_BODY)
        assert str(request.url) == TOKEN_ENDPOINT
        assert fields["device_code"] == ["synthetic-device-code"]
        assert fields["grant_type"] == ["urn:ietf:params:oauth:grant-type:device_code"]
        polls += 1
        if polls < 3:
            detail = (
                "CLI_AUTH_DEVICE_PENDING" if polls == 1 else "CLI_AUTH_DEVICE_SLOW_DOWN"
            )
            return httpx.Response(400, json={"detail": detail})
        return httpx.Response(200, json=TOKEN_BODY)

    result = run_device_login(
        CONFIG,
        transport=httpx.MockTransport(handle),
        open_browser=False,
        announce=announced.append,
        sleep=waits.append,
    )

    assert result.workspace_id == "workspace-one"
    assert result.token == "synthetic-nulara-token"
    assert result.scopes == ["read", "write"]
    assert waits == [1, 1, 6]
    assert announced[0].user_code == "BCDF-GHJK"


def test_nulara_workspace_tokens_stay_isolated(monkeypatch):
    keyring = {}
    monkeypatch.setattr(
        config_module.keyring,
        "set_password",
        lambda service, username, token: keyring.__setitem__(
            (service, username), token
        ),
    )
    monkeypatch.setattr(
        config_module.keyring,
        "get_password",
        lambda service, username: keyring.get((service, username)),
    )
    monkeypatch.delenv("NULARA_TOKEN", raising=False)
    for identity in ("one", "two"):
        workspace = WorkspaceRef(f"workspace-{identity}", f"Workspace {identity}")
        config_module.store_token(CONFIG, f"synthetic-{identity}", workspace.id)
        config_module.remember_workspace(CONFIG, workspace)

    assert get_token(CONFIG) == ("synthetic-two", "OS keyring")
    assert get_token(replace(CONFIG, workspace="Workspace one")) == (
        "synthetic-one",
        "OS keyring",
    )
    assert config_module.resolve_workspace(CONFIG) == WorkspaceRef(
        "workspace-two", "Workspace two"
    )


@pytest.mark.parametrize("surface", [Surface.CUSTOMER, Surface.DEVELOPMENT])
@pytest.mark.parametrize("device", [False, True])
def test_nulara_login_command_stores_the_granted_workspace(
    monkeypatch, surface, device
):
    stored = []
    printed = []
    metadata = {
        "token_prefix": "synthetic-prefix",
        "expires_at": "2030-01-01T00:00:00Z",
        "workspace_id": "workspace-one",
    }
    client = SimpleNamespace(
        current_api_key=lambda: metadata,
        list_workspaces=lambda: [{"id": "workspace-one", "name": "Workspace one"}],
    )

    def login(config, **kwargs):
        assert config.product is NULARA
        assert config.surface is surface
        assert kwargs["open_browser"] is False
        return LoginResult(
            token="synthetic-nulara-token",
            token_prefix="synthetic-prefix",
            scopes=["read", "write"],
            expires_in=600,
            workspace_id="workspace-one",
        )

    def wrong_flow(*args, **kwargs):
        pytest.fail("the requested login flow must be used")

    monkeypatch.setattr(
        main_module, "run_device_login", login if device else wrong_flow
    )
    monkeypatch.setattr(
        main_module, "run_browser_login", wrong_flow if device else login
    )
    monkeypatch.setattr(main_module, "ApiClient", lambda *_: nullcontext(client))
    monkeypatch.setattr(
        main_module,
        "store_token",
        lambda config, token, workspace, **_login: stored.append(
            (config, token, workspace)
        ),
    )
    monkeypatch.setattr(
        main_module.console, "print", lambda value: printed.append(str(value))
    )
    monkeypatch.delenv("NULARA_API_URL", raising=False)

    with pytest.raises(SystemExit) as completed:
        main_module.build_app(NULARA, surface)(
            ["login", "--no-open-browser", "--device" if device else "--no-device"],
            exit_on_error=False,
        )
    assert completed.value.code == 0

    assert len(stored) == 1
    config, token, workspace_id = stored[0]
    assert token == "synthetic-nulara-token"
    assert workspace_id == "workspace-one"
    assert config_module.resolve_workspace(config) == WorkspaceRef(
        "workspace-one", "Workspace one"
    )
    assert any("Authenticated" in line and "Workspace one" in line for line in printed)
    assert all(token not in line for line in printed)

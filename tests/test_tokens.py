"""The bearer token a command sends, and the refresh that keeps it alive."""

from urllib.parse import parse_qs

import httpx
import pytest
from support import NULARA

from nulara.core import config as config_module
from nulara.core import tokens as credentials_module
from nulara.core.config import (
    ProductConfig,
    StoredLogin,
    Surface,
    WorkspaceRef,
    read_login,
    remember_workspace,
    store_token,
)
from nulara.core.errors import AuthenticationError, CliError, ConfigurationError
from nulara.core.oauth import refresh_login
from nulara.core.tokens import REFRESH_MARGIN_SECONDS, get_token

CONFIG = ProductConfig(
    product=NULARA,
    surface=Surface.DEVELOPMENT,
    base_url="http://localhost:5710/v1/app",
    token_env="NULARA_TOKEN",
    keyring_service="nulara-cli",
)
WORKSPACE = WorkspaceRef("workspace-one", "Workspace one")
NOW = 10_000.0
METADATA = {
    "issuer": CONFIG.base_url,
    "authorization_endpoint": "http://localhost:5700/cli/authorize",
    "token_endpoint": f"{CONFIG.base_url}/auth/cli/token",
}


@pytest.fixture
def keyring(monkeypatch) -> dict[tuple[str, str], str]:
    entries: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(
        config_module.keyring,
        "get_password",
        lambda service, username: entries.get((service, username)),
    )
    monkeypatch.setattr(
        config_module.keyring,
        "set_password",
        lambda service, username, value: entries.__setitem__(
            (service, username), value
        ),
    )
    monkeypatch.delenv(CONFIG.token_env, raising=False)
    monkeypatch.setattr(credentials_module.time, "time", lambda: NOW)
    remember_workspace(CONFIG, WORKSPACE)
    return entries


def server(requests: list[dict[str, list[str]]], *, status: int = 200):
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/auth/cli/metadata"):
            return httpx.Response(200, json=METADATA)
        requests.append(parse_qs(request.content.decode()))
        if status != 200:
            return httpx.Response(status, json={"detail": "CLI_AUTH_GRANT_INVALID"})
        return httpx.Response(
            200,
            json={
                "access_token": "nulara_sk_next",
                "refresh_token": "nulara_rt_next",
                "expires_in": 3600,
                "scopes": ["read", "write"],
                "token_prefix": "nulara_sk_x",
                "workspace_id": WORKSPACE.id,
            },
        )

    return httpx.MockTransport(handle)


def test_a_pasted_pat_is_sent_as_stored(keyring) -> None:
    store_token(CONFIG, "nulara_sk_pat", WORKSPACE.id)

    assert get_token(CONFIG) == ("nulara_sk_pat", "OS keyring")
    assert read_login(CONFIG, WORKSPACE) == StoredLogin("nulara_sk_pat")


def test_a_login_with_time_left_is_sent_without_a_refresh(keyring) -> None:
    store_token(
        CONFIG,
        "nulara_sk_now",
        WORKSPACE.id,
        refresh_token="nulara_rt_now",
        access_expires_at=NOW + REFRESH_MARGIN_SECONDS + 1,
    )
    requests: list[dict[str, list[str]]] = []

    assert get_token(CONFIG, transport=server(requests)) == (
        "nulara_sk_now",
        "OS keyring",
    )
    assert requests == []


def test_a_login_about_to_run_out_is_refreshed_and_stored_first(keyring) -> None:
    store_token(
        CONFIG,
        "nulara_sk_old",
        WORKSPACE.id,
        refresh_token="nulara_rt_old",
        access_expires_at=NOW + REFRESH_MARGIN_SECONDS - 1,
    )
    requests: list[dict[str, list[str]]] = []

    assert get_token(CONFIG, transport=server(requests)) == (
        "nulara_sk_next",
        "OS keyring",
    )
    assert requests == [
        {
            "grant_type": ["refresh_token"],
            "client_id": ["nulara-cli"],
            "refresh_token": ["nulara_rt_old"],
        }
    ]
    assert read_login(CONFIG, WORKSPACE) == StoredLogin(
        "nulara_sk_next", "nulara_rt_next", NOW + 3600
    )


def test_a_refresh_another_process_finished_is_not_repeated(
    keyring, monkeypatch
) -> None:
    # The first read sees the old token; by the time the lock is held another
    # process has refreshed and stored. Spending the old refresh token again
    # would end the login, so the second read decides.
    stale = StoredLogin("nulara_sk_old", "nulara_rt_old", NOW - 1)
    fresh = StoredLogin("nulara_sk_new", "nulara_rt_new", NOW + 3600)
    reads = iter([stale, fresh])
    monkeypatch.setattr(credentials_module, "read_login", lambda *_: next(reads))
    requests: list[dict[str, list[str]]] = []

    assert get_token(CONFIG, transport=server(requests)) == (
        "nulara_sk_new",
        "OS keyring",
    )
    assert requests == []


def test_an_ended_login_asks_for_a_new_one(keyring) -> None:
    store_token(
        CONFIG,
        "nulara_sk_old",
        WORKSPACE.id,
        refresh_token="nulara_rt_old",
        access_expires_at=NOW - 1,
    )

    with pytest.raises(AuthenticationError, match="nulara-dev login"):
        get_token(CONFIG, transport=server([], status=400))


def test_a_refresh_answer_for_another_workspace_is_refused(
    keyring, monkeypatch
) -> None:
    store_token(
        CONFIG,
        "nulara_sk_old",
        WORKSPACE.id,
        refresh_token="nulara_rt_old",
        access_expires_at=NOW - 1,
    )
    other = WorkspaceRef("workspace-two", "Workspace two")
    remember_workspace(CONFIG, other)
    store_token(
        CONFIG,
        "nulara_sk_two",
        other.id,
        refresh_token="nulara_rt_two",
        access_expires_at=NOW - 1,
    )

    with pytest.raises(AuthenticationError, match="Unexpected token refresh"):
        get_token(CONFIG, transport=server([]))


def test_an_unopenable_lock_file_is_a_configuration_error(
    keyring, monkeypatch, tmp_path
) -> None:
    store_token(
        CONFIG,
        "nulara_sk_old",
        WORKSPACE.id,
        refresh_token="nulara_rt_old",
        access_expires_at=NOW - 1,
    )
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("")
    monkeypatch.setattr(
        credentials_module, "state_path", lambda _product: blocker / "state.json"
    )

    with pytest.raises(ConfigurationError, match="Could not open"):
        get_token(CONFIG, transport=server([]))


def test_a_login_without_a_selected_workspace_is_not_authenticated(
    monkeypatch,
) -> None:
    monkeypatch.delenv(CONFIG.token_env, raising=False)

    with pytest.raises(AuthenticationError, match="Not authenticated"):
        get_token(CONFIG)


@pytest.mark.parametrize(
    "value",
    ['{"access_token": "x"}', "{broken", '{"access_token": "x", "refresh_token":'],
)
def test_an_unreadable_stored_login_asks_for_a_new_one(keyring, value) -> None:
    keyring[(CONFIG.keyring_service, f"{CONFIG.base_url}#{WORKSPACE.id}")] = value

    with pytest.raises(AuthenticationError, match="unreadable"):
        read_login(CONFIG, WORKSPACE)


def test_an_unreachable_token_endpoint_is_reported(keyring) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/auth/cli/metadata"):
            return httpx.Response(200, json=METADATA)
        raise httpx.ConnectError("synthetic outage", request=request)

    with pytest.raises(CliError, match="Token refresh failed"):
        refresh_login(CONFIG, "nulara_rt_old", transport=httpx.MockTransport(handle))


def test_a_refresh_token_is_never_stored_without_its_deadline(keyring) -> None:
    with pytest.raises(ValueError, match="deadline"):
        store_token(CONFIG, "nulara_sk_x", WORKSPACE.id, refresh_token="rt")

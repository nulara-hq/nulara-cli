"""Credential, URL and state failure boundaries for Nulara."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
from keyring.errors import KeyringError, PasswordDeleteError
from support import NULARA, NULARA_DEV

from nulara.core import config as c
from nulara.core.errors import AuthenticationError, ConfigurationError
from nulara.core.tokens import get_token


@pytest.fixture
def config(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NULARA_API_URL", raising=False)
    monkeypatch.delenv("NULARA_API_TOKEN", raising=False)
    return c.product_config(NULARA_DEV, surface=c.Surface.DEVELOPMENT)


@pytest.mark.parametrize(
    "url",
    [
        "relative",
        "ftp://example.test",
        "https://user:synthetic@example.test",
        "https://example.test?q=1",
        "https://example.test#fragment",
        "http://example.test",
    ],
)
def test_unsafe_api_urls_are_rejected(url):
    with pytest.raises(ConfigurationError):
        c.validate_api_url(url)


def test_nulara_config_precedence_and_project_discovery(config, tmp_path, monkeypatch):
    file = tmp_path / ".nulara.toml"
    file.write_text('api_url="https://api.project.example/v1/app"\n')
    nested = tmp_path / "nested"
    nested.mkdir()
    resolved = c.product_config(NULARA, surface=c.Surface.CUSTOMER, start_dir=nested)
    assert resolved.base_url_source == str(file)
    monkeypatch.setenv("NULARA_API_URL", "https://api.environment.example/v1/app")
    monkeypatch.setenv("NULARA_WORKSPACE", "environment-workspace")
    resolved = c.product_config(NULARA, surface=c.Surface.CUSTOMER, start_dir=nested)
    assert resolved.base_url_source == "NULARA_API_URL"
    assert resolved.workspace_source == "NULARA_WORKSPACE"
    assert resolved.workspace_env == "NULARA_WORKSPACE"
    assert resolved.entrypoint == "nulara"
    assert config.entrypoint == "nulara-dev"
    resolved = c.product_config(
        NULARA,
        surface=c.Surface.CUSTOMER,
        api_url="https://explicit.example",
        workspace="one",
    )
    assert (resolved.base_url_source, resolved.workspace_source) == (
        "--api-url",
        "--workspace",
    )


@pytest.mark.parametrize(
    "contents,expected",
    [
        ("api_url=5", "non-empty string"),
        ('api_url=""', "non-empty string"),
        ("[broken", "Could not read config"),
    ],
)
def test_invalid_project_configuration_fails_closed(
    config, tmp_path, contents, expected
):
    file = tmp_path / ".nulara.toml"
    file.write_text(contents)
    with pytest.raises(ConfigurationError, match=expected):
        c.product_config(NULARA_DEV, surface=c.Surface.DEVELOPMENT, config_file=file)


@pytest.mark.parametrize("contents", ["", "[nulara]\n", "[unrelated]\napi_url=42"])
def test_unset_product_url_uses_default(config, tmp_path, contents):
    file = tmp_path / ".nulara.toml"
    file.write_text(contents)
    assert (
        c.product_config(NULARA_DEV, surface=c.Surface.DEVELOPMENT).base_url
        == config.base_url
    )


def test_missing_explicit_config_is_actionable(config, tmp_path):
    with pytest.raises(ConfigurationError, match="Config file not found"):
        c.product_config(
            NULARA_DEV,
            surface=c.Surface.DEVELOPMENT,
            config_file=tmp_path / "absent",
        )


@pytest.mark.parametrize(
    "state,match",
    [
        ("broken", "Could not read CLI state"),
        ("[]", "Unsupported CLI state"),
        ('{"version":2}', "Unsupported CLI state"),
        ('{"version":1,"remotes":[]}', "no remotes table"),
    ],
)
def test_bad_workspace_state_is_reported(config, state, match):
    path = c.state_path(NULARA_DEV)
    path.parent.mkdir(parents=True)
    path.write_text(state)
    with pytest.raises(ConfigurationError, match=match):
        c.known_workspaces(config)


def test_workspace_selection_ambiguity_and_missing_credentials(config, monkeypatch):
    with pytest.raises(AuthenticationError, match="No workspace"):
        c.match_workspace(config, "one")
    with pytest.raises(AuthenticationError, match="Not authenticated"):
        get_token(config)
    for identity in ["one", "two"]:
        c.remember_workspace(config, c.WorkspaceRef(identity, "Same"))
    with pytest.raises(ConfigurationError, match="more than one"):
        c.match_workspace(config, "SAME")
    with pytest.raises(ConfigurationError, match="Unknown workspace"):
        c.match_workspace(config, "missing")
    assert c.match_workspace(config, "one").id == "one"
    c.set_active_workspace(config, "missing")
    assert c.resolve_workspace(config) is None
    c.forget_workspace(config, "two")
    selected = c.resolve_workspace(config)
    assert selected is not None and selected.id == "one"
    monkeypatch.setattr(c.keyring, "get_password", lambda *args: None)
    with pytest.raises(AuthenticationError, match="workspace Same"):
        get_token(config)
    c.forget_workspace(config, "one")
    assert c.resolve_workspace(config) is None
    c.forget_workspace(replace(config, base_url="https://unused.example"), "one")


def test_remember_without_activation_preserves_selected_workspace(config):
    c.remember_workspace(config, c.WorkspaceRef("one", "One"), activate=False)
    c.remember_workspace(config, c.WorkspaceRef("two", "Two"), activate=False)
    selected = c.resolve_workspace(config)
    assert selected is not None and selected.id == "one"
    c.remember_workspace(config, c.WorkspaceRef("one", "Renamed"), activate=False)
    assert [w.name for w in c.known_workspaces(config)] == ["Renamed", "Two"]


@pytest.mark.parametrize("operation", ["get", "store", "delete"])
def test_keyring_errors_are_authentication_errors(config, monkeypatch, operation):
    c.remember_workspace(config, c.WorkspaceRef("one", "One"))

    def denied(*args):
        raise KeyringError("synthetic locked keyring")

    monkeypatch.setattr(c.keyring, "get_password", denied)
    monkeypatch.setattr(c.keyring, "set_password", denied)
    with pytest.raises(AuthenticationError, match="keyring"):
        if operation == "get":
            get_token(config)
        elif operation == "store":
            c.store_token(config, "synthetic-token", "one")
        else:
            c.delete_token(config, "one")


@pytest.mark.parametrize("state", ["absent", "removed", "present"])
def test_delete_keyring_token_handles_racing_removal(config, monkeypatch, state):
    monkeypatch.setattr(
        c.keyring,
        "get_password",
        lambda *a: None if state == "absent" else "synthetic-token",
    )
    calls = []

    def delete(*args):
        calls.append(args)
        if state == "removed":
            raise PasswordDeleteError("synthetic already removed")

    monkeypatch.setattr(c.keyring, "delete_password", delete)
    assert c.delete_token(config, "one") == (state == "present")
    assert bool(calls) == (state != "absent")


def test_project_only_remote_cannot_receive_environment_token(
    config, monkeypatch, tmp_path
):
    file = tmp_path / ".nulara.toml"
    monkeypatch.setenv(config.token_env, "synthetic-token")
    remote = replace(
        config,
        base_url="https://api.untrusted.example",
        config_file=file,
        base_url_source=str(file),
    )
    with pytest.raises(AuthenticationError, match="Refusing to use"):
        get_token(remote)
    assert get_token(replace(remote, base_url_source="--api-url")) == (
        "synthetic-token",
        config.token_env,
    )


def test_state_io_failures_are_config_errors(config, monkeypatch):
    def denied(*args, **kwargs):
        raise PermissionError("synthetic denied")

    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "read_text", denied)
        with pytest.raises(ConfigurationError, match="Could not read CLI state"):
            c.known_workspaces(config)
    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "write_text", denied)
        with pytest.raises(ConfigurationError, match="Could not write CLI state"):
            c.remember_workspace(config, c.WorkspaceRef("one", "One"))


def test_state_home_fallback_and_malformed_entries(config, monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_CONFIG_HOME")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert c.state_path(NULARA_DEV) == tmp_path / ".config/nulara/state.json"
    path = c.state_path(NULARA_DEV)
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "remotes": {
                    f"nulara|{config.base_url}": {
                        "workspaces": [None, {}, {"id": "one"}]
                    }
                },
            }
        )
    )
    assert c.known_workspaces(config) == [c.WorkspaceRef("one", "one")]


@pytest.mark.parametrize(
    "url,expected",
    [
        ("relative", False),
        ("https://api.example", False),
        ("http://127.0.0.2", True),
        ("http://[::1]", True),
    ],
)
def test_loopback_is_an_address_property(url, expected):
    assert c.is_loopback_url(url) is expected


@pytest.mark.parametrize(
    "url",
    [
        "https://[broken",
        "https://api.nulara.example:invalid/v1/app",
        "https://api.nulara.example:70000/v1/app",
        "https://api.nulara.example:0/v1/app",
        "https://api.nulara.example/with\ncontrol",
        "https://api.nulara.example\\path",
    ],
)
def test_malformed_api_url_fails_as_configuration_error(url):
    with pytest.raises(ConfigurationError):
        c.validate_api_url(url)

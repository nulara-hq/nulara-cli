"""Per-workspace credentials and the local state that indexes them."""

import json
from unittest.mock import Mock

import pytest
from support import NULARA_DEV

from nulara.core import config as config_module
from nulara.core.config import (
    Surface,
    WorkspaceRef,
    active_workspace_id,
    delete_token,
    forget_workspace,
    keyring_username,
    known_workspaces,
    match_workspace,
    product_config,
    remember_workspace,
    resolve_workspace,
    set_active_workspace,
    state_path,
    store_token,
)
from nulara.core.errors import AuthenticationError, ConfigurationError
from nulara.core.tokens import get_token

DEV = Surface.DEVELOPMENT
ACME = WorkspaceRef(id="01a061db-5513-70f1-8f7e-000000000001", name="Acme")
GLOBEX = WorkspaceRef(id="01a061db-5513-70f1-8f7e-000000000002", name="Globex")


def nulara_config() -> config_module.ProductConfig:
    return product_config(NULARA_DEV, surface=DEV)


def test_state_lives_under_xdg_config_home(isolate_cli_state) -> None:
    assert state_path(NULARA_DEV) == isolate_cli_state / "nulara" / "state.json"


def test_state_falls_back_to_home_config(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert state_path(NULARA_DEV) == tmp_path / ".config" / "nulara" / "state.json"


def test_two_workspaces_hold_separate_credentials(monkeypatch) -> None:
    # The defect this replaces: one slot per (product, base_url) meant logging
    # in to a second workspace overwrote the first one's token.
    config = nulara_config()
    slots: dict[str, str] = {}
    monkeypatch.setattr(
        config_module.keyring,
        "set_password",
        lambda _service, username, token: slots.__setitem__(username, token),
    )
    monkeypatch.setattr(
        config_module.keyring,
        "get_password",
        lambda _service, username: slots.get(username),
    )

    store_token(config, "token-acme", ACME.id)
    remember_workspace(config, ACME)
    store_token(config, "token-globex", GLOBEX.id)
    remember_workspace(config, GLOBEX)

    assert slots == {
        keyring_username(config, ACME.id): "token-acme",
        keyring_username(config, GLOBEX.id): "token-globex",
    }
    # The last login is active, and each workspace still resolves to its own.
    assert get_token(nulara_config()) == ("token-globex", "OS keyring")
    set_active_workspace(config, ACME.id)
    assert get_token(nulara_config()) == ("token-acme", "OS keyring")


def test_workspace_override_beats_the_active_workspace(monkeypatch) -> None:
    config = nulara_config()
    remember_workspace(config, ACME)
    remember_workspace(config, GLOBEX)
    set_active_workspace(config, ACME.id)

    by_flag = product_config(NULARA_DEV, surface=DEV, workspace="Globex")
    assert resolve_workspace(by_flag) == GLOBEX
    assert by_flag.workspace_source == "--workspace"

    monkeypatch.setenv("NULARA_WORKSPACE", GLOBEX.id)
    by_env = product_config(NULARA_DEV, surface=DEV)
    assert resolve_workspace(by_env) == GLOBEX
    assert by_env.workspace_source == "NULARA_WORKSPACE"

    # The flag still wins over the environment variable.
    assert (
        product_config(NULARA_DEV, surface=DEV, workspace="Acme").workspace_source
        == "--workspace"
    )


def test_match_workspace_accepts_id_and_name_and_explains_misses() -> None:
    config = nulara_config()
    with pytest.raises(AuthenticationError, match="No workspace is logged in"):
        match_workspace(config, "Acme")

    remember_workspace(config, ACME)
    remember_workspace(config, GLOBEX)
    assert match_workspace(config, ACME.id) == ACME
    assert match_workspace(config, "acme") == ACME

    with pytest.raises(ConfigurationError, match="Unknown workspace"):
        match_workspace(config, "Initech")

    remember_workspace(config, WorkspaceRef(id="duplicate-id", name="Acme"))
    with pytest.raises(ConfigurationError, match="more than one workspace"):
        match_workspace(config, "Acme")


def test_a_single_workspace_needs_no_active_pointer() -> None:
    config = nulara_config()
    remember_workspace(config, ACME)
    set_active_workspace(config, "vanished-workspace")
    # The pointer names a workspace that is no longer logged in; the one
    # remaining credential is still unambiguous.
    assert resolve_workspace(config) == ACME


def test_resolve_returns_nothing_when_the_choice_is_ambiguous() -> None:
    config = nulara_config()
    remember_workspace(config, ACME)
    remember_workspace(config, GLOBEX)
    set_active_workspace(config, "vanished-workspace")
    assert resolve_workspace(config) is None


def test_forget_workspace_hands_the_active_pointer_on(monkeypatch) -> None:
    config = nulara_config()
    remember_workspace(config, ACME)
    remember_workspace(config, GLOBEX)
    set_active_workspace(config, GLOBEX.id)

    forget_workspace(config, GLOBEX.id)
    assert known_workspaces(config) == [ACME]
    assert active_workspace_id(config) == ACME.id

    forget_workspace(config, ACME.id)
    assert known_workspaces(config) == []
    assert active_workspace_id(config) is None
    # Forgetting an unknown remote is a no-op, not an error.
    forget_workspace(product_config(NULARA_DEV, surface=DEV), ACME.id)


def test_remember_keeps_the_active_workspace_when_asked() -> None:
    config = nulara_config()
    remember_workspace(config, ACME)
    remember_workspace(config, GLOBEX, activate=False)
    assert active_workspace_id(config) == ACME.id
    # Names are refreshed in place rather than duplicated.
    remember_workspace(config, WorkspaceRef(id=ACME.id, name="Acme Ltd"))
    assert [workspace.name for workspace in known_workspaces(config)] == [
        "Acme Ltd",
        "Globex",
    ]


def test_missing_token_for_a_known_workspace_names_it(monkeypatch) -> None:
    config = nulara_config()
    remember_workspace(config, ACME)
    monkeypatch.setattr(config_module.keyring, "get_password", Mock(return_value=None))
    with pytest.raises(AuthenticationError, match="workspace Acme"):
        get_token(config)


def test_unknown_remote_and_empty_state_read_as_empty(monkeypatch) -> None:
    config = nulara_config()
    assert known_workspaces(config) == []
    assert active_workspace_id(config) is None
    assert resolve_workspace(config) is None
    monkeypatch.setattr(config_module.keyring, "get_password", Mock(return_value=None))
    assert delete_token(config, ACME.id) is False


def test_unreadable_state_is_reported_not_ignored(monkeypatch) -> None:
    config = nulara_config()
    remember_workspace(config, ACME)
    path = state_path(NULARA_DEV)

    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="Could not read CLI state"):
        known_workspaces(config)

    path.write_text(json.dumps({"version": 999, "remotes": {}}), encoding="utf-8")
    with pytest.raises(ConfigurationError, match="Unsupported CLI state version"):
        known_workspaces(config)

    path.write_text(json.dumps({"version": 1, "remotes": []}), encoding="utf-8")
    with pytest.raises(ConfigurationError, match="no remotes table"):
        known_workspaces(config)


def test_unwritable_state_is_reported(monkeypatch) -> None:
    monkeypatch.setattr(
        config_module.Path,
        "mkdir",
        Mock(side_effect=OSError("read-only")),
    )
    with pytest.raises(ConfigurationError, match="Could not write CLI state"):
        remember_workspace(nulara_config(), ACME)


def test_a_non_dict_remote_entry_is_treated_as_absent() -> None:
    config = nulara_config()
    remember_workspace(config, ACME)
    path = state_path(NULARA_DEV)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["remotes"][next(iter(payload["remotes"]))] = "corrupt"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert known_workspaces(config) == []


def test_malformed_workspace_entries_are_skipped() -> None:
    config = nulara_config()
    remember_workspace(config, ACME)
    path = state_path(NULARA_DEV)
    payload = json.loads(path.read_text(encoding="utf-8"))
    remote = payload["remotes"][next(iter(payload["remotes"]))]
    remote["workspaces"] = ["not-a-dict", {"name": "no id"}, {"id": GLOBEX.id}]
    path.write_text(json.dumps(payload), encoding="utf-8")
    # An entry without a name falls back to its id rather than disappearing.
    assert known_workspaces(config) == [WorkspaceRef(id=GLOBEX.id, name=GLOBEX.id)]

    remote["workspaces"] = "not-a-list"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert known_workspaces(config) == []


def test_workspace_env_var_is_named_after_the_product() -> None:
    assert nulara_config().workspace_env == "NULARA_WORKSPACE"
    assert product_config(NULARA_DEV, surface=DEV).workspace_env == ("NULARA_WORKSPACE")

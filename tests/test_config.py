import re
from unittest.mock import Mock

import pytest
from keyring.errors import KeyringError, PasswordDeleteError
from support import NULARA, NULARA_DEV

from nulara.core import config as config_module
from nulara.core.config import (
    Surface,
    WorkspaceRef,
    delete_token,
    is_loopback_url,
    product_config,
    remember_workspace,
    require_explicit_secret_endpoint,
    store_token,
    validate_api_url,
)
from nulara.core.errors import AuthenticationError, ConfigurationError
from nulara.core.tokens import get_token

DEV = Surface.DEVELOPMENT
WORKSPACE_A = "01a061db-5513-70f1-8f7e-000000000001"
WORKSPACE_B = "01a061db-5513-70f1-8f7e-000000000002"


def test_product_config_and_loopback_detection(monkeypatch) -> None:
    monkeypatch.setenv("NULARA_API_URL", "http://localhost:9999/v1/app/")
    config = product_config(NULARA_DEV, surface=DEV)
    assert config.base_url == "http://localhost:9999/v1/app"
    monkeypatch.delenv("NULARA_API_URL")
    assert product_config(NULARA_DEV, surface=DEV).base_url.endswith(":5710/v1/app")
    assert is_loopback_url(config.base_url)
    assert is_loopback_url("http://127.0.0.1/api")
    assert is_loopback_url("http://[::1]/api")
    assert not is_loopback_url("https://api.example.com")
    assert not is_loopback_url("not-a-url")


def test_surface_selects_the_default_api(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("NULARA_API_URL", raising=False)

    customer = product_config(NULARA, surface=Surface.CUSTOMER, start_dir=tmp_path)
    assert customer.base_url == "https://api.nulara.de/v1/app"
    assert customer.base_url_source == "default"
    assert customer.surface is Surface.CUSTOMER

    development = product_config(NULARA_DEV, surface=DEV, start_dir=tmp_path)
    assert development.base_url == "http://localhost:5710/v1/app"
    assert development.surface is DEV

    explicit = product_config(
        NULARA,
        surface=Surface.CUSTOMER,
        api_url="http://localhost:5710/v1/app",
        start_dir=tmp_path,
    )
    assert explicit.base_url == "http://localhost:5710/v1/app"
    assert explicit.base_url_source == "--api-url"


def test_not_authenticated_names_the_entrypoint_that_was_run(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(config_module.keyring, "get_password", Mock(return_value=None))
    for surface, expected in (
        (Surface.CUSTOMER, "`nulara login`"),
        (DEV, "`nulara-dev login`"),
    ):
        config = product_config(NULARA, surface=surface, start_dir=tmp_path)
        monkeypatch.delenv(config.token_env, raising=False)
        assert config.entrypoint in expected
        with pytest.raises(AuthenticationError, match=re.escape(expected)):
            get_token(config)


def test_config_precedence_and_parent_discovery(monkeypatch, tmp_path) -> None:
    project = tmp_path / "project"
    child = project / "nested"
    child.mkdir(parents=True)
    config_file = project / ".nulara.toml"
    config_file.write_text('api_url = "https://file.example/v1/app/"\n')

    config = product_config(NULARA_DEV, surface=DEV, start_dir=child)
    assert config.base_url == "https://file.example/v1/app"
    assert config.base_url_source == str(config_file)
    assert config.config_file == config_file

    monkeypatch.setenv("NULARA_API_URL", "https://env.example/v1/app")
    assert (
        product_config(NULARA_DEV, surface=DEV, start_dir=child).base_url_source
        == "NULARA_API_URL"
    )
    explicit = product_config(
        NULARA_DEV,
        surface=DEV,
        api_url="https://flag.example/v1/app",
        config_file=config_file,
    )
    assert explicit.base_url == "https://flag.example/v1/app"
    assert explicit.base_url_source == "--api-url"


def test_canonical_project_config_is_discovered(tmp_path) -> None:
    canonical_file = tmp_path / ".nulara.toml"
    canonical_file.write_text('api_url = "https://nulara.example/v1/app"\n')
    canonical = product_config(NULARA_DEV, surface=DEV, start_dir=tmp_path)
    assert canonical.config_file == canonical_file
    assert canonical.base_url == "https://nulara.example/v1/app"


def test_config_defaults_when_the_key_is_absent(tmp_path) -> None:
    config_file = tmp_path / ".nulara.toml"
    config_file.write_text("[other]\napi_url = 'https://example.test'\n")
    assert (
        product_config(NULARA_DEV, surface=DEV, start_dir=tmp_path).base_url_source
        == "default"
    )
    config_file.write_text("label = 'local'\n")
    assert (
        product_config(NULARA_DEV, surface=DEV, start_dir=tmp_path).base_url_source
        == "default"
    )


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("relative/path", "absolute"),
        ("ftp://example.test/v1", "absolute"),
        ("https://user:secret@example.test/v1", "credentials"),
        ("https://example.test/v1?token=x", "query or fragment"),
        ("https://example.test/v1#section", "query or fragment"),
        ("http://example.test/v1", "must use HTTPS"),
    ],
)
def test_api_url_validation(url: str, message: str) -> None:
    with pytest.raises(ConfigurationError, match=message):
        validate_api_url(url)
    assert validate_api_url(" http://127.0.0.1:5710/v1/app/ ") == (
        "http://127.0.0.1:5710/v1/app"
    )


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        ("[nulara", "Could not read"),
        ("[api_url]", "non-empty string"),
        ("api_url = 3", "non-empty string"),
        ('api_url = ""', "non-empty string"),
    ],
)
def test_invalid_project_config(tmp_path, contents: str, message: str) -> None:
    config_file = tmp_path / ".nulara.toml"
    config_file.write_text(contents)
    with pytest.raises(ConfigurationError, match=message):
        product_config(NULARA_DEV, surface=DEV, config_file=config_file)


def test_missing_and_unreadable_config(monkeypatch, tmp_path) -> None:
    missing = tmp_path / "missing.toml"
    with pytest.raises(ConfigurationError, match="not found"):
        product_config(NULARA_DEV, surface=DEV, config_file=missing)

    config_file = tmp_path / ".nulara.toml"
    config_file.write_text("")
    monkeypatch.setattr(type(config_file), "open", Mock(side_effect=OSError("blocked")))
    with pytest.raises(ConfigurationError, match="blocked"):
        product_config(NULARA_DEV, surface=DEV, config_file=config_file)


def test_token_sources_and_keyring_mutations(monkeypatch) -> None:
    config = product_config(NULARA_DEV, surface=DEV)
    monkeypatch.setenv(config.token_env, "env-token")
    assert get_token(config) == ("env-token", config.token_env)
    monkeypatch.delenv(config.token_env)

    remember_workspace(config, WorkspaceRef(id=WORKSPACE_A, name="Acme"))
    monkeypatch.setattr(
        config_module.keyring, "get_password", Mock(return_value="saved")
    )
    assert get_token(config) == ("saved", "OS keyring")
    set_password = Mock()
    monkeypatch.setattr(config_module.keyring, "set_password", set_password)
    store_token(config, "new", WORKSPACE_A)
    set_password.assert_called_once()
    # The slot carries the workspace, so a second workspace does not overwrite
    # the first one's credential.
    assert set_password.call_args.args[1] == f"{config.base_url}#{WORKSPACE_A}"
    delete_password = Mock()
    monkeypatch.setattr(config_module.keyring, "delete_password", delete_password)
    assert delete_token(config, WORKSPACE_A)
    assert [call.args[0] for call in delete_password.call_args_list] == [
        "nulara-cli",
    ]


def test_environment_token_requires_explicit_remote_endpoint(
    monkeypatch, tmp_path
) -> None:
    config_file = tmp_path / ".nulara.toml"
    config_file.write_text('api_url = "https://api.example.test/v1/app"\n')
    config = product_config(NULARA_DEV, surface=DEV, start_dir=tmp_path)
    monkeypatch.setenv(config.token_env, "env-token")
    with pytest.raises(AuthenticationError, match="Refusing.*NULARA_API_TOKEN"):
        get_token(config)

    explicit = product_config(
        NULARA_DEV,
        surface=DEV,
        api_url="https://api.example.test/v1/app",
        config_file=config_file,
    )
    assert get_token(explicit) == ("env-token", explicit.token_env)

    local_file = tmp_path / "local.toml"
    local_file.write_text('api_url = "http://localhost:5710/v1/app"\n')
    local = product_config(NULARA_DEV, surface=DEV, config_file=local_file)
    assert get_token(local) == ("env-token", local.token_env)


def test_customer_default_endpoint_accepts_credentials(monkeypatch, tmp_path) -> None:
    # The production default is a built-in, not a project file, so the
    # anti-redirect guard must not fire on it.
    config = product_config(NULARA, surface=Surface.CUSTOMER, start_dir=tmp_path)
    monkeypatch.setenv(config.token_env, "env-token")
    require_explicit_secret_endpoint(config, "a pasted PAT")
    assert get_token(config) == ("env-token", config.token_env)


def test_project_config_endpoint_is_safe_for_endpoint_scoped_keyring(
    monkeypatch, tmp_path
) -> None:
    config_file = tmp_path / ".nulara.toml"
    config_file.write_text('api_url = "https://api.example.test/v1/app"\n')
    config = product_config(NULARA_DEV, surface=DEV, start_dir=tmp_path)
    monkeypatch.delenv(config.token_env, raising=False)
    remember_workspace(config, WorkspaceRef(id=WORKSPACE_A, name="Acme"))
    monkeypatch.setattr(
        config_module.keyring, "get_password", Mock(return_value="saved")
    )
    assert get_token(config) == ("saved", "OS keyring")
    with pytest.raises(AuthenticationError, match="pass --api-url"):
        require_explicit_secret_endpoint(config, "a pasted PAT")


def test_keyring_failures_are_mapped(monkeypatch) -> None:
    config = product_config(NULARA_DEV, surface=DEV)
    monkeypatch.delenv(config.token_env, raising=False)
    remember_workspace(config, WorkspaceRef(id=WORKSPACE_A, name="Acme"))
    monkeypatch.setattr(config_module.keyring, "get_password", Mock(return_value=None))
    with pytest.raises(AuthenticationError, match="Not authenticated"):
        get_token(config)
    assert not delete_token(config, WORKSPACE_A)

    monkeypatch.setattr(
        config_module.keyring, "get_password", Mock(side_effect=KeyringError("broken"))
    )
    with pytest.raises(AuthenticationError, match="unavailable"):
        get_token(config)
    with pytest.raises(AuthenticationError, match="access"):
        delete_token(config, WORKSPACE_A)

    monkeypatch.setattr(
        config_module.keyring, "set_password", Mock(side_effect=KeyringError("broken"))
    )
    with pytest.raises(AuthenticationError, match="store"):
        store_token(config, "token", WORKSPACE_A)

    monkeypatch.setattr(
        config_module.keyring, "get_password", Mock(return_value="saved")
    )
    monkeypatch.setattr(
        config_module.keyring,
        "delete_password",
        Mock(side_effect=PasswordDeleteError("gone")),
    )
    assert not delete_token(config, WORKSPACE_A)

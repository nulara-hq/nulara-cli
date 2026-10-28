import json
import math
import os
import tomllib
from dataclasses import dataclass
from enum import Enum
from importlib.resources.abc import Traversable
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import keyring
from keyring.errors import KeyringError, PasswordDeleteError

from nulara.core.errors import AuthenticationError, ConfigurationError

# Which workspace each remote is currently pointed at, plus the names needed to
# resolve `workspace use <name>` without a server call. Deliberately not in the
# OS keyring: a workspace id is not a secret, and the keyring cannot be
# enumerated portably, so `auth status` could otherwise not list what is stored.
STATE_FILENAME = "state.json"
STATE_VERSION = 1
# Seconds an API request may take; --request-timeout or <PRODUCT>_TIMEOUT
# override it.
DEFAULT_TIMEOUT = 15.0


@dataclass(frozen=True)
class Product:
    """Everything the CLI knows about the product it is the front door of.

    The entrypoint builds it; nothing below it knows which products exist.
    """

    # The command name. It also names the environment variables, the keyring
    # service, the state directory and the project file.
    name: str
    display_name: str
    # The API an invocation talks to unless --api-url, the environment or the
    # project file says otherwise.
    api_url: str
    # Registered with the product's authorization server.
    oauth_client_id: str
    # The generated command manifest (`openapi.write_command_manifest`).
    manifest: Traversable
    version: str
    # A Claude Code skill shipped with the entrypoint; `claude-code install`
    # copies it into a skills directory. None registers no such command.
    skill: Traversable | None = None

    @property
    def env_prefix(self) -> str:
        return self.name.upper().replace("-", "_")

    @property
    def keyring_service(self) -> str:
        return f"{self.name}-cli"

    @property
    def project_config_filename(self) -> str:
        return f".{self.name}.toml"


class Surface(str, Enum):
    """Which entrypoint is asking, because they default to different APIs."""

    CUSTOMER = "customer"
    DEVELOPMENT = "development"


@dataclass(frozen=True)
class WorkspaceRef:
    """A workspace this machine holds a token for."""

    id: str
    name: str


@dataclass(frozen=True)
class ProductConfig:
    product: Product
    surface: Surface
    base_url: str
    token_env: str
    keyring_service: str
    base_url_source: str = "default"
    config_file: Path | None = None
    # Name or id passed with `--workspace` or the product's workspace
    # environment variable. Overrides the stored active workspace for this
    # invocation only, the way `gh --repo` or `aws --profile` do.
    workspace: str | None = None
    workspace_source: str = "active workspace"
    timeout: float = DEFAULT_TIMEOUT

    @property
    def entrypoint(self) -> str:
        if self.surface is Surface.DEVELOPMENT:
            return f"{self.product.name}-dev"
        return self.product.name

    @property
    def workspace_env(self) -> str:
        """Per-invocation workspace override, e.g. NULARA_WORKSPACE."""
        return f"{self.product.env_prefix}_WORKSPACE"

    @property
    def user_agent(self) -> str:
        return f"{self.product.name}/{self.product.version}"


def product_config(
    product: Product,
    *,
    surface: Surface,
    api_url: str | None = None,
    config_file: Path | None = None,
    start_dir: Path | None = None,
    workspace: str | None = None,
    timeout: float | None = None,
) -> ProductConfig:
    env_prefix = product.env_prefix
    api_url_env = f"{env_prefix}_API_URL"
    workspace_env = f"{env_prefix}_WORKSPACE"
    timeout_env = f"{env_prefix}_TIMEOUT"
    resolved_file = _resolve_config_file(product, config_file, start_dir=start_dir)
    file_url = _read_api_url(resolved_file)
    if api_url is not None:
        base_url, source = api_url, "--api-url"
    elif env_url := os.getenv(api_url_env):
        base_url, source = env_url, api_url_env
    elif file_url is not None:
        base_url, source = file_url, str(resolved_file)
    else:
        base_url, source = product.api_url, "default"
    base_url = validate_api_url(base_url)
    if workspace is not None:
        selector, workspace_source = workspace, "--workspace"
    elif env_workspace := os.getenv(workspace_env):
        selector, workspace_source = env_workspace, workspace_env
    else:
        selector, workspace_source = None, "active workspace"
    return ProductConfig(
        product=product,
        surface=surface,
        base_url=base_url,
        token_env=f"{env_prefix}_API_TOKEN",
        keyring_service=product.keyring_service,
        base_url_source=source,
        config_file=resolved_file,
        workspace=selector,
        workspace_source=workspace_source,
        timeout=_resolve_timeout(timeout, timeout_env),
    )


def _resolve_timeout(explicit: float | None, env_name: str) -> float:
    if explicit is not None:
        value, source = explicit, "--request-timeout"
    elif raw := os.getenv(env_name):
        try:
            value = float(raw)
        except ValueError as exc:
            raise ConfigurationError(f"{env_name} must be a number of seconds") from exc
        source = env_name
    else:
        return DEFAULT_TIMEOUT
    if not math.isfinite(value) or value <= 0:
        raise ConfigurationError(f"{source} must be a positive number of seconds")
    return value


def validate_api_url(url: str) -> str:
    normalized = url.strip().rstrip("/")
    if any(ord(char) <= 32 or char == "\\" for char in normalized):
        raise ConfigurationError("API URL must not contain whitespace or backslashes")
    try:
        parsed = urlparse(normalized)
        port = parsed.port
    except ValueError as exc:
        raise ConfigurationError("API URL is not a valid absolute http(s) URL") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigurationError("API URL must be an absolute http(s) URL")
    if port == 0:
        raise ConfigurationError("API URL port must be between 1 and 65535")
    if parsed.username or parsed.password:
        raise ConfigurationError("API URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ConfigurationError("API URL must not contain a query or fragment")
    if parsed.scheme != "https" and not is_loopback_url(normalized):
        raise ConfigurationError(
            "Non-loopback API URLs must use HTTPS to protect bearer tokens"
        )
    return normalized


def is_loopback_url(url: str) -> bool:
    hostname = urlparse(url).hostname
    if hostname == "localhost":
        return True
    if hostname is None:
        return False
    try:
        return ip_address(hostname).is_loopback
    except ValueError:
        return False


def _resolve_config_file(
    product: Product, explicit: Path | None, *, start_dir: Path | None
) -> Path | None:
    if explicit is not None:
        path = explicit.expanduser().resolve()
        if not path.is_file():
            raise ConfigurationError(f"Config file not found: {path}")
        return path
    current = (start_dir or Path.cwd()).resolve()
    for directory in (current, *current.parents):
        candidate = directory / product.project_config_filename
        if candidate.is_file():
            return candidate
    return None


def _read_api_url(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        with path.open("rb") as file:
            payload: Any = tomllib.load(file)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"Could not read config file {path}: {exc}") from exc
    api_url = payload.get("api_url")
    if api_url is None:
        return None
    if not isinstance(api_url, str) or not api_url.strip():
        raise ConfigurationError(f"api_url must be a non-empty string in {path}")
    return api_url


def state_path(product: Product) -> Path:
    """Where the active workspace and the known workspace names are recorded."""
    base = os.getenv("XDG_CONFIG_HOME")
    root = Path(base).expanduser() if base else Path.home() / ".config"
    return root / product.name / STATE_FILENAME


def _remote_key(config: ProductConfig) -> str:
    """State is keyed per product *and* API, so a dev and a prod login coexist."""
    return f"{config.product.name}|{config.base_url}"


def _read_state(product: Product) -> dict[str, Any]:
    path = state_path(product)
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"version": STATE_VERSION, "remotes": {}}
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Could not read CLI state {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("version") != STATE_VERSION:
        raise ConfigurationError(
            f"Unsupported CLI state version in {path}. Remove the file to start over."
        )
    remotes = payload.get("remotes")
    if not isinstance(remotes, dict):
        raise ConfigurationError(f"CLI state {path} has no remotes table")
    return payload


def _write_state(product: Product, state: dict[str, Any]) -> None:
    path = state_path(product)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Written through a sibling and renamed so an interrupted write cannot
        # leave a half-file that every later invocation refuses to parse.
        temporary = path.with_name(f"{path.name}.tmp")
        temporary.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.replace(path)
    except OSError as exc:
        raise ConfigurationError(f"Could not write CLI state {path}: {exc}") from exc


def _remote_state(config: ProductConfig) -> dict[str, Any]:
    remote = _read_state(config.product)["remotes"].get(_remote_key(config))
    return remote if isinstance(remote, dict) else {}


def known_workspaces(config: ProductConfig) -> list[WorkspaceRef]:
    """Workspaces this machine has logged in to for this product and API."""
    entries = _remote_state(config).get("workspaces")
    if not isinstance(entries, list):
        return []
    return [
        WorkspaceRef(id=str(entry["id"]), name=str(entry.get("name", entry["id"])))
        for entry in entries
        if isinstance(entry, dict) and entry.get("id")
    ]


def active_workspace_id(config: ProductConfig) -> str | None:
    active = _remote_state(config).get("active_workspace_id")
    return str(active) if active else None


def remember_workspace(
    config: ProductConfig, workspace: WorkspaceRef, *, activate: bool = True
) -> None:
    """Record a workspace this machine now holds a token for."""
    state = _read_state(config.product)
    remote = state["remotes"].setdefault(_remote_key(config), {})
    entries = [entry for entry in known_workspaces(config) if entry.id != workspace.id]
    entries.append(workspace)
    remote["workspaces"] = [
        {"id": entry.id, "name": entry.name}
        for entry in sorted(entries, key=lambda entry: entry.name.casefold())
    ]
    if activate or not remote.get("active_workspace_id"):
        remote["active_workspace_id"] = workspace.id
    _write_state(config.product, state)


def set_active_workspace(config: ProductConfig, workspace_id: str) -> None:
    state = _read_state(config.product)
    remote = state["remotes"].setdefault(_remote_key(config), {})
    remote["active_workspace_id"] = workspace_id
    _write_state(config.product, state)


def forget_workspace(config: ProductConfig, workspace_id: str) -> None:
    """Drop one workspace from the state file, after its token is gone."""
    state = _read_state(config.product)
    remote = state["remotes"].get(_remote_key(config))
    if not isinstance(remote, dict):
        return
    remote["workspaces"] = [
        {"id": entry.id, "name": entry.name}
        for entry in known_workspaces(config)
        if entry.id != workspace_id
    ]
    if remote.get("active_workspace_id") == workspace_id:
        remaining = remote["workspaces"]
        remote["active_workspace_id"] = remaining[0]["id"] if remaining else None
    _write_state(config.product, state)


def match_workspace(config: ProductConfig, selector: str) -> WorkspaceRef:
    """Resolve a `<name|id>` selector against what this machine already knows.

    Name matching is what makes `workspace use` a local operation: the names
    were recorded at login, so switching needs no server call and no re-login.
    """
    known = known_workspaces(config)
    for workspace in known:
        if workspace.id == selector:
            return workspace
    matches = [
        workspace
        for workspace in known
        if workspace.name.casefold() == selector.casefold()
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise ConfigurationError(
            f"{selector!r} matches more than one workspace. Use the workspace id: "
            + ", ".join(workspace.id for workspace in matches)
        )
    if not known:
        raise AuthenticationError(
            f"No workspace is logged in for {config.base_url}. "
            f"Run `{config.entrypoint} login`."
        )
    raise ConfigurationError(
        f"Unknown workspace {selector!r}. Logged in: "
        + ", ".join(f"{workspace.name} ({workspace.id})" for workspace in known)
    )


def resolve_workspace(config: ProductConfig) -> WorkspaceRef | None:
    """Which workspace this invocation acts as, override first."""
    if config.workspace is not None:
        return match_workspace(config, config.workspace)
    active = active_workspace_id(config)
    known = known_workspaces(config)
    for workspace in known:
        if workspace.id == active:
            return workspace
    return known[0] if len(known) == 1 else None


def keyring_username(config: ProductConfig, workspace_id: str) -> str:
    """Keyring slot for one workspace at one API.

    A PAT is audience-restricted to the workspace it was minted for, so the slot
    carries the workspace id — otherwise a second login overwrites the first and
    only one workspace can be driven at a time.
    """
    return f"{config.base_url}#{workspace_id}"


@dataclass(frozen=True)
class StoredLogin:
    """What the keyring holds for one workspace.

    A PAT pasted with `auth login` is only a token. A browser or device login
    also holds the refresh token that replaces its hour-long bearer token, and
    the epoch second that bearer token stops working. Either is one keyring
    entry, so a workspace never has half a credential.
    """

    access_token: str
    refresh_token: str | None = None
    access_expires_at: float | None = None


def _encode_login(login: StoredLogin) -> str:
    if login.refresh_token is None:
        return login.access_token
    return json.dumps(
        {
            "access_token": login.access_token,
            "refresh_token": login.refresh_token,
            "access_expires_at": login.access_expires_at,
        },
        sort_keys=True,
    )


def _decode_login(value: str) -> StoredLogin:
    # A PAT is `<product>_sk_…` and never starts with a brace, so the two shapes
    # cannot be mistaken for each other.
    if not value.startswith("{"):
        return StoredLogin(access_token=value)
    try:
        payload: Any = json.loads(value)
        login = StoredLogin(
            access_token=str(payload["access_token"]),
            refresh_token=str(payload["refresh_token"]),
            access_expires_at=float(payload["access_expires_at"]),
        )
    except (ValueError, TypeError, KeyError) as exc:
        raise AuthenticationError(
            "The stored login is unreadable. Run `login` again."
        ) from exc
    return login


def read_login(config: ProductConfig, workspace: WorkspaceRef) -> StoredLogin:
    try:
        value = keyring.get_password(
            config.keyring_service, keyring_username(config, workspace.id)
        )
    except KeyringError as exc:
        raise AuthenticationError(f"OS keyring unavailable: {exc}") from exc
    if not value:
        raise AuthenticationError(
            f"Not authenticated for workspace {workspace.name}. "
            f"Run `{config.entrypoint} login` or set {config.token_env}."
        )
    return _decode_login(value)


def require_explicit_secret_endpoint(
    config: ProductConfig, credential_source: str
) -> None:
    """Refuse a credential operation against a project-config-only remote API.

    A checked-in project file must not be able to choose where credentials are
    sent (a pasted PAT) or minted (the browser login, whose consent page is
    named by that API's discovery document).
    """
    if (
        config.config_file is not None
        and config.base_url_source == str(config.config_file)
        and not is_loopback_url(config.base_url)
    ):
        api_url_env = f"{config.product.env_prefix}_API_URL"
        raise AuthenticationError(
            f"Refusing to use {credential_source} with an API URL sourced only "
            f"from {config.config_file}. Set {api_url_env} or pass --api-url "
            "explicitly."
        )


def store_token(
    config: ProductConfig,
    token: str,
    workspace_id: str,
    *,
    refresh_token: str | None = None,
    access_expires_at: float | None = None,
) -> None:
    if (refresh_token is None) != (access_expires_at is None):
        raise ValueError("A refresh token is stored together with its deadline")
    login = StoredLogin(
        access_token=token,
        refresh_token=refresh_token,
        access_expires_at=access_expires_at,
    )
    try:
        keyring.set_password(
            config.keyring_service,
            keyring_username(config, workspace_id),
            _encode_login(login),
        )
    except KeyringError as exc:
        raise AuthenticationError(
            f"Could not store token in OS keyring: {exc}"
        ) from exc


def delete_token(config: ProductConfig, workspace_id: str) -> bool:
    """Remove one workspace's token, leaving the other workspaces signed in."""
    try:
        username = keyring_username(config, workspace_id)
        if keyring.get_password(config.keyring_service, username) is None:
            return False
        try:
            keyring.delete_password(config.keyring_service, username)
        except PasswordDeleteError:
            return False
        return True
    except KeyringError as exc:
        raise AuthenticationError(f"Could not access OS keyring: {exc}") from exc

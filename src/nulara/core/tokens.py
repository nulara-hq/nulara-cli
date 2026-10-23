"""The bearer token a command sends, refreshed before it runs out.

A browser or device login stores an hour-long bearer token and a refresh token
(RFC 6749 §6). The refresh token is single use: the server spends it on every
refresh and ends the whole login when a spent one comes back (RFC 9700
§4.14.2). Two CLI processes refreshing with the same stored token would
therefore log the user out — an agent running commands in parallel does exactly
that. Refreshing happens under an exclusive file lock, and the keyring is read
again once the lock is held, so the second process finds the token the first
one just stored instead of spending the old one a second time.
"""

import fcntl
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager

import httpx

from nulara.core.config import (
    Product,
    ProductConfig,
    StoredLogin,
    WorkspaceRef,
    read_login,
    require_explicit_secret_endpoint,
    resolve_workspace,
    state_path,
    store_token,
)
from nulara.core.errors import AuthenticationError, ConfigurationError
from nulara.core.oauth import refresh_login

# Refresh this long before the deadline, so a request that starts just before
# it does not arrive just after it.
REFRESH_MARGIN_SECONDS = 60.0
REFRESH_LOCK_FILENAME = "refresh.lock"


def get_token(
    config: ProductConfig, *, transport: httpx.BaseTransport | None = None
) -> tuple[str, str]:
    if token := os.getenv(config.token_env):
        require_explicit_secret_endpoint(config, config.token_env)
        return token, config.token_env
    workspace = resolve_workspace(config)
    if workspace is None:
        raise AuthenticationError(
            f"Not authenticated. Run `{config.entrypoint} login` or set "
            f"{config.token_env}."
        )
    login = read_login(config, workspace)
    if _due_refresh_token(login) is not None:
        with _refresh_lock(config.product):
            login = read_login(config, workspace)
            if (refresh_token := _due_refresh_token(login)) is not None:
                login = _refresh(config, workspace, refresh_token, transport=transport)
    return login.access_token, "OS keyring"


def _due_refresh_token(login: StoredLogin) -> str | None:
    """The refresh token, if the bearer token beside it is about to run out."""
    if login.refresh_token is None or login.access_expires_at is None:
        return None
    if login.access_expires_at - time.time() >= REFRESH_MARGIN_SECONDS:
        return None
    return login.refresh_token


def _refresh(
    config: ProductConfig,
    workspace: WorkspaceRef,
    refresh_token: str,
    *,
    transport: httpx.BaseTransport | None,
) -> StoredLogin:
    result = refresh_login(config, refresh_token, transport=transport)
    if result.workspace_id != workspace.id or result.refresh_token is None:
        raise AuthenticationError(
            f"Unexpected token refresh response. Run `{config.entrypoint} login` again."
        )
    # Stored before anything else: the refresh token sent above is spent now.
    access_expires_at = time.time() + result.expires_in
    store_token(
        config,
        result.token,
        workspace.id,
        refresh_token=result.refresh_token,
        access_expires_at=access_expires_at,
    )
    return StoredLogin(
        access_token=result.token,
        refresh_token=result.refresh_token,
        access_expires_at=access_expires_at,
    )


@contextmanager
def _refresh_lock(product: Product) -> Iterator[None]:
    path = state_path(product).with_name(REFRESH_LOCK_FILENAME)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.open("a")
    except OSError as exc:
        raise ConfigurationError(f"Could not open {path}: {exc}") from exc
    with handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


__all__ = ["REFRESH_MARGIN_SECONDS", "get_token"]

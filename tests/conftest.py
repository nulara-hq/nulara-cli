"""Suite-wide isolation for CLI tests."""

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolate_cli_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep every test's workspace state inside its own directory.

    `state_path()` resolves through `XDG_CONFIG_HOME`, so without this a test
    that stores a workspace writes to the developer's real `~/.config` and the
    next test inherits it. The workspace override variables are cleared for the
    same reason: a shell that exports one must not steer the suite.
    """
    config_home = tmp_path / "xdg-config"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    for product in ("NULARA",):
        monkeypatch.delenv(f"{product}_WORKSPACE", raising=False)
    return config_home


@pytest.fixture(autouse=True)
def retry_pauses(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record the client's retry pauses instead of sleeping through them."""
    pauses: list[float] = []
    monkeypatch.setattr("nulara.core.client._pause", pauses.append)
    return pauses

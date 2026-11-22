"""Suite-wide isolation for CLI tests."""

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolate_cli_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep every test's workspace state inside its own directory.

    `state_path()` resolves through `XDG_CONFIG_HOME`, so without this a test
    that stores a workspace writes to the developer's real `~/.config`. The
    workspace override is cleared for the same reason: a shell that exports it
    must not steer the suite.
    """
    config_home = tmp_path / "xdg-config"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    monkeypatch.delenv("NULARA_WORKSPACE", raising=False)
    return config_home

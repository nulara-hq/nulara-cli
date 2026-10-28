"""Nulara's machine output remains parseable at terminal-width boundaries."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def invoke(
    tmp_path: Path, columns: int, *arguments: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "from nulara import main; main()",
            *arguments,
        ],
        cwd=tmp_path,
        env={
            "PATH": os.environ.get("PATH", ""),
            "COLUMNS": str(columns),
            "NO_COLOR": "1",
            "XDG_CONFIG_HOME": str(tmp_path / "config"),
            "PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring",
        },
        input="",
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )


@pytest.mark.parametrize("columns", [20, 80])
def test_json_confirmation_error_is_one_complete_json_document(
    tmp_path: Path, columns: int
) -> None:
    result = invoke(
        tmp_path,
        columns,
        "locations",
        "create",
        "--name",
        "Synthetic warehouse",
        "--type",
        "warehouse",
        "--timezone",
        "Europe/Berlin",
        "--json",
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert json.loads(result.stderr) == {
        "error": "runtime_error",
        "exit_code": 1,
        "message": "POST /locations mutates data; pass --yes in non-interactive use",
    }
    assert len(result.stderr.splitlines()) == 1


def test_json_configuration_error_preserves_long_unicode_path(tmp_path: Path) -> None:
    missing = tmp_path / ("synthetic-ü-" * 15 + ".toml")
    result = invoke(
        tmp_path, 20, "locations", "list", "--json", "--config", str(missing)
    )
    assert result.returncode == 2
    payload = json.loads(result.stderr)
    assert payload["error"] == "configuration_error"
    assert str(missing) in payload["message"]
    assert result.stdout == ""
    assert len(result.stderr.splitlines()) == 1


@pytest.mark.parametrize("json_output", [True, False])
def test_a_parse_error_has_its_own_exit_code(tmp_path: Path, json_output: bool) -> None:
    result = invoke(
        tmp_path,
        80,
        "locations",
        "list",
        "--no-such-option",
        *(["--json"] if json_output else []),
    )
    assert result.returncode == 9
    assert result.stdout == ""
    if json_output:
        payload = json.loads(result.stderr)
        assert payload["error"] == "usage_error"
        assert payload["exit_code"] == 9
        assert "--no-such-option" in payload["message"]
        assert len(result.stderr.splitlines()) == 1
    else:
        assert "--no-such-option" in result.stderr


def test_a_usage_error_raised_by_a_command_is_printed(tmp_path: Path) -> None:
    result = invoke(tmp_path, 80, "describe", "no-such-module")
    assert result.returncode == 9
    assert "Unknown module `no-such-module`" in result.stderr

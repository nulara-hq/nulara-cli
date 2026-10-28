"""The packaged Claude Code skill installs into a skills directory."""

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cyclopts import App
from support import NULARA

from nulara.core import skill as skill_module
from nulara.core.config import Surface
from nulara.core.errors import CliError
from nulara.core.main import build_app
from nulara.core.skill import install_skill

SKILL = NULARA.skill.read_text(encoding="utf-8") if NULARA.skill else ""


@pytest.fixture
def invoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    rendered: list[Any] = []
    monkeypatch.setattr(skill_module, "render_json", rendered.append)
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    monkeypatch.chdir(tmp_path)
    app = build_app(NULARA, Surface.CUSTOMER)

    def run(*tokens: str) -> Any:
        try:
            app(["claude-code", *tokens], exit_on_error=False)
        except SystemExit as exc:
            assert exc.code == 0
        return rendered[-1] if rendered else None

    return run


def test_the_skill_names_itself_and_the_commands_it_teaches() -> None:
    assert SKILL.startswith("---\nname: nulara\ndescription: ")
    for command in ("nulara describe", "--all", "--dry-run", "get-qr-code"):
        assert command in SKILL


def test_install_writes_the_personal_skill_and_reports_it(invoke, tmp_path) -> None:
    target = tmp_path / "home/.claude/skills/nulara/SKILL.md"
    assert invoke("install", "--json") == {"status": "installed", "path": str(target)}
    assert target.read_text(encoding="utf-8") == SKILL
    assert invoke("install", "--json")["status"] == "unchanged"


def test_install_into_the_project(invoke, tmp_path) -> None:
    invoke("install", "--project", "--json")
    assert (tmp_path / ".claude/skills/nulara/SKILL.md").read_text() == SKILL


def test_a_changed_skill_is_replaced_only_with_force(invoke, tmp_path) -> None:
    target = tmp_path / "home/.claude/skills/nulara/SKILL.md"
    target.parent.mkdir(parents=True)
    target.write_text("edited by hand")
    with pytest.raises(CliError, match="pass --force"):
        invoke("install")
    assert target.read_text() == "edited by hand"
    assert invoke("install", "--force", "--json")["status"] == "updated"
    assert target.read_text(encoding="utf-8") == SKILL
    assert not list(target.parent.glob(".SKILL.*"))


def test_install_reports_unwritable_and_unreadable_targets(tmp_path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir(mode=0o500)
    try:
        with pytest.raises(CliError, match="Could not write"):
            install_skill("x", locked / "nulara/SKILL.md", force=False)
    finally:
        locked.chmod(0o700)
    directory = tmp_path / "SKILL.md"
    directory.mkdir()
    with pytest.raises(CliError, match="Could not read"):
        install_skill("x", directory, force=False)


def test_show_prints_the_skill_verbatim(invoke, capsys) -> None:
    invoke("show")
    assert capsys.readouterr().out == SKILL


def test_a_product_without_a_skill_has_no_command() -> None:
    app = build_app(replace(NULARA, skill=None), Surface.CUSTOMER)
    assert "claude-code" not in app
    assert isinstance(build_app(NULARA, Surface.CUSTOMER)["claude-code"], App)

import os
import sys
import tempfile
from pathlib import Path
from typing import Annotated

from cyclopts import App, Parameter
from rich.console import Console

from nulara.core.config import Product
from nulara.core.errors import CliError
from nulara.core.render import render_json

console = Console()


def register_skill_commands(app: App, product: Product) -> None:
    """`claude-code install|show` for the skill an entrypoint ships, if any.

    Not under `agent`: that group runs the workspace agent.
    """
    if product.skill is None:
        return
    skill = product.skill
    group = app.command(
        App(name="claude-code", help="Set up Claude Code to work with this CLI.")
    )

    @group.command
    def install(
        *,
        project: Annotated[
            bool,
            Parameter(
                negative=(),
                help=(
                    "Install into .claude/skills/ of the current directory, for "
                    "everyone working in it, instead of ~/.claude/skills/."
                ),
            ),
        ] = False,
        force: Annotated[
            bool,
            Parameter(negative=(), help="Replace a skill file that was changed."),
        ] = False,
        json_output: Annotated[
            bool,
            Parameter(name="--json", negative=(), help="Print the result as JSON."),
        ] = False,
    ) -> None:
        """Install the skill that teaches Claude Code to use this CLI."""
        base = Path.cwd() if project else Path.home()
        target = base / ".claude" / "skills" / product.name / "SKILL.md"
        status = install_skill(skill.read_text(encoding="utf-8"), target, force=force)
        if json_output:
            render_json({"status": status, "path": str(target)})
        else:
            console.print(f"[green]Skill {status}[/green]: {target}")

    @group.command
    def show() -> None:
        """Print the skill, for an agent that reads instructions from stdin."""
        # Verbatim: a Rich console would wrap lines at the terminal width.
        sys.stdout.write(skill.read_text(encoding="utf-8"))


def install_skill(content: str, target: Path, *, force: bool) -> str:
    """Write the skill atomically; never overwrite local edits without --force."""
    try:
        current = target.read_text(encoding="utf-8")
    except FileNotFoundError:
        current = None
    except OSError as exc:
        raise CliError(f"Could not read {target}: {exc}") from exc
    if current == content:
        return "unchanged"
    if current is not None and not force:
        raise CliError(f"{target} differs from this version's skill; pass --force")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=".SKILL.", suffix=".part", dir=target.parent
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temporary, target)
    except OSError as exc:
        raise CliError(f"Could not write {target}: {exc}") from exc
    return "installed" if current is None else "updated"

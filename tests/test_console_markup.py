"""Server- and agent-supplied text reaches the terminal as text, never as Rich markup."""

import sys
from io import StringIO

import pytest
from cyclopts import App
from rich.console import Console

from nulara.core import main as main_module
from nulara.core.errors import CliError


def _capture(monkeypatch: pytest.MonkeyPatch, name: str) -> StringIO:
    output = StringIO()
    monkeypatch.setattr(main_module, name, Console(file=output, width=200))
    return output


def test_pending_action_shows_markup_in_name_and_args_literally(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _capture(monkeypatch, "console")
    monkeypatch.setattr(main_module.Confirm, "ask", lambda *_args, **_kwargs: False)

    decisions = main_module._prompt_agent_decisions(
        {
            "action_requests": [
                {
                    "id": "action-1",
                    "name": "delete_[conceal]all[/conceal]",
                    "args": {"note": "[conceal]every record[/conceal]"},
                }
            ]
        }
    )

    printed = output.getvalue()
    assert "delete_[conceal]all[/conceal]" in printed
    assert "[conceal]every record[/conceal]" in printed
    assert decisions["decisions"] == [
        {"type": "reject", "action_request_id": "action-1"}
    ]


def test_error_message_with_a_closing_tag_prints_instead_of_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _capture(monkeypatch, "error_console")

    def fail() -> App:
        raise CliError("detail [/link] from the server")

    monkeypatch.setattr(sys, "argv", ["nulara"])

    with pytest.raises(SystemExit):
        main_module.run(fail)

    assert "detail [/link] from the server" in output.getvalue()

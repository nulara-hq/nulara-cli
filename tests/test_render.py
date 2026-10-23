import json
from datetime import date
from unittest.mock import Mock

import pytest
from rich.table import Table

from nulara.core import render


def test_render_json_serializes_non_json_values(monkeypatch) -> None:
    console = Mock()
    monkeypatch.setattr(render, "console", console)

    render.render_json({"date": date(2026, 7, 13)})

    console.print_json.assert_called_once_with('{"date": "2026-07-13"}')


@pytest.mark.parametrize("payload", [{}, {"items": []}, {"items": "invalid"}, [1]])
def test_render_rows_falls_back_for_non_tabular_payloads(
    monkeypatch, payload: object
) -> None:
    rendered: list[object] = []
    monkeypatch.setattr(render, "render_json", rendered.append)

    render.render_rows(payload)

    assert rendered == [payload]


def test_render_rows_builds_table_from_wrapped_items(monkeypatch) -> None:
    printed: list[Table] = []
    monkeypatch.setattr(render.console, "print", printed.append)
    payload = {
        "items": [
            {"id": 1, "details": {"ready": True}, "optional": None},
            {"id": 2, "details": ["one", "two"], "optional": "present"},
        ]
    }

    render.render_rows(payload)

    table = printed[0]
    assert [column.header for column in table.columns] == [
        "id",
        "details",
        "optional",
    ]
    assert [list(column.cells) for column in table.columns] == [
        ["1", "2"],
        [json.dumps({"ready": True}), json.dumps(["one", "two"])],
        ["", "present"],
    ]


def test_render_rows_limits_discovered_columns(monkeypatch) -> None:
    printed: list[Table] = []
    monkeypatch.setattr(render.console, "print", printed.append)

    render.render_rows([{f"column_{index}": index for index in range(9)}])

    assert [column.header for column in printed[0].columns] == [
        f"column_{index}" for index in range(8)
    ]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"key": "välue"}, '{"key": "välue"}'),
        ([1, 2], "[1, 2]"),
        (None, ""),
        (42, "42"),
    ],
)
def test_cell_formats_supported_values(value: object, expected: str) -> None:
    assert render._cell(value) == expected

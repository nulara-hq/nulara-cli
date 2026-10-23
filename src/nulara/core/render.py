import json
from typing import Any

from rich.console import Console
from rich.table import Table

console = Console()


def render_json(payload: Any) -> None:
    console.print_json(json.dumps(payload, default=str))


def render_rows(payload: Any) -> None:
    rows = payload.get("items") if isinstance(payload, dict) else payload
    if not isinstance(rows, list) or not rows:
        render_json(payload)
        return
    if not all(isinstance(row, dict) for row in rows):
        render_json(payload)
        return

    columns: list[str] = []
    for row in rows[:20]:
        for key in row:
            if key not in columns:
                columns.append(key)
            if len(columns) == 8:
                break
        if len(columns) == 8:
            break

    table = Table(show_lines=False)
    for column in columns:
        table.add_column(column)
    for row in rows:
        table.add_row(*[_cell(row.get(column)) for column in columns])
    console.print(table)


def _cell(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return "" if value is None else str(value)

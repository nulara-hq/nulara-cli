"""`--all` follows `has_more` for the lists whose pages can be merged."""

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cyclopts.exceptions import UnknownOptionError
from support import NULARA

from nulara.core import direct as direct_module
from nulara.core.client import ApiResult
from nulara.core.config import Surface
from nulara.core.errors import CliError, UsageError
from nulara.core.main import build_app
from nulara.core.openapi import build_command_manifest

SECURITY = [{"NularaPersonalAccessToken": []}]
PAGE_PARAMETERS = [
    {
        "name": "limit",
        "in": "query",
        "schema": {"type": "integer", "minimum": 1, "maximum": 3, "default": 2},
    },
    {"name": "offset", "in": "query", "schema": {"type": "integer", "minimum": 0}},
    {"name": "search", "in": "query", "schema": {"type": "string"}},
]


def page_schema(**properties: Any) -> dict[str, Any]:
    return {"type": "object", "properties": properties}


ARRAY = {"type": "array", "items": {"type": "object"}}
FLAG = {"type": "boolean"}
COUNT = {"type": "integer"}


def list_operation(
    operation_id: str, schema: dict[str, Any], parameters: list | None = None
) -> dict[str, Any]:
    return {
        "get": {
            "operationId": operation_id,
            "tags": ["app-records"],
            "security": SECURITY,
            "parameters": PAGE_PARAMETERS if parameters is None else parameters,
            "responses": {"200": {"content": {"application/json": {"schema": schema}}}},
        }
    }


def document() -> dict[str, Any]:
    return {
        "openapi": "3.1.0",
        "components": {
            "securitySchemes": {
                "NularaPersonalAccessToken": {"type": "http", "scheme": "bearer"}
            },
            "schemas": {
                "RecordPage": page_schema(
                    items={"$ref": "#/components/schemas/RecordList"},
                    total=COUNT,
                    has_more=FLAG,
                ),
                "RecordList": ARRAY,
            },
        },
        "paths": {
            "/records": list_operation(
                "list_records", {"$ref": "#/components/schemas/RecordPage"}
            ),
            "/records/entries": list_operation(
                "list_record_entries",
                page_schema(entries=ARRAY, has_more=FLAG, total=COUNT),
            ),
            "/records/with-default": list_operation(
                "list_records_with_default",
                page_schema(items=ARRAY, has_more=FLAG, default_id=COUNT),
            ),
            "/records/folders": list_operation(
                "list_record_folders",
                page_schema(files=ARRAY, folders=ARRAY, has_more=FLAG),
            ),
            "/records/plain": list_operation("list_plain_records", ARRAY),
            "/records/unpaged": list_operation(
                "list_unpaged_records",
                page_schema(items=ARRAY, has_more=FLAG),
                parameters=[],
            ),
        },
    }


def pagination(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        operation["operation_id"]: operation["pagination"]
        for module in manifest["modules"]
        for operation in module["operations"]
    }


def test_the_manifest_marks_only_lists_whose_pages_merge() -> None:
    manifest = build_command_manifest(document(), product="nulara")
    assert pagination(manifest) == {
        "list_records": {"items": "items"},
        "list_record_entries": {"items": "entries"},
        "list_records_with_default": None,
        "list_record_folders": None,
        "list_plain_records": None,
        "list_unpaged_records": None,
    }


class PagedClient:
    calls: list[list[tuple[str, Any]]] = []
    records = [{"id": index} for index in range(7)]
    broken = False

    def __init__(self, *_args: Any) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def request_result(self, method: str, path: str, **kwargs: Any) -> ApiResult:
        params = kwargs["params"]
        type(self).calls.append(params)
        values = dict(params)
        offset, limit = int(values["offset"]), int(values["limit"])
        page = self.records[offset : offset + limit]
        body: Any = {
            "items": page,
            "total": len(self.records),
            "has_more": offset + limit < len(self.records),
        }
        if type(self).broken:
            body = {"items": page}
        return ApiResult(200, "application/json", json.dumps(body).encode(), {})


@pytest.fixture
def app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    manifest_path = tmp_path / "spec.json"
    manifest_path.write_text(
        json.dumps(build_command_manifest(document(), product="nulara"))
    )
    PagedClient.calls = []
    PagedClient.broken = False
    rendered: list[Any] = []
    monkeypatch.setattr(direct_module, "ApiClient", PagedClient)
    monkeypatch.setattr(direct_module, "get_token", lambda _config: ("token", "env"))
    monkeypatch.setattr(direct_module, "render_json", rendered.append)
    monkeypatch.setattr(direct_module, "render_rows", rendered.append)
    product = replace(NULARA, manifest=manifest_path)
    built = build_app(product, Surface.CUSTOMER)

    def invoke(*tokens: str) -> list[Any]:
        try:
            built(tokens, exit_on_error=False)
        except SystemExit as exc:
            assert exc.code == 0
        return rendered

    return invoke


def test_all_collects_every_page_at_the_largest_page_size(app) -> None:
    rendered = app("records", "list", "--all", "--search", "bottle", "--json")
    assert rendered[-1] == {"items": PagedClient.records, "total": 7}
    assert PagedClient.calls == [
        [("search", "bottle"), ("limit", 3), ("offset", "0")],
        [("search", "bottle"), ("limit", 3), ("offset", "3")],
        [("search", "bottle"), ("limit", 3), ("offset", "6")],
    ]


def test_all_starts_at_the_given_offset_and_stops_at_max_items(app) -> None:
    rendered = app(
        "records", "list", "--all", "--limit", "2", "--offset", "1", "--max-items", "3"
    )
    assert rendered[-1] == {"items": PagedClient.records[1:4], "total": 7}
    assert [dict(call)["offset"] for call in PagedClient.calls] == ["1", "3"]


def test_all_refuses_a_page_without_has_more(app) -> None:
    PagedClient.broken = True
    with pytest.raises(CliError, match="did not answer with a page"):
        app("records", "list", "--all")


@pytest.mark.parametrize(
    "tokens,message",
    [
        (("--max-items", "2"), "only applies together with --all"),
        (("--all", "--max-items", "0"), "at least 1"),
        (("--all", "--output", "records.json"), "cannot be combined with --output"),
    ],
)
def test_all_rejects_contradicting_options(app, tokens, message) -> None:
    with pytest.raises(UsageError, match=message):
        app("records", "list", *tokens)
    assert PagedClient.calls == []


def test_only_paginated_lists_offer_all(app) -> None:
    with pytest.raises(UnknownOptionError):
        app("records", "list-with-default", "--all")

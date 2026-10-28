"""`describe` explains a command from the packaged manifest, offline."""

from typing import Any

import pytest
from support import NULARA

from nulara.core import describe as describe_module
from nulara.core.config import Surface
from nulara.core.describe import describe_operation
from nulara.core.errors import UsageError
from nulara.core.main import build_app


@pytest.fixture
def describe(monkeypatch: pytest.MonkeyPatch):
    rendered: list[Any] = []
    monkeypatch.setattr(describe_module, "render_json", rendered.append)
    monkeypatch.delenv("NULARA_API_TOKEN", raising=False)
    app = build_app(NULARA, Surface.CUSTOMER)

    def invoke(*tokens: str) -> Any:
        try:
            app(["describe", *tokens], exit_on_error=False)
        except SystemExit as exc:
            assert exc.code == 0
        return rendered[-1]

    return invoke


def test_describe_lists_modules_and_their_commands(describe) -> None:
    modules = {entry["name"]: entry for entry in describe()["modules"]}
    assert "create" in modules["products"]["commands"]
    commands = {
        entry["name"]: entry
        for entry in describe("passport-publications", "--json")["commands"]
    }
    assert commands["publish-passport"] == {
        "name": "publish-passport",
        "summary": "Publish Passport",
        "method": "POST",
        "dangerous": True,
    }


def test_describe_explains_one_command_with_an_example(describe) -> None:
    described = describe("products", "create")
    assert described["command"] == "nulara products create"
    assert described["method"] == "POST"
    assert described["dangerous"] is True
    assert described["body"]["required_fields"] == ["name", "inventory_mode"]
    assert described["body"]["accepts_input_file"] is True
    assert described["body"]["schema"]["properties"]["name"]["maxLength"] == 255
    name = next(
        option for option in described["options"] if option["option"] == "--name"
    )
    assert name == {
        "option": "--name",
        "in": "body",
        "required": True,
        "description": None,
        "schema": {
            "format": None,
            "kind": "string",
            "maxLength": 255,
            "minLength": 1,
            "nullable": False,
        },
    }
    assert described["example"] == (
        "nulara products create --name <name> --inventory-mode serialized --yes --json"
    )


def test_describe_rejects_an_unknown_name_with_suggestions(describe) -> None:
    with pytest.raises(UsageError, match="did you mean products"):
        describe("product")
    with pytest.raises(UsageError, match="Unknown products command `crate`"):
        describe("products", "crate")


def operation(**overrides: Any) -> dict[str, Any]:
    return {
        "name": "download",
        "operation_id": "download_record",
        "summary": "Download Record",
        "description": None,
        "method": "GET",
        "path": "/records/{record_id}/file",
        "dangerous": False,
        "parameters": [
            {
                "argument": "record_id",
                "name": "record_id",
                "option": "record-id",
                "location": "path",
                "required": True,
                "schema": {"kind": "string"},
            },
            {
                "argument": "inline",
                "name": "inline",
                "option": "inline",
                "location": "query",
                "required": True,
                "schema": {"kind": "boolean"},
            },
        ],
        "body": None,
        "response_content_types": ["image/png"],
        "pagination": None,
        **overrides,
    }


def test_the_example_covers_paths_flags_files_and_sensitive_bodies() -> None:
    described = describe_operation(NULARA, "records", operation())
    assert described["arguments"][0]["name"] == "record_id"
    assert described["options"][0]["in"] == "query"
    assert described["body"] is None
    assert described["example"] == (
        "nulara records download <record-id> --inline --output <file> --json"
    )

    secret_body = {
        "content_type": "application/json",
        "required": True,
        "structured": True,
        "properties": [
            {
                "argument": "token",
                "name": "token",
                "option": "token",
                "required": True,
                "sensitive": True,
                "schema": {"kind": "string"},
            }
        ],
        "schema": {},
    }
    described = describe_operation(
        NULARA,
        "records",
        operation(
            method="POST",
            dangerous=True,
            parameters=[],
            body=secret_body,
            response_content_types=["application/json"],
        ),
    )
    assert described["options"] == []
    assert described["body"]["sensitive_fields"] == ["token"]
    assert (
        described["example"] == "nulara records download --input body.json --yes --json"
    )

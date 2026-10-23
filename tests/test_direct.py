import io
import json
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from rich.console import Console
from support import NULARA

from nulara.core import direct as direct_module
from nulara.core import main as main_module
from nulara.core.client import ApiResult
from nulara.core.config import Product, ProductConfig, Surface
from nulara.core.direct import (
    _check_bound,
    _command_signature,
    _confirm_if_dangerous,
    _decimal_union_schema,
    _decoded_route_path,
    _field_help,
    _json_value,
    _multipart_payload,
    _operation_path_matches,
    _parse_assignments,
    _python_type,
    _read_input,
    _redact_json_body,
    _run_operation,
    _schema_properties,
    _sensitive_body_strings,
    _validate_json_schema,
    _validate_number,
    _validate_value,
    _wire_scalar,
    load_manifest,
    render_api_result,
    run_raw_api,
    validate_relative_endpoint,
)
from nulara.core.errors import CliError, ConfigurationError
from nulara.core.main import build_app


class FakeApiClient:
    calls: list[tuple[str, str, dict[str, Any]]] = []
    result = ApiResult(
        status_code=200,
        content_type="application/json",
        content=b'{"id":"location-1"}',
        headers={},
    )

    def __init__(self, config: ProductConfig, token: str):
        self.config = config
        self.token = token

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def request_result(self, method: str, path: str, **kwargs: Any) -> ApiResult:
        content = kwargs.get("content")
        if content is not None and not isinstance(content, bytes):
            kwargs["content"] = b"".join(content)
        type(self).calls.append((method, path, kwargs))
        return type(self).result

    def request_to_file(
        self,
        method: str,
        path: str,
        output: Path,
        **kwargs: Any,
    ) -> SimpleNamespace:
        type(self).calls.append((method, path, kwargs))
        output.write_bytes(type(self).result.content)
        return SimpleNamespace(
            bytes_written=len(type(self).result.content), output=output
        )


@pytest.fixture(autouse=True)
def direct_mocks(monkeypatch):
    rendered_json: list[Any] = []
    rendered_rows: list[Any] = []
    printed: list[str] = []
    FakeApiClient.calls = []
    FakeApiClient.result = ApiResult(
        status_code=200,
        content_type="application/json",
        content=b'{"id":"location-1"}',
        headers={},
    )
    monkeypatch.setattr(direct_module, "ApiClient", FakeApiClient)
    monkeypatch.setattr(direct_module, "get_token", lambda _config: ("token", "test"))
    monkeypatch.setattr(direct_module, "render_json", rendered_json.append)
    monkeypatch.setattr(direct_module, "render_rows", rendered_rows.append)
    monkeypatch.setattr(
        direct_module.console,
        "print",
        lambda value="", **_kwargs: printed.append(str(value)),
    )
    return SimpleNamespace(
        rendered_json=rendered_json,
        rendered_rows=rendered_rows,
        printed=printed,
    )


def invoke(*tokens: str, product: Product = NULARA) -> object:
    try:
        return build_app(product, Surface.CUSTOMER)(tokens, exit_on_error=False)
    except SystemExit as exc:
        if exc.code != 0:
            raise
        return None


def test_the_generated_manifest_registers_every_product_module() -> None:
    for manifest in (load_manifest(NULARA),):
        assert manifest["module_count"] == len(manifest["modules"])
        assert manifest["operation_count"] == sum(
            len(module["operations"]) for module in manifest["modules"]
        )
        assert manifest["module_count"] > 1
        # All five streaming routes belong to the dedicated thread protocol,
        # never to the generated one-response commands.
        excluded_streams = manifest["excluded_event_stream_operations"]
        assert manifest["excluded_event_stream_operation_count"] == len(
            excluded_streams
        )
        assert {
            (operation["operation_id"], operation["method"], operation["path"])
            for operation in excluded_streams
        } == {
            ("chat_with_agent", "POST", "/threads/chat"),
            ("attach_thread_run", "GET", "/threads/{thread_id}/attach"),
            ("resume_agent_execution", "POST", "/threads/{thread_id}/resume"),
            ("start_thread_run", "POST", "/threads/{thread_id}/runs"),
            ("retry_thread_run", "POST", "/threads/{thread_id}/runs/retry"),
        }
        assert len(excluded_streams) == 5
        operations = [
            operation
            for module in manifest["modules"]
            for operation in module["operations"]
        ]
        assert not {operation["operation_id"] for operation in excluded_streams} & {
            operation["operation_id"] for operation in operations
        }
        assert all(
            operation["dangerous"] == (operation["method"] not in {"GET", "HEAD"})
            for operation in operations
        )
        fields = [
            field
            for operation in operations
            for field in (operation.get("body") or {}).get("properties", [])
        ]
        upload_fields = [
            field
            for field in fields
            if field["schema"].get("kind") == "file"
            or field["schema"].get("items", {}).get("kind") == "file"
        ]
        assert upload_fields
        assert all("x-maxSizeBytes" in field["schema"] for field in upload_fields)
        sensitive_names = {
            "credentials",
            "developer_token",
            "proof",
            "recovery_sealed_private_key",
            "sealed_private_key",
            "token",
        }
        assert all(
            field["sensitive"] for field in fields if field["name"] in sensitive_names
        )

    output = Console(record=True, width=140)
    build_app(NULARA, Surface.CUSTOMER).help_print(
        ["locations", "create"], console=output
    )
    help_text = output.export_text()
    assert "--name" in help_text
    assert "--type" in help_text
    assert "warehouse" in help_text


def test_due_diligence_manifest_exposes_the_strict_model_contract() -> None:
    manifest = load_manifest(NULARA)
    modules = {module["name"]: module for module in manifest["modules"]}
    declaration_operations = {
        operation["name"]: operation
        for operation in modules["due-diligence-declarations"]["operations"]
    }
    create_body = declaration_operations["create"]["body"]
    assert create_body["schema"]["required"] == [
        "scope",
        "statement_text",
        "regulation_reference",
        "issuer_party_id",
        "effective_from",
    ]
    assert "issuer_name" not in create_body["schema"]["properties"]
    assert "evidence_document_id" not in create_body["schema"]["properties"]

    document_operations = {
        operation["name"]: operation
        for operation in modules["due-diligence-documents"]["operations"]
    }
    upload_fields = {
        field["name"]: field
        for field in document_operations["upload"]["body"]["properties"]
    }
    document_type = upload_fields["document_type"]
    assert document_type["required"] is True
    assert document_type["schema"]["values"] == [
        "Policy",
        "RiskAssessment",
        "SupplierDeclaration",
        "AuditReport",
        "VerificationReport",
        "ApprovalDecision",
        "ChainOfCustody",
        "RemediationPlan",
        "PublicReport",
        "Other",
    ]


def test_schema_manifest_exposes_and_sends_the_strict_contract(
    direct_mocks,
) -> None:
    manifest = load_manifest(NULARA)
    modules = {module["name"]: module for module in manifest["modules"]}
    operations = {
        operation["name"]: operation for operation in modules["schemas"]["operations"]
    }

    create = operations["create"]
    assert create["body"]["schema"]["required"] == ["name", "definition"]
    update_fields = {
        field["name"]: field for field in operations["update"]["body"]["properties"]
    }
    assert update_fields["name"]["schema"]["nullable"] is False
    assert update_fields["definition"]["schema"]["nullable"] is False
    assert update_fields["passport_profile"]["schema"]["nullable"] is False
    assert (
        operations["bulk-delete"]["body"]["schema"]["properties"]["ids"]["maxItems"]
        == 100
    )

    definition = {
        "type": "object",
        "properties": {"quality": {"type": "string"}},
        "additionalProperties": False,
    }
    invoke(
        "schemas",
        "create",
        "--name",
        "Quality",
        "--definition",
        json.dumps(definition),
        "--passport-profile",
        "NONE",
        "--yes",
    )
    method, path, kwargs = FakeApiClient.calls[-1]
    assert (method, path) == ("POST", "/schemas")
    assert kwargs["json"] == {
        "name": "Quality",
        "definition": definition,
        "passport_profile": "NONE",
    }


def test_absence_manifest_exposes_timezone_update_and_id_filter() -> None:
    manifest = load_manifest(NULARA)
    modules = {module["name"]: module for module in manifest["modules"]}
    operations = {
        operation["name"]: operation for operation in modules["absences"]["operations"]
    }

    assert operations["create"]["body"]["schema"]["required"] == [
        "type",
        "start_at",
        "end_at",
        "timezone",
    ]
    update_fields = {
        field["name"]: field for field in operations["update"]["body"]["properties"]
    }
    assert update_fields["timezone"]["schema"]["nullable"] is False
    list_parameters = {
        parameter["name"]: parameter for parameter in operations["list"]["parameters"]
    }
    assert list_parameters["absence_ids"]["schema"]["maxItems"] == 100


def test_calendar_manifest_exposes_and_sends_the_time_contract(
    direct_mocks,
) -> None:
    manifest = load_manifest(NULARA)
    modules = {module["name"]: module for module in manifest["modules"]}
    operations = {
        operation["name"]: operation
        for operation in modules["calendar-events"]["operations"]
    }

    create = operations["create"]
    assert create["body"]["schema"]["required"] == [
        "title",
        "start_at",
        "end_at",
    ]
    create_fields = {field["name"]: field for field in create["body"]["properties"]}
    assert create_fields["timezone"]["schema"] == {
        "format": None,
        "kind": "string",
        "maxLength": 64,
        "minLength": 1,
        "nullable": True,
    }
    assert (
        operations["bulk-delete"]["body"]["schema"]["properties"]["ids"]["maxItems"]
        == 100
    )
    update_fields = {
        field["name"]: field for field in operations["update"]["body"]["properties"]
    }
    assert update_fields["title"]["required"] is False
    assert update_fields["title"]["schema"]["nullable"] is False
    assert update_fields["start_at"]["required"] is False
    assert update_fields["timezone"]["schema"]["nullable"] is True

    invoke(
        "calendar-events",
        "create",
        "--title",
        "Supplier audit",
        "--start-at",
        "2026-08-10T09:00:00+00:00",
        "--end-at",
        "2026-08-10T11:00:00+00:00",
        "--timezone",
        "Europe/Berlin",
        "--color",
        "teal",
        "--yes",
    )
    method, path, kwargs = FakeApiClient.calls[-1]
    assert (method, path) == ("POST", "/calendar-events")
    assert kwargs["json"] == {
        "title": "Supplier audit",
        "start_at": "2026-08-10T09:00:00+00:00",
        "end_at": "2026-08-10T11:00:00+00:00",
        "timezone": "Europe/Berlin",
        "color": "teal",
    }

    event_id = "00000000-0000-4000-8000-000000000001"
    invoke(
        "calendar-events",
        "update",
        "--calendar-event-id",
        event_id,
        "--title",
        "Supplier audit renamed",
        "--yes",
    )
    method, path, kwargs = FakeApiClient.calls[-1]
    assert (method, path) == ("PATCH", f"/calendar-events/{event_id}")
    assert kwargs["json"] == {"title": "Supplier audit renamed"}


def test_typed_create_sends_the_openapi_request(direct_mocks) -> None:
    invoke(
        "locations",
        "create",
        "--name",
        "Lager",
        "--type",
        "warehouse",
        "--timezone",
        "Europe/Berlin",
        "--yes",
        "--json",
    )

    method, path, kwargs = FakeApiClient.calls[-1]
    assert (method, path) == ("POST", "/locations")
    assert kwargs["json"] == {
        "name": "Lager",
        "location_type": "warehouse",
        "timezone": "Europe/Berlin",
    }
    assert direct_mocks.rendered_json[-1] == {"id": "location-1"}


def test_typed_commands_support_input_query_path_and_dry_run(
    direct_mocks, tmp_path: Path
) -> None:
    body = tmp_path / "location.json"
    body.write_text(
        '{"name":"Input Lager","location_type":"factory","timezone":"Europe/Berlin"}'
    )
    invoke("locations", "create", "--input", str(body), "--dry-run")
    assert direct_mocks.rendered_json[-1]["body"] == {
        "name": "Input Lager",
        "location_type": "factory",
        "timezone": "Europe/Berlin",
    }

    invoke(
        "absences",
        "list",
        "--user-ids",
        "user-1",
        "--user-ids",
        "user-2",
        "--types",
        "vacation",
    )
    _method, _path, kwargs = FakeApiClient.calls[-1]
    assert ("user_ids", "user-1") in kwargs["params"]
    assert ("user_ids", "user-2") in kwargs["params"]
    assert ("types", "vacation") in kwargs["params"]

    invoke(
        "locations",
        "update",
        "id with / slash",
        "--name",
        "Updated",
        "--type",
        "factory",
        "--timezone",
        "Europe/Berlin",
        "--dry-run",
    )
    assert direct_mocks.rendered_json[-1]["path"].endswith("id%20with%20%2F%20slash")


def test_typed_command_validates_required_body_and_input_conflicts(
    tmp_path: Path,
) -> None:
    with pytest.raises(CliError, match="Missing required body options"):
        invoke("locations", "create", "--dry-run")

    body = tmp_path / "body.json"
    body.write_text('{"name":"From input"}')
    with pytest.raises(CliError, match="cannot be combined"):
        invoke(
            "locations",
            "create",
            "--name",
            "Flag",
            "--input",
            str(body),
            "--dry-run",
        )

    body.write_text("not-json")
    with pytest.raises(CliError, match="not valid JSON"):
        invoke("locations", "create", "--input", str(body), "--dry-run")


def test_delete_requires_confirmation_in_automation(monkeypatch) -> None:
    monkeypatch.setattr(direct_module.sys.stdin, "isatty", lambda: False)
    with pytest.raises(CliError, match="pass --yes"):
        invoke("locations", "delete", "location-1")

    invoke("locations", "delete", "location-1", "--yes")
    assert FakeApiClient.calls[-1][:2] == ("DELETE", "/locations/location-1")


def test_multipart_uploads_single_and_repeated_files(tmp_path: Path) -> None:
    first = tmp_path / "one.txt"
    second = tmp_path / "two.txt"
    first.write_text("one")
    second.write_text("two")

    invoke(
        "files",
        "upload",
        "--thread-id",
        "00000000-0000-0000-0000-000000000001",
        "--file",
        str(first),
        "--yes",
    )
    files = FakeApiClient.calls[-1][2]["files"]
    assert files[0][0] == "file"
    assert files[0][1][0] == "one.txt"

    invoke(
        "products",
        "create-with-source-documents",
        "--name",
        "Product",
        "--inventory-mode",
        "serialized",
        "--files",
        str(first),
        "--files",
        str(second),
        "--yes",
    )
    files = FakeApiClient.calls[-1][2]["files"]
    assert [item[1][0] for item in files] == ["one.txt", "two.txt"]


def test_raw_api_dry_run_parses_fields_params_and_relative_path(direct_mocks) -> None:
    run_raw_api(
        endpoint="locations?existing=yes",
        method="post",
        fields=["count=2", "active=true"],
        raw_fields=["label=002"],
        params=["limit=10", "query=plain"],
        input_file=None,
        content_type="application/json",
        output=None,
        overwrite=False,
        yes=False,
        dry_run=True,
        json_output=False,
        connection=main_module.DEFAULT_CONNECTION_OPTIONS,
        product=NULARA,
        surface=Surface.CUSTOMER,
    )
    assert direct_mocks.rendered_json[-1] == {
        "method": "POST",
        "path": "/locations?existing=yes",
        "params": [("limit", 10), ("query", "plain")],
        "content_type": "application/json",
        "body": "<redacted>",
    }


def test_raw_api_sends_json_and_binary_input(tmp_path: Path) -> None:
    json_file = tmp_path / "body.json"
    json_file.write_text('{"name":"Lager"}')
    options = {
        "endpoint": "/locations",
        "method": "POST",
        "fields": [],
        "raw_fields": [],
        "params": [],
        "output": None,
        "overwrite": False,
        "yes": True,
        "dry_run": False,
        "json_output": True,
        "connection": main_module.DEFAULT_CONNECTION_OPTIONS,
        "product": NULARA,
        "surface": Surface.CUSTOMER,
    }
    run_raw_api(input_file=str(json_file), content_type="application/json", **options)
    assert FakeApiClient.calls[-1][2]["json"] == {"name": "Lager"}

    binary = tmp_path / "payload.bin"
    binary.write_bytes(b"payload")
    FakeApiClient.result = ApiResult(204, "", b"", {})
    run_raw_api(
        input_file=str(binary), content_type="application/octet-stream", **options
    )
    kwargs = FakeApiClient.calls[-1][2]
    assert kwargs["content"] == b"payload"
    assert kwargs["headers"] == {"Content-Type": "application/octet-stream"}


def test_raw_and_typed_api_stream_outputs_to_files(
    direct_mocks, tmp_path: Path
) -> None:
    raw_output = tmp_path / "raw.json"
    run_raw_api(
        endpoint="/locations",
        method="GET",
        fields=[],
        raw_fields=[],
        params=[],
        input_file=None,
        content_type="application/json",
        output=raw_output,
        overwrite=False,
        yes=False,
        dry_run=False,
        json_output=False,
        connection=main_module.DEFAULT_CONNECTION_OPTIONS,
        product=NULARA,
        surface=Surface.CUSTOMER,
    )
    assert raw_output.read_bytes() == b'{"id":"location-1"}'

    typed_output = tmp_path / "typed.json"
    invoke("locations", "list", "--output", str(typed_output))
    assert typed_output.read_bytes() == b'{"id":"location-1"}'
    assert len(direct_mocks.printed) == 2


def test_raw_api_rejects_unsafe_or_invalid_input(tmp_path: Path) -> None:
    base = {
        "endpoint": "/locations",
        "method": "POST",
        "fields": [],
        "raw_fields": [],
        "params": [],
        "input_file": None,
        "content_type": "application/json",
        "output": None,
        "overwrite": False,
        "yes": True,
        "dry_run": True,
        "json_output": False,
        "connection": main_module.DEFAULT_CONNECTION_OPTIONS,
        "product": NULARA,
        "surface": Surface.CUSTOMER,
    }
    with pytest.raises(CliError, match="Unsupported HTTP method"):
        run_raw_api(**{**base, "method": "TRACE"})
    for endpoint in (
        "/threads/chat",
        "/threads/%63hat",
        "/threads/%2563hat",
        "/threads/thread-1/resume",
        "/threads/thread-1/runs",
    ):
        with pytest.raises(CliError, match="agent run"):
            run_raw_api(
                **{
                    **base,
                    "endpoint": endpoint,
                    "method": "POST",
                }
            )
    with pytest.raises(CliError, match="expected key=value"):
        run_raw_api(**{**base, "fields": ["broken"]})

    source = tmp_path / "body.json"
    source.write_text("invalid")
    with pytest.raises(CliError, match="not valid JSON"):
        run_raw_api(**{**base, "input_file": str(source)})
    source.write_text("{}")
    with pytest.raises(CliError, match="cannot be combined"):
        run_raw_api(**{**base, "input_file": str(source), "fields": ["a=1"]})


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://evil.test/steal",
        "//evil.test/steal",
        "/a#fragment",
        "/a/../b",
        "/a/%2e%2e/b",
        r"/a\..\b",
        "/",
    ],
)
def test_raw_api_rejects_endpoints_that_can_escape_the_api(endpoint: str) -> None:
    with pytest.raises(CliError):
        validate_relative_endpoint(endpoint)


def test_render_api_result_handles_json_text_empty_binary_and_files(
    direct_mocks, tmp_path: Path
) -> None:
    render_api_result(
        ApiResult(200, "application/json", b'{"ok":true}', {}),
        json_output=False,
        output=None,
        overwrite=False,
    )
    assert direct_mocks.rendered_rows[-1] == {"ok": True}

    render_api_result(
        ApiResult(200, "text/plain", b"hello", {}),
        json_output=True,
        output=None,
        overwrite=False,
    )
    assert direct_mocks.rendered_json[-1] == "hello"

    render_api_result(
        ApiResult(204, "", b"", {}),
        json_output=False,
        output=None,
        overwrite=False,
    )
    assert "HTTP 204" in direct_mocks.printed[-1]

    binary = ApiResult(
        200,
        "application/pdf",
        b"pdf",
        {"content-disposition": 'attachment; filename="report.pdf"'},
    )
    with pytest.raises(CliError, match="--output report.pdf"):
        render_api_result(binary, json_output=False, output=None, overwrite=False)

    output = tmp_path / "result.pdf"
    with pytest.raises(CliError, match="Buffered output is disabled"):
        render_api_result(binary, json_output=False, output=output, overwrite=False)


def test_manifest_loader_rejects_broken_packaged_contracts(
    monkeypatch, tmp_path: Path
) -> None:
    target = tmp_path / "spec.json"
    product = replace(NULARA, manifest=target)

    cases = [
        ("not-json", "Could not load"),
        ("[]", "root must be an object"),
        ('{"manifest_version":999}', "Unsupported CLI contract"),
        (
            '{"manifest_version":2,"product":"other","modules":[]}',
            "for other loaded as nulara",
        ),
        (
            '{"manifest_version":2,"product":"nulara","modules":{}}',
            "no modules list",
        ),
    ]
    for content, message in cases:
        target.write_text(content)
        with pytest.raises(ConfigurationError, match=message):
            load_manifest(product)


def test_input_validation_and_low_level_helpers(monkeypatch, tmp_path: Path) -> None:
    field = {
        "option": "value",
        "schema": {
            "kind": "string",
            "minLength": 2,
            "maxLength": 4,
            "pattern": "[a-z]+",
        },
    }
    _validate_value(field, "abc")
    for value in ("a", "abcde", "12"):
        with pytest.raises(CliError):
            _validate_value(field, value)

    number = {
        "option": "number",
        "schema": {"kind": "integer", "minimum": 1, "maximum": 3},
    }
    for value in (0, 4):
        with pytest.raises(CliError):
            _validate_value(number, value)
    _validate_value(number, True)
    assert _wire_scalar(True) == "true"
    assert _wire_scalar(False) == "false"

    array = {
        "option": "items",
        "schema": {"kind": "array", "minItems": 2, "maxItems": 3},
    }
    for value in (["one"], ["one", "two", "three", "four"]):
        with pytest.raises(CliError):
            _validate_value(array, value)
    _check_bound(array, 2, "missing", "at least")

    unique = {
        "option": "ids",
        "schema": {"kind": "array", "uniqueItems": True},
    }
    with pytest.raises(CliError, match="unique"):
        _validate_value(unique, ["same", "same"])

    exclusive = {
        "option": "quantity",
        "schema": {
            "kind": "decimal",
            "exclusiveMinimum": 0,
            "multipleOf": 0.001,
        },
    }
    with pytest.raises(CliError, match="greater than"):
        _validate_value(exclusive, "0")
    with pytest.raises(CliError, match="multiple"):
        _validate_value(exclusive, "1.0005")
    _validate_value(exclusive, "1.001")

    object_field = {
        "option": "preferences",
        "schema": {"kind": "json", "minProperties": 1, "maxProperties": 2},
    }
    for value in ({}, {"a": 1, "b": 2, "c": 3}):
        with pytest.raises(CliError):
            _validate_value(object_field, value)

    json_field = {"option": "data", "schema": {"kind": "json"}}
    assert _json_value(json_field, '{"a":1}') == {"a": 1}
    assert _json_value(json_field, {"a": 1}) == {"a": 1}
    with pytest.raises(CliError, match="valid JSON"):
        _json_value(json_field, "invalid")

    assert _parse_assignments(["x=1", "text=value"], typed=True) == [
        ("x", 1),
        ("text", "value"),
    ]
    assert _parse_assignments(["x=1"], typed=False) == [("x", "1")]

    source = tmp_path / "input.txt"
    source.write_bytes(b"content")
    assert _read_input(str(source)) == b"content"
    with pytest.raises(CliError, match="Could not read"):
        _read_input(str(tmp_path / "missing"))
    monkeypatch.setattr(
        direct_module.sys,
        "stdin",
        SimpleNamespace(buffer=io.BytesIO(b"stdin")),
    )
    assert _read_input("-") == b"stdin"

    monkeypatch.setattr(direct_module, "MAX_JSON_INPUT_BYTES", 3)
    source.write_bytes(b"four")
    with pytest.raises(CliError, match="in-memory limit"):
        _read_input(str(source))

    assert _python_type({"kind": "unknown"}) is str
    assert "required" in _field_help(
        {
            "name": "sample_value",
            "required": True,
            "schema": {"kind": "json", "default": {}},
        }
    )


def test_json_schema_validation_handles_required_const_unique_and_decimal() -> None:
    schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["kind", "ids", "quantity"],
        "properties": {
            "kind": {"type": "string", "const": "publish"},
            "ids": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"type": "string"},
            },
            "quantity": {
                "anyOf": [
                    {"type": "number", "exclusiveMinimum": 0},
                    {"type": "string", "pattern": "^-?[0-9]+(?:\\.[0-9]+)?$"},
                ]
            },
        },
    }
    _validate_json_schema(
        {"kind": "publish", "ids": ["one"], "quantity": "1.5"},
        schema,
        label="--input",
    )
    for payload in (
        {},
        {"kind": "wrong", "ids": ["one"], "quantity": "1"},
        {"kind": "publish", "ids": ["one", "one"], "quantity": "1"},
        {"kind": "publish", "ids": ["one"], "quantity": "-1"},
        {"kind": "publish", "ids": ["one"], "quantity": "1", "extra": True},
    ):
        with pytest.raises(CliError):
            _validate_json_schema(payload, schema, label="--input")


def test_schema_helpers_cover_nested_redaction_and_defensive_shapes() -> None:
    assert _operation_path_matches(None, "/threads/chat") is False
    excessively_encoded = "%2e"
    for _ in range(9):
        excessively_encoded = excessively_encoded.replace("%", "%25")
    with pytest.raises(CliError, match="excessive nested encoding"):
        _decoded_route_path(excessively_encoded)

    decimal_field = {"option": "quantity", "schema": {"kind": "decimal"}}
    assert _json_value(decimal_field, "1.20") == "1.20"
    with pytest.raises(CliError, match="must be numeric"):
        _validate_number(decimal_field, "not-a-number")
    for value in ("NaN", "Infinity", "-Infinity"):
        with pytest.raises(CliError, match="finite"):
            _validate_number(decimal_field, value)

    _validate_json_schema("anything", None, label="--input")
    _validate_json_schema(None, {"nullable": True}, label="--input")
    alternatives = {"anyOf": [{"type": "string"}, {"type": "integer"}]}
    _validate_json_schema("valid", alternatives, label="--input")
    with pytest.raises(CliError, match="allowed schema"):
        _validate_json_schema(True, alternatives, label="--input")
    with pytest.raises(CliError, match="must be string"):
        _validate_json_schema(1, {"type": "string"}, label="--input")
    with pytest.raises(CliError, match="must be one of"):
        _validate_json_schema("x", {"enum": ["y"]}, label="--input")
    _validate_json_schema(
        ["one", "two"],
        {"type": "array", "items": {"type": "string"}},
        label="--input",
    )

    redaction_schema = {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {"token": {"x-sensitive": True}},
        },
    }
    assert _redact_json_body([{"token": "secret"}], redaction_schema) == [
        {"token": "<redacted>"}
    ]
    assert _redact_json_body("value", None) == "value"
    assert _redact_json_body("secret", {"writeOnly": True}) == "<redacted>"
    assert _sensitive_body_strings(
        {"credentials": {"token": "secret", "label": "public"}},
        {
            "type": "object",
            "properties": {
                "credentials": {
                    "type": "object",
                    "properties": {
                        "token": {"x-sensitive": True},
                        "label": {"type": "string"},
                    },
                }
            },
        },
    ) == ["secret"]
    assert _schema_properties(
        {
            "properties": {"direct": {}},
            "anyOf": [{"properties": {"nested": {}}}, None],
        }
    ) == {"direct": {}, "nested": {}}

    valid_decimal = [
        {"type": "number", "minimum": 0},
        {"type": "string", "pattern": "^[0-9]+$"},
        {"type": "null"},
    ]
    assert _decimal_union_schema(valid_decimal) == {
        "type": "string",
        "minimum": 0,
        "pattern": "^[0-9]+$",
        "kind": "decimal",
        "nullable": True,
    }
    for variants in (
        [None],
        [{"type": "number"}, {"type": "boolean"}],
        [{"type": "number"}, {"type": "string"}],
    ):
        assert _decimal_union_schema(variants) is None


def test_sensitive_fields_require_input_and_are_not_cli_options() -> None:
    operation = {
        "operation_id": "create_secret",
        "method": "POST",
        "path": "/secrets",
        "parameters": [],
        "body": {
            "required": True,
            "content_type": "application/json",
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
            "schema": {
                "type": "object",
                "required": ["token"],
                "properties": {"token": {"type": "string", "writeOnly": True}},
            },
        },
        "dangerous": True,
        "summary": "Create secret",
        "description": None,
    }
    signature = _command_signature(
        operation,
        connection_type=type(main_module.DEFAULT_CONNECTION_OPTIONS),
        default_connection=main_module.DEFAULT_CONNECTION_OPTIONS,
    )
    assert "body_token" not in signature.parameters
    assert "input_file" in signature.parameters
    with pytest.raises(CliError, match="sensitive.*--input"):
        _run_operation(
            NULARA,
            Surface.CUSTOMER,
            operation,
            {
                "dry_run": True,
                "yes": False,
                "json_output": False,
                "output": None,
                "overwrite": False,
                "connection": main_module.DEFAULT_CONNECTION_OPTIONS,
            },
        )


def test_required_unstructured_body_and_real_unique_input_are_rejected(
    tmp_path: Path,
) -> None:
    with pytest.raises(CliError, match="requires a request body"):
        invoke(
            "battery-observations",
            "ingest",
            "--dry-run",
        )

    source = tmp_path / "transition.json"
    source.write_text(
        '{"publication_ids":["00000000-0000-0000-0000-000000000001",'
        '"00000000-0000-0000-0000-000000000001"],"action":"publish"}'
    )
    with pytest.raises(CliError, match="unique"):
        invoke(
            "passport-publications",
            "bulk-transition",
            "--input",
            str(source),
            "--dry-run",
        )


def test_multipart_and_confirmation_error_paths(monkeypatch, tmp_path: Path) -> None:
    body = {
        "properties": [
            {
                "name": "missing",
                "schema": {"kind": "file"},
            }
        ]
    }
    with ExitStack() as stack, pytest.raises(CliError, match="Could not read"):
        _multipart_payload(body, {"missing": tmp_path / "missing"}, stack)

    form_body = {
        "properties": [
            {
                "name": "tags",
                "schema": {"kind": "array", "items": {"kind": "string"}},
            },
            {"name": "metadata", "schema": {"kind": "json"}},
            {"name": "ignored", "schema": {"kind": "string"}},
        ]
    }
    with ExitStack() as stack:
        data, files = _multipart_payload(
            form_body,
            {"tags": ["one", "two"], "metadata": {"ok": True}},
            stack,
        )
    assert data == {"tags": ["one", "two"], "metadata": '{"ok": true}'}
    assert files == []

    upload = tmp_path / "upload.txt"
    upload.write_bytes(b"too large")
    constrained = {
        "properties": [
            {
                "name": "file",
                "option": "file",
                "schema": {
                    "kind": "file",
                    "x-maxSizeBytes": 2,
                    "x-allowedContentTypes": ["text/plain"],
                },
            }
        ]
    }
    with ExitStack() as stack, pytest.raises(CliError, match="exceeds 2 bytes"):
        _multipart_payload(constrained, {"file": upload}, stack)

    upload.write_bytes(b"ok")
    constrained["properties"][0]["schema"]["x-allowedContentTypes"] = ["image/png"]
    with ExitStack() as stack, pytest.raises(CliError, match="unsupported type"):
        _multipart_payload(constrained, {"file": upload}, stack)

    monkeypatch.setattr(
        direct_module.sys, "stdin", SimpleNamespace(isatty=lambda: True)
    )
    monkeypatch.setattr(direct_module.Confirm, "ask", lambda *_args, **_kwargs: False)
    with pytest.raises(CliError, match="cancelled"):
        _confirm_if_dangerous(dangerous=True, yes=False, description="DELETE /x")
    monkeypatch.setattr(direct_module.Confirm, "ask", lambda *_args, **_kwargs: True)
    _confirm_if_dangerous(dangerous=True, yes=False, description="DELETE /x")
    _confirm_if_dangerous(dangerous=False, yes=False, description="GET /x")
    _confirm_if_dangerous(dangerous=True, yes=True, description="DELETE /x")


def test_run_operation_rejects_unfilled_path() -> None:
    operation = {
        "operation_id": "broken",
        "method": "GET",
        "path": "/records/{record_id}",
        "parameters": [],
        "body": None,
        "dangerous": False,
    }
    with pytest.raises(CliError, match="Not all path parameters"):
        _run_operation(NULARA, Surface.CUSTOMER, operation, {})


def test_run_operation_serializes_required_header(direct_mocks) -> None:
    operation = {
        "operation_id": "header_test",
        "method": "GET",
        "path": "/records",
        "parameters": [
            {
                "argument": "enabled",
                "name": "X-Enabled",
                "option": "enabled",
                "location": "header",
                "required": True,
                "schema": {"kind": "boolean"},
            }
        ],
        "body": None,
        "dangerous": False,
    }
    _run_operation(
        NULARA,
        Surface.CUSTOMER,
        operation,
        {
            "enabled": False,
            "connection": main_module.DEFAULT_CONNECTION_OPTIONS,
            "json_output": False,
            "output": None,
            "overwrite": False,
        },
    )
    assert FakeApiClient.calls[-1][2]["headers"] == {"X-Enabled": "false"}
    assert direct_mocks.rendered_rows[-1] == {"id": "location-1"}

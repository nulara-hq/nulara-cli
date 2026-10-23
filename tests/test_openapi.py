import json
from pathlib import Path

import pytest

from nulara.core.errors import ConfigurationError
from nulara.core.openapi import (
    _command_name,
    _decimal_descriptor,
    _plural,
    _request_body,
    _resolve,
    _response_content_types,
    _schema_descriptor,
    _singular,
    _unwrap_schema,
    _validation_schema,
    build_command_manifest,
    write_command_manifest,
)


def openapi_document() -> dict:
    security = [{"NularaPersonalAccessToken": []}]
    return {
        "openapi": "3.1.0",
        "components": {
            "securitySchemes": {
                "NularaPersonalAccessToken": {
                    "type": "http",
                    "scheme": "bearer",
                }
            },
            "schemas": {
                "LocationCreate": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 200,
                            "pattern": ".+",
                            "default": "Warehouse",
                        },
                        "location_type": {
                            "type": "string",
                            "enum": ["warehouse", "factory"],
                        },
                        "metadata": {"type": "object"},
                        "active": {"type": "boolean"},
                        "capacity": {"type": "integer", "minimum": 0},
                        "ratio": {"type": "number", "maximum": 1},
                        "labels": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 3,
                            "items": {"type": "string"},
                        },
                        "note": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                        "secret": {
                            "$ref": "#/components/schemas/SecretValue",
                            "writeOnly": True,
                        },
                    },
                },
                "SecretValue": {"type": "string"},
                "Upload": {
                    "type": "object",
                    "required": ["file"],
                    "properties": {
                        "file": {
                            "type": "string",
                            "contentMediaType": "application/octet-stream",
                            "x-maxSizeBytes": 1024,
                            "x-allowedContentTypes": ["text/plain"],
                        },
                        "legacy_file": {"type": "string", "format": "binary"},
                        "files": {
                            "anyOf": [
                                {
                                    "type": "array",
                                    "items": {
                                        "type": "string",
                                        "contentMediaType": "application/octet-stream",
                                    },
                                },
                                {"type": "null"},
                            ],
                            "x-maxSizeBytes": 2048,
                            "x-allowedContentTypes": ["text/plain"],
                        },
                    },
                },
            },
        },
        "paths": {
            "/locations/{location_id}": {
                "parameters": [
                    {
                        "name": "location_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "post": {
                    "operationId": "create_location",
                    "summary": "Create location",
                    "description": "Create one location.",
                    "tags": ["app-locations"],
                    "security": security,
                    "parameters": [
                        {
                            "name": "filter",
                            "in": "query",
                            "schema": {"type": "string"},
                        },
                        {
                            "name": "filter",
                            "in": "header",
                            "required": True,
                            "schema": {"type": "boolean"},
                        },
                        {
                            "name": "1-mode",
                            "in": "query",
                            "schema": {"type": "integer"},
                        },
                        {
                            "name": "session",
                            "in": "cookie",
                            "schema": {"type": "string"},
                        },
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/LocationCreate"
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "content": {
                                "application/json": {"schema": {"type": "object"}},
                                "application/problem+json": {
                                    "schema": {"type": "object"}
                                },
                            }
                        },
                        "400": {"content": {"application/json": {}}},
                    },
                },
                "delete": {
                    "operationId": "delete_location",
                    "summary": "Delete location",
                    "tags": ["app-locations"],
                    "security": security,
                    "responses": {"204": {"description": "Deleted"}},
                },
            },
            "/files": {
                "post": {
                    "operationId": "upload_file",
                    "summary": "Upload file",
                    "tags": ["app-files"],
                    "security": security,
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {"$ref": "#/components/schemas/Upload"}
                            }
                        }
                    },
                    "responses": {},
                }
            },
            "/fallback": {
                "get": {
                    "operationId": "get_fallback",
                    "summary": "Fallback",
                    "security": security,
                    "responses": [],
                }
            },
            "/public": {
                "get": {
                    "operationId": "get_public",
                    "security": [],
                    "responses": {},
                }
            },
            "/ignored": {"options": {"operationId": "ignored", "security": security}},
            "/stream": {
                "post": {
                    "operationId": "stream_agent",
                    "tags": ["app-threads"],
                    "security": security,
                    "responses": {"200": {"content": {"text/event-stream": {}}}},
                }
            },
        },
    }


def operation(manifest: dict, module_name: str, command_name: str) -> dict:
    module = next(item for item in manifest["modules"] if item["name"] == module_name)
    return next(item for item in module["operations"] if item["name"] == command_name)


def test_builds_typed_pat_command_manifest() -> None:
    document = openapi_document()
    manifest = build_command_manifest(document, product="nulara")

    assert manifest["product"] == "nulara"
    assert manifest["security_scheme"] == "NularaPersonalAccessToken"
    assert manifest["module_count"] == 3
    assert manifest["operation_count"] == 4
    assert manifest["excluded_event_stream_operation_count"] == 1
    assert manifest["excluded_event_stream_operations"] == [
        {
            "operation_id": "stream_agent",
            "method": "POST",
            "path": "/stream",
        }
    ]
    assert len(manifest["openapi_sha256"]) == 64

    create = operation(manifest, "locations", "create")
    assert create["dangerous"] is True
    assert create["description"] == "Create one location."
    assert create["response_content_types"] == [
        "application/json",
        "application/problem+json",
    ]
    assert [item["argument"] for item in create["parameters"]] == [
        "location_id",
        "filter",
        "header_filter",
        "value_1_mode",
    ]
    body = {item["name"]: item for item in create["body"]["properties"]}
    assert body["location_type"]["option"] == "type"
    assert body["metadata"]["schema"]["kind"] == "json"
    assert body["note"]["schema"]["nullable"] is True
    assert body["labels"]["schema"]["items"]["kind"] == "string"
    assert body["secret"]["sensitive"] is True
    assert create["body"]["schema"]["properties"]["secret"]["writeOnly"] is True

    delete = operation(manifest, "locations", "delete")
    assert delete["dangerous"] is True
    upload = operation(manifest, "files", "upload")
    upload_fields = {item["name"]: item for item in upload["body"]["properties"]}
    assert upload_fields["file"]["schema"]["kind"] == "file"
    assert upload_fields["file"]["schema"]["x-maxSizeBytes"] == 1024
    assert upload_fields["files"]["schema"]["x-maxSizeBytes"] == 2048
    assert upload_fields["files"]["schema"]["x-allowedContentTypes"] == ["text/plain"]
    assert upload_fields["file"]["schema"]["x-allowedContentTypes"] == ["text/plain"]
    assert upload_fields["legacy_file"]["schema"]["kind"] == "file"
    assert upload_fields["files"]["schema"]["items"]["kind"] == "file"
    assert operation(manifest, "fallback", "get")["body"] is None


def test_writes_manifest_and_supports_one_fallback_bearer(tmp_path: Path) -> None:
    document = openapi_document()
    document["components"]["securitySchemes"] = {
        "CustomerToken": {"type": "http", "scheme": "bearer"}
    }
    for path_item in document["paths"].values():
        for candidate in path_item.values():
            if isinstance(candidate, dict) and "security" in candidate:
                candidate["security"] = [{"CustomerToken": []}]
    source = tmp_path / "nested" / "openapi.json"
    source.parent.mkdir()
    source.write_text(json.dumps(document))
    target = tmp_path / "output" / "spec.json"

    write_command_manifest(source, target, product="nulara")

    payload = json.loads(target.read_text())
    assert payload["product"] == "nulara"
    assert payload["security_scheme"] == "CustomerToken"


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda document: document.update(paths=[]), "paths object"),
        (
            lambda document: document["components"].update(schemas=[]),
            "components.schemas",
        ),
        (
            lambda document: document["components"].update(securitySchemes=[]),
            "security schemes",
        ),
        (
            lambda document: document["components"].update(
                securitySchemes={
                    "One": {"type": "http", "scheme": "bearer"},
                    "Two": {"type": "http", "scheme": "bearer"},
                }
            ),
            "Expected one bearer",
        ),
        (
            lambda document: document["paths"]["/fallback"]["get"].pop("operationId"),
            "has no operationId",
        ),
        (
            lambda document: document["paths"].update(
                {
                    "/second": {
                        "get": {
                            "operationId": "get_fallback",
                            "security": [{"NularaPersonalAccessToken": []}],
                            "tags": ["app-fallback"],
                        }
                    },
                    "/third": {
                        "get": {
                            "operationId": "get_fallback",
                            "security": [{"NularaPersonalAccessToken": []}],
                            "tags": ["app-fallback"],
                        }
                    },
                }
            ),
            "Duplicate CLI command",
        ),
        (
            lambda document: document["paths"].update(
                {
                    "{root}": {
                        "get": {
                            "operationId": "root",
                            "security": [{"NularaPersonalAccessToken": []}],
                        }
                    }
                }
            ),
            "Cannot derive CLI module",
        ),
    ],
)
def test_rejects_invalid_openapi_contracts(mutation, message: str) -> None:
    document = openapi_document()
    mutation(document)
    with pytest.raises(ConfigurationError, match=message):
        build_command_manifest(document, product="nulara")


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not json", "Could not read OpenAPI"),
        ("[]", "root must be an object"),
    ],
)
def test_write_rejects_invalid_documents(
    tmp_path: Path, content: str, message: str
) -> None:
    source = tmp_path / "openapi.json"
    source.write_text(content)
    with pytest.raises(ConfigurationError, match=message):
        write_command_manifest(source, tmp_path / "output.json", product="nulara")


def test_openapi_helpers_cover_unstructured_and_defensive_shapes() -> None:
    schemas = {"Text": {"type": "string"}, "Broken": []}
    assert _request_body(None, schemas, "files") is None
    assert _request_body({"content": {}}, schemas, "files") is None
    assert _request_body(
        {"content": {"application/xml": {"schema": []}}}, schemas, "files"
    ) == {
        "required": False,
        "content_type": "application/xml",
        "properties": [],
        "structured": False,
        "schema": {},
    }
    body = _request_body(
        {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            1: {"type": "string"},
                            "missing": None,
                        },
                    }
                }
            }
        },
        schemas,
        "files",
    )
    assert body is not None
    assert [field["name"] for field in body["properties"]] == ["missing"]

    assert _schema_descriptor([], schemas) == {"kind": "json", "nullable": False}
    decimal = {
        "anyOf": [
            {"type": "number", "minimum": 0},
            {"type": "string", "pattern": "^[0-9]+$"},
            {"type": "null"},
        ]
    }
    assert _schema_descriptor(decimal, schemas) == {
        "kind": "decimal",
        "nullable": True,
        "minimum": 0,
        "pattern": "^[0-9]+$",
    }
    assert _decimal_descriptor({"anyOf": [None]}, schemas) is None
    assert (
        _decimal_descriptor(
            {"anyOf": [{"type": "number"}, {"type": "string"}]}, schemas
        )
        is None
    )
    assert _unwrap_schema(
        {"oneOf": [{"type": "string"}, {"type": "integer"}]}, schemas
    )[0]["oneOf"]
    assert _resolve({"$ref": "#/external/Thing"}, schemas) == {
        "$ref": "#/external/Thing"
    }
    assert _resolve({"$ref": "#/components/schemas/Broken"}, schemas) == {
        "$ref": "#/components/schemas/Broken"
    }
    assert _validation_schema({"$ref": "#/components/schemas/Missing"}, schemas) == {}
    assert (
        _validation_schema(
            {"$ref": "#/components/schemas/Loop"},
            {"Loop": {"$ref": "#/components/schemas/Loop"}},
        )
        == {}
    )
    assert _response_content_types({"responses": None}) == []
    assert (
        _response_content_types(
            {
                "responses": {
                    "201": None,
                    "400": {"content": {"application/problem+json": {}}},
                    "204": {"content": []},
                }
            }
        )
        == []
    )

    assert _command_name("get_location_stats", "locations") == "get-stats"
    assert _command_name("create_location_snapshot", "locations") == ("create-snapshot")
    assert _command_name("custom_action", "locations") == "custom-action"
    assert _singular("categories") == "category"
    assert _singular("batches") == "batch"
    assert _singular("products") == "product"
    assert _singular("address") == "address"


@pytest.mark.parametrize(
    ("operation_id", "module", "expected"),
    [
        # The module noun goes, wherever inside the name it sits.
        ("download_mail_draft_attachment", "mail", "download-draft-attachment"),
        ("mark_inbox_message_read", "inbox", "mark-message-read"),
        ("geocode_autocomplete", "geocode", "autocomplete"),
        ("set_product_stock", "products", "set-stock"),
        # Singular and plural spellings of the module both count as the noun.
        ("export_products", "products", "export"),
        ("list_agent_memories", "memory", "list-agent"),
        ("bulk_delete_categories", "categories", "bulk-delete"),
        ("revoke_issuer_key", "issuer-keys", "revoke"),
        ("cancel_work_order", "work-orders", "cancel"),
        ("list_overdue_work_orders", "work-orders", "list-overdue"),
        # Read verbs survive, so one and many stay told apart by the verb
        # rather than by an "s".
        ("get_mail_draft", "mail", "get-draft"),
        ("list_mail_drafts", "mail", "list-drafts"),
        ("get_workspace_deletion_request", "workspace", "get-deletion-request"),
        ("get_default_workspace", "workspace", "get-default"),
        ("get_workspace_billing", "billing", "get-workspace"),
        ("list_workspaces", "workspace", "list"),
        # A noun governed by a preposition is not what the command acts on.
        ("promote_html_artifact_to_box", "boxes", "promote-html-artifact-to-box"),
        # Nothing would be left to name the command by.
        ("workspace", "workspace", "workspace"),
        # The name never mentions the module noun.
        ("custom_action", "locations", "custom-action"),
    ],
)
def test_command_name_drops_the_module_noun(
    operation_id: str, module: str, expected: str
) -> None:
    assert _command_name(operation_id, module) == expected


def test_plural_mirrors_singular() -> None:
    assert _plural("category") == "categories"
    assert _plural("issuer-key") == "issuer-keys"
    assert _plural("box") == "boxes"
    assert _plural("workspace") == "workspaces"


def test_equally_deep_contested_names_both_stay_unabbreviated() -> None:
    document = openapi_document()
    for path, operation_id in (
        ("/locations/export", "export_location"),
        ("/locations/export-all", "export_locations"),
    ):
        document["paths"][path] = {
            "get": {
                "operationId": operation_id,
                "security": [{"NularaPersonalAccessToken": []}],
                "tags": ["app-locations"],
            }
        }
    manifest = build_command_manifest(document, product="nulara")
    module = next(item for item in manifest["modules"] if item["name"] == "locations")
    names = {item["name"] for item in module["operations"]}
    assert {"export-location", "export-locations"} <= names
    assert "export" not in names


def test_a_contested_name_goes_to_the_single_resource_operation() -> None:
    document = openapi_document()
    for path, operation_id in (
        ("/locations/export", "export_locations"),
        ("/locations/{location_id}/export", "export_location"),
    ):
        document["paths"][path] = {
            "get": {
                "operationId": operation_id,
                "security": [{"NularaPersonalAccessToken": []}],
                "tags": ["app-locations"],
            }
        }
    manifest = build_command_manifest(document, product="nulara")
    module = next(item for item in manifest["modules"] if item["name"] == "locations")
    names = {item["operation_id"]: item["name"] for item in module["operations"]}
    assert names["export_location"] == "export"
    assert names["export_locations"] == "export-locations"


def test_build_skips_malformed_path_and_parameter_entries() -> None:
    document = openapi_document()
    document["paths"]["/malformed"] = []
    create = document["paths"]["/locations/{location_id}"]["post"]
    create["tags"] = [None, "app-locations"]
    create["parameters"].extend([None, {"in": "query"}, {"in": "query", "name": ""}])
    manifest = build_command_manifest(document, product="nulara")
    assert operation(manifest, "locations", "create")["operation_id"] == (
        "create_location"
    )

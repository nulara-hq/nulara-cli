from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from nulara.core.errors import ConfigurationError

MANIFEST_VERSION = 2
HTTP_METHODS = {"delete", "get", "head", "patch", "post", "put"}
PREPOSITIONS = {"as", "by", "for", "from", "in", "into", "of", "on", "to", "with"}


def build_command_manifest(document: dict[str, Any], *, product: str) -> dict[str, Any]:
    """Build the customer CLI contract from one product app OpenAPI document."""
    security_scheme = _pat_security_scheme(document, product)
    schemas = document.get("components", {}).get("schemas", {})
    if not isinstance(schemas, dict):
        raise ConfigurationError("OpenAPI components.schemas must be an object")

    modules: dict[str, list[dict[str, Any]]] = defaultdict(list)
    excluded_event_stream_operations: list[dict[str, str]] = []
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise ConfigurationError("OpenAPI document has no paths object")

    for path, path_item in sorted(paths.items()):
        if not isinstance(path_item, dict):
            continue
        inherited_parameters = path_item.get("parameters", [])
        for method, operation in path_item.items():
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            if not _uses_security_scheme(operation, security_scheme):
                continue
            response_content_types = _response_content_types(operation)
            if "text/event-stream" in response_content_types:
                excluded_event_stream_operations.append(
                    {
                        "operation_id": str(operation.get("operationId") or "unknown"),
                        "method": method.upper(),
                        "path": path,
                    }
                )
                continue
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or not operation_id:
                raise ConfigurationError(f"{method.upper()} {path} has no operationId")
            module = _module_name(operation, path)
            parameters = _parameters(
                [*inherited_parameters, *operation.get("parameters", [])],
                schemas,
                module,
            )
            body = _request_body(operation.get("requestBody"), schemas, module)
            modules[module].append(
                {
                    "operation_id": operation_id,
                    "method": method.upper(),
                    "path": path,
                    "summary": operation.get("summary") or operation_id,
                    "description": operation.get("description"),
                    "parameters": parameters,
                    "body": body,
                    "response_content_types": response_content_types,
                    "dangerous": method not in {"get", "head"},
                }
            )

    rendered_modules: list[dict[str, Any]] = []
    for module, operations in sorted(modules.items()):
        ordered = sorted(operations, key=lambda item: item["operation_id"])
        candidates = [_command_name(item["operation_id"], module) for item in ordered]
        contested = {name for name, count in Counter(candidates).items() if count > 1}
        keepers = _single_resource_keepers(ordered, candidates, contested)
        used_names: set[str] = set()
        rendered_operations: list[dict[str, Any]] = []
        for index, (operation, candidate) in enumerate(
            zip(ordered, candidates, strict=True)
        ):
            if candidate in contested and index not in keepers:
                candidate = operation["operation_id"].replace("_", "-")
            if candidate in used_names:
                raise ConfigurationError(
                    f"Duplicate CLI command {module} {candidate} in OpenAPI"
                )
            used_names.add(candidate)
            rendered_operations.append({"name": candidate, **operation})
        rendered_modules.append(
            {
                "name": module,
                "operations": rendered_operations,
            }
        )

    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return {
        "manifest_version": MANIFEST_VERSION,
        "product": product,
        "openapi_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
        "security_scheme": security_scheme,
        "module_count": len(rendered_modules),
        "operation_count": sum(
            len(module["operations"]) for module in rendered_modules
        ),
        "excluded_event_stream_operation_count": len(excluded_event_stream_operations),
        "excluded_event_stream_operations": excluded_event_stream_operations,
        "modules": rendered_modules,
    }


def write_command_manifest(
    document_path: Path, output_path: Path, *, product: str
) -> None:
    try:
        document = json.loads(document_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(
            f"Could not read OpenAPI document {document_path}: {exc}"
        ) from exc
    if not isinstance(document, dict):
        raise ConfigurationError("OpenAPI document root must be an object")
    manifest = build_command_manifest(document, product=product)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )


def _pat_security_scheme(document: dict[str, Any], product: str) -> str:
    schemes = document.get("components", {}).get("securitySchemes", {})
    if not isinstance(schemes, dict):
        raise ConfigurationError("OpenAPI document has no security schemes")
    expected = f"{product.title()}PersonalAccessToken"
    scheme = schemes.get(expected)
    if isinstance(scheme, dict) and scheme.get("scheme") == "bearer":
        return expected
    candidates = [
        name
        for name, value in schemes.items()
        if isinstance(value, dict)
        and value.get("type") == "http"
        and value.get("scheme") == "bearer"
    ]
    if len(candidates) != 1:
        raise ConfigurationError(
            f"Expected one bearer security scheme for {product}, found {candidates}"
        )
    return candidates[0]


def _uses_security_scheme(operation: dict[str, Any], scheme: str) -> bool:
    security = operation.get("security")
    return isinstance(security, list) and any(
        isinstance(requirement, dict) and scheme in requirement
        for requirement in security
    )


def _module_name(operation: dict[str, Any], path: str) -> str:
    tags = operation.get("tags", [])
    for tag in tags:
        if isinstance(tag, str) and tag.startswith("app-"):
            return tag.removeprefix("app-")
    segment = path.strip("/").split("/", 1)[0]
    if not segment or segment.startswith("{"):
        raise ConfigurationError(f"Cannot derive CLI module for path {path}")
    return segment


def _parameters(
    raw_parameters: list[Any], schemas: dict[str, Any], module: str
) -> list[dict[str, Any]]:
    parameters: list[dict[str, Any]] = []
    used_arguments: set[str] = set()
    for raw in raw_parameters:
        parameter = _resolve(raw, schemas)
        if not isinstance(parameter, dict):
            continue
        location = parameter.get("in")
        name = parameter.get("name")
        if location == "cookie" or location not in {"path", "query", "header"}:
            continue
        if not isinstance(name, str) or not name:
            continue
        argument = _unique_argument(name, location, used_arguments)
        used_arguments.add(argument)
        parameters.append(
            {
                "argument": argument,
                "name": name,
                "option": _option_name(name, module),
                "location": location,
                "required": bool(parameter.get("required")),
                "description": parameter.get("description"),
                "schema": _schema_descriptor(parameter.get("schema", {}), schemas),
            }
        )
    return parameters


def _request_body(
    raw_body: Any, schemas: dict[str, Any], module: str
) -> dict[str, Any] | None:
    body = _resolve(raw_body, schemas)
    if not isinstance(body, dict):
        return None
    content = body.get("content")
    if not isinstance(content, dict) or not content:
        return None
    content_type = (
        "application/json"
        if "application/json" in content
        else "multipart/form-data"
        if "multipart/form-data" in content
        else sorted(content)[0]
    )
    media = content.get(content_type)
    schema = (
        _resolve(media.get("schema", {}), schemas) if isinstance(media, dict) else {}
    )
    if not isinstance(schema, dict):
        schema = {}
    properties = schema.get("properties")
    required_fields = schema.get("required", [])
    rendered_properties: list[dict[str, Any]] = []
    if isinstance(properties, dict):
        used_arguments: set[str] = set()
        for name, property_schema in properties.items():
            if not isinstance(name, str):
                continue
            argument = _unique_argument(name, "body", used_arguments)
            used_arguments.add(argument)
            resolved = _resolve(property_schema, schemas)
            rendered_properties.append(
                {
                    "argument": argument,
                    "name": name,
                    "option": _option_name(name, module),
                    "required": name in required_fields,
                    "sensitive": bool(
                        isinstance(resolved, dict)
                        and (
                            resolved.get("writeOnly") is True
                            or resolved.get("x-sensitive") is True
                        )
                    ),
                    "description": (
                        resolved.get("description")
                        if isinstance(resolved, dict)
                        else None
                    ),
                    "schema": _schema_descriptor(property_schema, schemas),
                }
            )
    return {
        "required": bool(body.get("required")),
        "content_type": content_type,
        "properties": rendered_properties,
        "structured": isinstance(properties, dict),
        "schema": _validation_schema(
            media.get("schema", {}) if isinstance(media, dict) else {}, schemas
        ),
    }


def _schema_descriptor(raw_schema: Any, schemas: dict[str, Any]) -> dict[str, Any]:
    decimal = _decimal_descriptor(raw_schema, schemas)
    if decimal is not None:
        return decimal
    resolved_schema = _resolve(raw_schema, schemas)
    outer_constraints = (
        _constraints(resolved_schema) if isinstance(resolved_schema, dict) else {}
    )
    schema, nullable = _unwrap_schema(raw_schema, schemas)
    if not isinstance(schema, dict):
        return {"kind": "json", "nullable": nullable}
    schema_type = schema.get("type")
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return {
            "kind": "enum",
            "values": enum,
            "nullable": nullable,
            **_constraints(schema),
            **outer_constraints,
        }
    if schema_type == "array":
        return {
            "kind": "array",
            "items": _schema_descriptor(schema.get("items", {}), schemas),
            "nullable": nullable,
            **_constraints(schema),
            **outer_constraints,
        }
    if schema_type in {"string", "integer", "number", "boolean"}:
        return {
            "kind": "file"
            if schema_type == "string"
            and (
                schema.get("format") == "binary"
                or schema.get("contentMediaType") == "application/octet-stream"
            )
            else schema_type,
            "format": schema.get("format"),
            "nullable": nullable,
            **_constraints(schema),
            **outer_constraints,
        }
    return {
        "kind": "json",
        "nullable": nullable,
        **_constraints(schema),
        **outer_constraints,
    }


def _unwrap_schema(
    raw_schema: Any, schemas: dict[str, Any]
) -> tuple[dict[str, Any], bool]:
    schema = _resolve(raw_schema, schemas)
    if not isinstance(schema, dict):
        return {}, False
    nullable = schema.get("nullable") is True
    variants = schema.get("anyOf") or schema.get("oneOf")
    if isinstance(variants, list):
        non_null = []
        for variant in variants:
            resolved = _resolve(variant, schemas)
            if isinstance(resolved, dict) and resolved.get("type") == "null":
                nullable = True
            else:
                non_null.append(resolved)
        if len(non_null) == 1 and isinstance(non_null[0], dict):
            schema = non_null[0]
    return schema, nullable


def _resolve(raw: Any, schemas: dict[str, Any]) -> Any:
    if not isinstance(raw, dict):
        return raw
    reference = raw.get("$ref")
    if not isinstance(reference, str):
        return raw
    prefix = "#/components/schemas/"
    if not reference.startswith(prefix):
        return raw
    resolved = schemas.get(reference.removeprefix(prefix))
    if not isinstance(resolved, dict):
        return raw
    siblings = {key: value for key, value in raw.items() if key != "$ref"}
    return {**resolved, **siblings}


def _constraints(schema: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "const",
        "default",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "maximum",
        "maxItems",
        "maxLength",
        "maxProperties",
        "minimum",
        "minItems",
        "minLength",
        "minProperties",
        "multipleOf",
        "pattern",
        "uniqueItems",
        "x-allowedContentTypes",
        "x-maxSizeBytes",
    )
    return {key: schema[key] for key in keys if key in schema}


def _decimal_descriptor(
    raw_schema: Any, schemas: dict[str, Any]
) -> dict[str, Any] | None:
    schema = _resolve(raw_schema, schemas)
    if not isinstance(schema, dict):
        return None
    variants = schema.get("anyOf") or schema.get("oneOf")
    if not isinstance(variants, list):
        return None
    nullable = False
    number: dict[str, Any] | None = None
    string: dict[str, Any] | None = None
    for variant in variants:
        resolved = _resolve(variant, schemas)
        if not isinstance(resolved, dict):
            return None
        if resolved.get("type") == "null":
            nullable = True
        elif resolved.get("type") == "number" and number is None:
            number = resolved
        elif resolved.get("type") == "string" and string is None:
            string = resolved
        else:
            return None
    if number is None or string is None or not string.get("pattern"):
        return None
    return {
        "kind": "decimal",
        "nullable": nullable,
        **_constraints(number),
        **_constraints(string),
    }


def _validation_schema(
    raw_schema: Any,
    schemas: dict[str, Any],
    seen: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if not isinstance(raw_schema, dict):
        return {}
    reference = raw_schema.get("$ref")
    if isinstance(reference, str) and reference.startswith("#/components/schemas/"):
        name = reference.removeprefix("#/components/schemas/")
        if name in seen:
            return {}
        resolved = schemas.get(name)
        if not isinstance(resolved, dict):
            return {}
        next_seen = seen | {name}
        referenced = _validation_schema(resolved, schemas, next_seen)
        siblings = {key: value for key, value in raw_schema.items() if key != "$ref"}
        return {
            **referenced,
            **_validation_schema(siblings, schemas, next_seen),
        }

    scalar_keys = (
        "additionalProperties",
        "const",
        "enum",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "format",
        "maximum",
        "maxItems",
        "maxLength",
        "maxProperties",
        "minimum",
        "minItems",
        "minLength",
        "minProperties",
        "multipleOf",
        "nullable",
        "pattern",
        "required",
        "type",
        "uniqueItems",
        "writeOnly",
        "x-allowedContentTypes",
        "x-maxSizeBytes",
        "x-sensitive",
    )
    rendered = {key: raw_schema[key] for key in scalar_keys if key in raw_schema}
    properties = raw_schema.get("properties")
    if isinstance(properties, dict):
        rendered["properties"] = {
            str(name): _validation_schema(value, schemas, seen)
            for name, value in properties.items()
            if isinstance(name, str)
        }
    items = raw_schema.get("items")
    if isinstance(items, dict):
        rendered["items"] = _validation_schema(items, schemas, seen)
    for keyword in ("anyOf", "oneOf"):
        variants = raw_schema.get(keyword)
        if isinstance(variants, list):
            rendered[keyword] = [
                _validation_schema(variant, schemas, seen)
                for variant in variants
                if isinstance(variant, dict)
            ]
    return rendered


def _response_content_types(operation: dict[str, Any]) -> list[str]:
    content_types: set[str] = set()
    responses = operation.get("responses", {})
    if not isinstance(responses, dict):
        return []
    for status, response in responses.items():
        if not str(status).startswith("2") or not isinstance(response, dict):
            continue
        content = response.get("content", {})
        if isinstance(content, dict):
            content_types.update(content)
    return sorted(content_types)


def _option_name(name: str, module: str) -> str:
    singular = _singular(module.replace("-", "_"))
    normalized = name.replace("-", "_")
    if normalized == f"{singular}_type":
        return "type"
    return normalized.replace("_", "-")


def _unique_argument(name: str, location: str, used: set[str]) -> str:
    argument = re.sub(r"\W+", "_", name).strip("_") or "value"
    if argument[0].isdigit():
        argument = f"value_{argument}"
    if argument in used:
        argument = f"{location}_{argument}"
    return argument


def _single_resource_keepers(
    operations: list[dict[str, Any]],
    candidates: list[str],
    contested: set[str],
) -> set[int]:
    """Award a contested name to the one rival that addresses a single resource.

    Two operations shorten to the same name when one acts on a collection and the
    other on one member of it. The member route is the one carrying more path
    parameters, and it keeps the short name; its rivals fall back to their full
    operation ID, so the two never differ by an "s" alone.
    """
    keepers: set[int] = set()
    for name in contested:
        rivals = [index for index, value in enumerate(candidates) if value == name]
        depths = [operations[index]["path"].count("{") for index in rivals]
        deepest = max(depths)
        if depths.count(deepest) == 1:
            keepers.add(rivals[depths.index(deepest)])
    return keepers


def _command_name(operation_id: str, module: str) -> str:
    """Name a command without repeating the module noun it is already filed under."""
    tokens = operation_id.replace("_", "-").split("-")
    span = _module_noun_span(tokens, module)
    if span is None:
        return "-".join(tokens)
    start, length = span
    remaining = [*tokens[:start], *tokens[start + length :]]
    if not remaining:
        return "-".join(tokens)
    return "-".join(remaining)


def _module_noun_span(tokens: list[str], module: str) -> tuple[int, int] | None:
    """Locate the module's own noun in a command name, longest spelling first."""
    module_name = module.replace("_", "-")
    singular = _singular(module_name)
    forms = sorted(
        {module_name, singular, _plural(singular)},
        key=lambda form: (-form.count("-"), form),
    )
    for start in range(len(tokens)):
        if start and tokens[start - 1] in PREPOSITIONS:
            continue
        for form in forms:
            words = form.split("-")
            if tokens[start : start + len(words)] == words:
                return start, len(words)
    return None


def _singular(value: str) -> str:
    if value.endswith("ies"):
        return f"{value[:-3]}y"
    if value.endswith(("ches", "shes", "xes", "zes", "sses")):
        return value[:-2]
    if value.endswith("s") and not value.endswith("ss"):
        return value[:-1]
    return value


def _plural(value: str) -> str:
    if value.endswith("y") and not value.endswith(("ay", "ey", "oy", "uy")):
        return f"{value[:-1]}ies"
    if value.endswith(("ch", "sh", "s", "x", "z")):
        return f"{value}es"
    return f"{value}s"


__all__ = ["MANIFEST_VERSION", "build_command_manifest", "write_command_manifest"]

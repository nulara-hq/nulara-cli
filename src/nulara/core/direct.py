from __future__ import annotations

import inspect
import json
import mimetypes
import re
import sys
from collections.abc import Iterator
from contextlib import ExitStack
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Annotated, Any, BinaryIO, Literal
from urllib.parse import quote, unquote, urlsplit

from cyclopts import App, Group, Parameter
from rich.console import Console
from rich.prompt import Confirm

from nulara.core.client import ApiClient, ApiResult
from nulara.core.config import Product, Surface
from nulara.core.errors import CliError, ConfigurationError
from nulara.core.openapi import MANIFEST_VERSION
from nulara.core.render import render_json, render_rows
from nulara.core.tokens import get_token

console = Console()
MODULE_GROUP = Group("Product modules", sort_key=20)
HTTP_METHODS = Literal["DELETE", "GET", "HEAD", "PATCH", "POST", "PUT"]
MAX_JSON_INPUT_BYTES = 10 * 1024 * 1024


def register_module_commands(
    app: App,
    product: Product,
    surface: Surface,
    *,
    connection_type: type,
    default_connection: Any,
) -> dict[str, App]:
    """Register every PAT-protected product operation from its generated manifest.

    Returns the module apps by name so an entrypoint can add a hand-written
    command to a generated group — `workspace use` is local-only and has no
    operation in the manifest to be generated from.
    """
    manifest = load_manifest(product)
    module_apps: dict[str, App] = {}
    for module in manifest["modules"]:
        module_app = app.command(
            App(
                name=module["name"],
                help=f"Direct {module['name']} API operations.",
                group=MODULE_GROUP,
            )
        )
        module_apps[module["name"]] = module_app
        for operation in module["operations"]:
            command = _build_command(
                product,
                surface,
                operation,
                connection_type=connection_type,
                default_connection=default_connection,
            )
            module_app.command(command, name=operation["name"])
    return module_apps


def load_manifest(product: Product) -> dict[str, Any]:
    try:
        payload = json.loads(product.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(
            f"Could not load the {product.name} CLI contract: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise ConfigurationError("CLI contract root must be an object")
    if payload.get("manifest_version") != MANIFEST_VERSION:
        raise ConfigurationError(
            f"Unsupported CLI contract version {payload.get('manifest_version')}"
        )
    if payload.get("product") != product.name:
        raise ConfigurationError(
            f"CLI contract for {payload.get('product')} loaded as {product.name}"
        )
    modules = payload.get("modules")
    if not isinstance(modules, list):
        raise ConfigurationError("CLI contract has no modules list")
    return payload


def run_raw_api(
    *,
    endpoint: str,
    method: str,
    fields: list[str],
    raw_fields: list[str],
    params: list[str],
    input_file: str | None,
    content_type: str,
    output: Path | None,
    overwrite: bool,
    yes: bool,
    dry_run: bool,
    json_output: bool,
    connection: Any,
    product: Product,
    surface: Surface,
) -> None:
    path = validate_relative_endpoint(endpoint)
    normalized_method = method.upper()
    if normalized_method not in HTTP_METHODS.__args__:
        raise CliError(f"Unsupported HTTP method {method}")
    streaming_operations = load_manifest(product).get(
        "excluded_event_stream_operations", []
    )
    request_path = _decoded_route_path(urlsplit(path).path)
    if any(
        operation.get("method") == normalized_method
        and _operation_path_matches(operation.get("path"), request_path)
        for operation in streaming_operations
        if isinstance(operation, dict)
    ):
        raise CliError(
            f"{normalized_method} {request_path} is an agent event stream; "
            f"use `{product.name} agent run` so SSE and HITL are handled safely"
        )
    query = _parse_assignments(params, typed=True)
    body_fields = dict(_parse_assignments(fields, typed=True))
    body_fields.update(_parse_assignments(raw_fields, typed=False))
    if input_file is not None and body_fields:
        raise CliError("--input cannot be combined with --field or --raw-field")
    body: Any = body_fields or None
    content_input: str | None = None
    if input_file is not None:
        if content_type == "application/json":
            raw = _read_input(input_file)
            try:
                body = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise CliError(f"--input is not valid JSON: {exc}") from exc
        else:
            content_input = input_file

    preview = {
        "method": normalized_method,
        "path": path,
        "params": query,
        "content_type": (
            content_type if content_input is not None else "application/json"
        ),
        "body": (
            "<redacted>"
            if body is not None
            else "<redacted input>"
            if content_input is not None
            else None
        ),
    }
    if dry_run:
        render_json(preview)
        return
    _confirm_if_dangerous(
        dangerous=normalized_method not in {"GET", "HEAD"},
        yes=yes,
        description=f"{normalized_method} {path}",
    )
    config = connection.resolve(product, surface)
    token, _source = get_token(config)
    headers = {"Content-Type": content_type} if content_input is not None else None
    redact_values = _body_strings(body)
    content = _input_chunks(content_input) if content_input is not None else None
    with ApiClient(config, token) as client:
        request_arguments = {
            "params": query,
            "json": body if content is None else None,
            "headers": headers,
            "content": content,
            "redact_values": redact_values,
        }
        if output is not None:
            download = client.request_to_file(
                normalized_method,
                path,
                output,
                overwrite=overwrite,
                **request_arguments,
            )
            _render_download(download.bytes_written, download.output)
            return
        result = client.request_result(normalized_method, path, **request_arguments)
    render_api_result(result, json_output=json_output, output=None, overwrite=False)


def validate_relative_endpoint(endpoint: str) -> str:
    value = endpoint.strip()
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or value.startswith("//"):
        raise CliError("API endpoint must be relative to the configured product API")
    if parsed.fragment:
        raise CliError("API endpoint must not contain a fragment")
    path = parsed.path if parsed.path.startswith("/") else f"/{parsed.path}"
    if not path.strip("/"):
        raise CliError("API endpoint must name a route")
    decoded_path = _decoded_route_path(path)
    if any(segment == ".." for segment in decoded_path.split("/")):
        raise CliError("API endpoint must not contain parent path segments")
    return f"{path}?{parsed.query}" if parsed.query else path


def _decoded_route_path(path: str) -> str:
    decoded = path
    for _round in range(8):
        candidate = unquote(decoded).replace("\\", "/")
        if candidate == decoded:
            return candidate
        decoded = candidate
    if unquote(decoded).replace("\\", "/") != decoded:
        raise CliError("API endpoint contains excessive nested encoding")
    return decoded


def _operation_path_matches(template: Any, path: str) -> bool:
    if not isinstance(template, str):
        return False
    template_segments = template.strip("/").split("/")
    path_segments = path.strip("/").split("/")
    return len(template_segments) == len(path_segments) and all(
        template_segment == path_segment
        or (template_segment.startswith("{") and template_segment.endswith("}"))
        for template_segment, path_segment in zip(
            template_segments, path_segments, strict=True
        )
    )


def render_api_result(
    result: ApiResult,
    *,
    json_output: bool,
    output: Path | None,
    overwrite: bool,
) -> None:
    if output is not None:
        raise CliError(
            "Buffered output is disabled; use the streaming request output path"
        )
    if result.is_binary:
        suggestion = result.filename or "response.bin"
        raise CliError(
            f"API returned {result.content_type or 'binary data'}; pass "
            f"--output {suggestion}"
        )
    payload = result.payload()
    if payload is None:
        console.print(f"[green]Completed[/green] (HTTP {result.status_code})")
    elif json_output:
        render_json(payload)
    else:
        render_rows(payload)


def _render_download(bytes_written: int, output: Path) -> None:
    console.print(f"[green]Saved[/green] {bytes_written} bytes to {output}")


def _build_command(
    product: Product,
    surface: Surface,
    operation: dict[str, Any],
    *,
    connection_type: type,
    default_connection: Any,
):
    path_parameters = [
        parameter
        for parameter in operation["parameters"]
        if parameter["location"] == "path"
    ]
    signature = _command_signature(
        operation,
        connection_type=connection_type,
        default_connection=default_connection,
    )
    defaults = {
        name: parameter.default
        for name, parameter in signature.parameters.items()
        if parameter.default is not inspect.Parameter.empty
    }

    def command(*args: Any, **kwargs: Any) -> None:
        values = dict(defaults)
        values.update(
            zip(
                (item["argument"] for item in path_parameters),
                args,
                strict=True,
            )
        )
        values.update(kwargs)
        _run_operation(product, surface, operation, values)

    command.__name__ = operation["operation_id"]
    command.__doc__ = _command_help(operation)
    command_with_signature: Any = command
    command_with_signature.__signature__ = signature
    return command


def _command_signature(
    operation: dict[str, Any], *, connection_type: type, default_connection: Any
) -> inspect.Signature:
    parameters: list[inspect.Parameter] = []
    for parameter in operation["parameters"]:
        if parameter["location"] != "path":
            continue
        parameters.append(
            inspect.Parameter(
                parameter["argument"],
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=_field_annotation(parameter, positional=True),
            )
        )
    for parameter in operation["parameters"]:
        if parameter["location"] == "path":
            continue
        parameters.append(
            inspect.Parameter(
                parameter["argument"],
                inspect.Parameter.KEYWORD_ONLY,
                annotation=_field_annotation(parameter),
                default=inspect.Parameter.empty if parameter["required"] else None,
            )
        )
    body = operation.get("body")
    if isinstance(body, dict):
        for field in body["properties"]:
            if field.get("sensitive"):
                continue
            parameters.append(
                inspect.Parameter(
                    f"body_{field['argument']}",
                    inspect.Parameter.KEYWORD_ONLY,
                    annotation=_field_annotation(field, body=True),
                    default=None,
                )
            )
        if body["content_type"] == "application/json":
            parameters.append(
                inspect.Parameter(
                    "input_file",
                    inspect.Parameter.KEYWORD_ONLY,
                    annotation=Annotated[
                        str | None,
                        Parameter(
                            name="--input",
                            help="Read the complete JSON body from FILE; use - for stdin.",
                        ),
                    ],
                    default=None,
                )
            )
    parameters.extend(
        [
            inspect.Parameter(
                "output",
                inspect.Parameter.KEYWORD_ONLY,
                annotation=Annotated[
                    Path | None,
                    Parameter(help="Write the raw response body to FILE."),
                ],
                default=None,
            ),
            inspect.Parameter(
                "overwrite",
                inspect.Parameter.KEYWORD_ONLY,
                annotation=Annotated[
                    bool,
                    Parameter(
                        negative=(),
                        help="Replace an existing --output file.",
                    ),
                ],
                default=False,
            ),
        ]
    )
    if operation["dangerous"]:
        parameters.append(
            inspect.Parameter(
                "yes",
                inspect.Parameter.KEYWORD_ONLY,
                annotation=Annotated[
                    bool,
                    Parameter(
                        negative=(),
                        help="Skip the mutating-operation confirmation.",
                    ),
                ],
                default=False,
            )
        )
    if operation["method"] != "GET":
        parameters.append(
            inspect.Parameter(
                "dry_run",
                inspect.Parameter.KEYWORD_ONLY,
                annotation=Annotated[
                    bool,
                    Parameter(
                        name="--dry-run",
                        negative=(),
                        help="Show the request without sending it.",
                    ),
                ],
                default=False,
            )
        )
    parameters.extend(
        [
            inspect.Parameter(
                "json_output",
                inspect.Parameter.KEYWORD_ONLY,
                annotation=Annotated[bool, Parameter(name="--json", negative=())],
                default=False,
            ),
            inspect.Parameter(
                "connection",
                inspect.Parameter.KEYWORD_ONLY,
                annotation=connection_type,
                default=default_connection,
            ),
        ]
    )
    return inspect.Signature(parameters)


def _run_operation(
    product: Product,
    surface: Surface,
    operation: dict[str, Any],
    values: dict[str, Any],
) -> None:
    path = operation["path"]
    query: list[tuple[str, Any]] = []
    headers: dict[str, str] = {}
    for parameter in operation["parameters"]:
        value = values.get(parameter["argument"])
        if value is None:
            continue
        _validate_value(parameter, value)
        if parameter["location"] == "path":
            path = path.replace(f"{{{parameter['name']}}}", quote(str(value), safe=""))
        elif parameter["location"] == "query":
            _append_values(query, parameter["name"], value)
        else:
            headers[parameter["name"]] = _wire_scalar(value)
    if "{" in path or "}" in path:
        raise CliError(f"Not all path parameters were provided for {path}")

    body_spec = operation.get("body")
    json_body: Any = None
    data: dict[str, Any] | None = None
    files: list[tuple[str, Any]] | None = None
    body_values: dict[str, Any] = {}
    if isinstance(body_spec, dict):
        body_values = {
            field["name"]: values.get(f"body_{field['argument']}")
            for field in body_spec["properties"]
            if values.get(f"body_{field['argument']}") is not None
        }
        input_file = values.get("input_file")
        if input_file is not None and body_values:
            raise CliError("--input cannot be combined with body field options")
        if input_file is not None:
            try:
                json_body = json.loads(_read_input(input_file))
            except json.JSONDecodeError as exc:
                raise CliError(f"--input is not valid JSON: {exc}") from exc
            _validate_json_schema(
                json_body,
                body_spec.get("schema", {}),
                label="--input",
            )
        else:
            if body_spec["required"] and not body_spec["structured"]:
                raise CliError("This operation requires a request body; pass --input")
            sensitive_required = [
                field["name"]
                for field in body_spec["properties"]
                if field["required"] and field.get("sensitive")
            ]
            if sensitive_required:
                fields = ", ".join(sensitive_required)
                raise CliError(
                    f"Required sensitive body field(s) {fields} must be read via --input"
                )
            missing = [
                field["option"]
                for field in body_spec["properties"]
                if field["required"] and field["name"] not in body_values
            ]
            if missing:
                flags = ", ".join(f"--{name}" for name in missing)
                raise CliError(
                    f"Missing required body options: {flags}; alternatively pass --input"
                )
            for field in body_spec["properties"]:
                if field["name"] in body_values:
                    _validate_value(field, body_values[field["name"]])
            if body_spec["content_type"] == "application/json":
                json_body = {
                    field["name"]: _json_value(field, body_values[field["name"]])
                    for field in body_spec["properties"]
                    if field["name"] in body_values
                }
                _validate_json_schema(
                    json_body,
                    body_spec.get("schema", {}),
                    label="request body",
                )

    preview = {
        "operation_id": operation["operation_id"],
        "method": operation["method"],
        "path": path,
        "params": query,
        "body": _redact_json_body(
            json_body if json_body is not None else body_values or None,
            body_spec.get("schema", {}) if isinstance(body_spec, dict) else {},
        ),
    }
    if values.get("dry_run", False):
        render_json(preview)
        return
    _confirm_if_dangerous(
        dangerous=operation["dangerous"],
        yes=values.get("yes", False),
        description=f"{operation['method']} {path}",
    )
    connection = values["connection"]
    config = connection.resolve(product, surface)
    token, _source = get_token(config)
    with ExitStack() as stack:
        if (
            isinstance(body_spec, dict)
            and body_spec["content_type"] == "multipart/form-data"
        ):
            data, files = _multipart_payload(body_spec, body_values, stack)
        with ApiClient(config, token) as client:
            request_arguments = {
                "params": query,
                "json": json_body,
                "data": data,
                "files": files,
                "headers": headers or None,
                "redact_values": _sensitive_body_strings(
                    json_body if json_body is not None else body_values,
                    body_spec.get("schema", {}) if isinstance(body_spec, dict) else {},
                ),
            }
            output = values["output"]
            if output is not None:
                download = client.request_to_file(
                    operation["method"],
                    path,
                    output,
                    overwrite=values["overwrite"],
                    **request_arguments,
                )
                _render_download(download.bytes_written, download.output)
                return
            result = client.request_result(
                operation["method"], path, **request_arguments
            )
    render_api_result(
        result, json_output=values["json_output"], output=None, overwrite=False
    )


def _field_annotation(
    field: dict[str, Any], *, positional: bool = False, body: bool = False
) -> Any:
    schema = field["schema"]
    base = _python_type(schema)
    if not field.get("required") or body:
        base = base | None
    help_text = field.get("description") or _field_help(field)
    if positional:
        return Annotated[base, Parameter(help=help_text)]
    return Annotated[
        base,
        Parameter(name=f"--{field['option']}", help=help_text),
    ]


def _python_type(schema: dict[str, Any]) -> Any:
    kind = schema.get("kind")
    if kind == "enum":
        return Literal[*schema["values"]]
    if kind == "integer":
        return int
    if kind == "number":
        return float
    if kind == "decimal":
        return str
    if kind == "boolean":
        return bool
    if kind == "file":
        return Path
    if kind == "array":
        return list[_python_type(schema["items"])]
    return str


def _field_help(field: dict[str, Any]) -> str:
    schema = field["schema"]
    parts = [field["name"].replace("_", " ").capitalize()]
    if field.get("required"):
        parts.append("required")
    if "default" in schema:
        parts.append(f"default: {schema['default']}")
    if schema.get("kind") == "json":
        parts.append("JSON value")
    return f"{' ('.join(parts)}{')' if len(parts) > 1 else ''}."


def _command_help(operation: dict[str, Any]) -> str:
    description = operation.get("description") or operation["summary"]
    return f"{description}\n\nOpenAPI operation: {operation['operation_id']}."


def _parse_assignments(values: list[str], *, typed: bool) -> list[tuple[str, Any]]:
    parsed: list[tuple[str, Any]] = []
    for value in values:
        key, separator, raw = value.partition("=")
        if not separator or not key:
            raise CliError(f"Invalid value `{value}`; expected key=value")
        if typed:
            try:
                parsed_value = json.loads(raw)
            except json.JSONDecodeError:
                parsed_value = raw
        else:
            parsed_value = raw
        parsed.append((key, parsed_value))
    return parsed


def _read_input(value: str) -> bytes:
    source: BinaryIO
    try:
        if value == "-":
            source = sys.stdin.buffer
            content = source.read(MAX_JSON_INPUT_BYTES + 1)
        else:
            with Path(value).open("rb") as source:
                content = source.read(MAX_JSON_INPUT_BYTES + 1)
    except OSError as exc:
        raise CliError(f"Could not read input file {value}: {exc}") from exc
    if len(content) > MAX_JSON_INPUT_BYTES:
        raise CliError(
            f"JSON input exceeds the {MAX_JSON_INPUT_BYTES}-byte in-memory limit"
        )
    return content


def _input_chunks(value: str) -> Iterator[bytes]:
    def chunks() -> Iterator[bytes]:
        try:
            if value == "-":
                while chunk := sys.stdin.buffer.read(1024 * 1024):
                    yield chunk
                return
            with Path(value).open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    yield chunk
        except OSError as exc:
            raise CliError(f"Could not read input file {value}: {exc}") from exc

    return chunks()


def _append_values(target: list[tuple[str, Any]], name: str, value: Any) -> None:
    if isinstance(value, list):
        target.extend((name, _wire_scalar(item)) for item in value)
    else:
        target.append((name, _wire_scalar(value)))


def _wire_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _json_value(field: dict[str, Any], value: Any) -> Any:
    schema = field["schema"]
    if schema.get("kind") == "decimal":
        return str(value)
    if schema.get("kind") != "json" or not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise CliError(
            f"--{field['option']} must contain a valid JSON value: {exc}"
        ) from exc


def _multipart_payload(
    body_spec: dict[str, Any],
    values: dict[str, Any],
    stack: ExitStack,
) -> tuple[dict[str, Any], list[tuple[str, Any]]]:
    data: dict[str, Any] = {}
    files: list[tuple[str, Any]] = []
    for field in body_spec["properties"]:
        if field["name"] not in values:
            continue
        value = values[field["name"]]
        schema = field["schema"]
        is_file = schema.get("kind") == "file"
        is_file_array = (
            schema.get("kind") == "array"
            and schema.get("items", {}).get("kind") == "file"
        )
        if is_file or is_file_array:
            paths = value if isinstance(value, list) else [value]
            file_schema = schema.get("items", {}) if is_file_array else schema
            for raw_path in paths:
                path = Path(raw_path)
                try:
                    size = path.stat().st_size
                    handle = stack.enter_context(path.open("rb"))
                except OSError as exc:
                    raise CliError(f"Could not read upload file {path}: {exc}") from exc
                maximum_size = file_schema.get("x-maxSizeBytes") or schema.get(
                    "x-maxSizeBytes"
                )
                if maximum_size is not None and size > maximum_size:
                    raise CliError(
                        f"--{field['option']} file {path} exceeds {maximum_size} bytes"
                    )
                media_type = mimetypes.guess_type(path.name)[0]
                allowed_types = file_schema.get("x-allowedContentTypes") or schema.get(
                    "x-allowedContentTypes"
                )
                if allowed_types and media_type not in allowed_types:
                    allowed = ", ".join(allowed_types)
                    raise CliError(
                        f"--{field['option']} file {path} has unsupported type "
                        f"{media_type or 'application/octet-stream'}; allowed: {allowed}"
                    )
                files.append(
                    (
                        field["name"],
                        (path.name, handle, media_type or "application/octet-stream"),
                    )
                )
        elif isinstance(value, list):
            data[field["name"]] = [_wire_scalar(item) for item in value]
        else:
            rendered = _json_value(field, value)
            data[field["name"]] = (
                json.dumps(rendered)
                if isinstance(rendered, (dict, list))
                else _wire_scalar(rendered)
            )
    return data, files


def _validate_value(field: dict[str, Any], value: Any) -> None:
    schema = field["schema"]
    if isinstance(value, list):
        _check_bound(field, len(value), "minItems", "at least")
        _check_bound(field, len(value), "maxItems", "at most")
        if schema.get("uniqueItems") and len(
            {_stable_value(item) for item in value}
        ) != len(value):
            raise CliError(f"--{field['option']} must contain unique values")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for item in value:
                _validate_value({**field, "schema": item_schema}, item)
        return
    if isinstance(value, dict):
        _check_bound(field, len(value), "minProperties", "at least")
        _check_bound(field, len(value), "maxProperties", "at most")
    constant = schema.get("const")
    if "const" in schema and value != constant:
        raise CliError(f"--{field['option']} must equal {constant!r}")
    if isinstance(value, str):
        _check_bound(field, len(value), "minLength", "at least")
        _check_bound(field, len(value), "maxLength", "at most")
        pattern = schema.get("pattern")
        if pattern and re.fullmatch(pattern, value) is None:
            raise CliError(
                f"--{field['option']} does not match required pattern {pattern}"
            )
    if (
        isinstance(value, (int, float, Decimal, str))
        and not isinstance(value, bool)
        and schema.get("kind") in {"integer", "number", "decimal"}
    ):
        _validate_number(field, value)


def _validate_number(field: dict[str, Any], value: Any) -> None:
    schema = field["schema"]
    try:
        number = Decimal(str(value))
    except InvalidOperation as exc:
        raise CliError(f"--{field['option']} must be numeric") from exc
    if not number.is_finite():
        raise CliError(f"--{field['option']} must be a finite number")
    bounds = (
        ("minimum", lambda actual, expected: actual < expected, "at least"),
        ("maximum", lambda actual, expected: actual > expected, "at most"),
        (
            "exclusiveMinimum",
            lambda actual, expected: actual <= expected,
            "greater than",
        ),
        ("exclusiveMaximum", lambda actual, expected: actual >= expected, "less than"),
    )
    for key, invalid, description in bounds:
        expected = schema.get(key)
        if expected is not None and invalid(number, Decimal(str(expected))):
            raise CliError(f"--{field['option']} must be {description} {expected}")
    multiple = schema.get("multipleOf")
    if multiple is not None and number % Decimal(str(multiple)) != 0:
        raise CliError(f"--{field['option']} must be a multiple of {multiple}")


def _check_bound(
    field: dict[str, Any], actual: int, key: str, description: str
) -> None:
    expected = field["schema"].get(key)
    if expected is None:
        return
    invalid = actual < expected if key.startswith("min") else actual > expected
    if invalid:
        raise CliError(
            f"--{field['option']} must contain {description} {expected} value(s)"
        )


def _confirm_if_dangerous(*, dangerous: bool, yes: bool, description: str) -> None:
    if not dangerous or yes:
        return
    if not sys.stdin.isatty():
        raise CliError(f"{description} mutates data; pass --yes in non-interactive use")
    if not Confirm.ask(f"Run mutating operation {description}?", default=False):
        raise CliError("Operation cancelled")


def _stable_value(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _validate_json_schema(value: Any, schema: Any, *, label: str) -> None:
    if not isinstance(schema, dict) or not schema:
        return
    if value is None and (schema.get("nullable") or schema.get("type") == "null"):
        return
    variants = schema.get("anyOf") or schema.get("oneOf")
    if isinstance(variants, list) and variants:
        decimal_schema = _decimal_union_schema(variants)
        if decimal_schema is not None:
            _validate_value(
                {"option": label, "schema": decimal_schema},
                value,
            )
            return
        failures: list[CliError] = []
        for variant in variants:
            try:
                _validate_json_schema(value, variant, label=label)
                return
            except CliError as exc:
                failures.append(exc)
        raise CliError(f"{label} does not match any allowed schema") from failures[-1]

    raw_schema_type = schema.get("type")
    schema_type = raw_schema_type if isinstance(raw_schema_type, str) else None
    validators = {
        "array": lambda item: isinstance(item, list),
        "boolean": lambda item: isinstance(item, bool),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "null": lambda item: item is None,
        "number": lambda item: isinstance(item, (int, float))
        and not isinstance(item, bool),
        "object": lambda item: isinstance(item, dict),
        "string": lambda item: isinstance(item, str),
    }
    valid_type = validators.get(schema_type) if schema_type is not None else None
    if valid_type is not None and not valid_type(value):
        raise CliError(f"{label} must be {schema_type}")
    if "const" in schema and value != schema["const"]:
        raise CliError(f"{label} must equal {schema['const']!r}")
    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        raise CliError(f"{label} must be one of {enum}")

    field = {"option": label, "schema": {**schema, "kind": schema_type or "json"}}
    if isinstance(value, (str, int, float, list, dict)) and not isinstance(value, bool):
        _validate_value(field, value)
    if isinstance(value, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(value):
                _validate_json_schema(item, items, label=f"{label}[{index}]")
    if isinstance(value, dict):
        required = schema.get("required", [])
        if isinstance(required, list):
            missing = [name for name in required if name not in value]
            if missing:
                raise CliError(
                    f"{label} is missing required field(s): {', '.join(missing)}"
                )
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            if schema.get("additionalProperties") is False:
                unknown = sorted(set(value) - set(properties))
                if unknown:
                    raise CliError(
                        f"{label} contains unknown field(s): {', '.join(unknown)}"
                    )
            for name, item in value.items():
                property_schema = properties.get(name)
                if isinstance(property_schema, dict):
                    _validate_json_schema(
                        item, property_schema, label=f"{label}.{name}"
                    )


def _redact_json_body(value: Any, schema: Any) -> Any:
    if not isinstance(schema, dict):
        return value
    if schema.get("writeOnly") is True or schema.get("x-sensitive") is True:
        return "<redacted>"
    if isinstance(value, list):
        item_schema = schema.get("items", {})
        return [_redact_json_body(item, item_schema) for item in value]
    if isinstance(value, dict):
        properties = _schema_properties(schema)
        return {
            name: _redact_json_body(item, properties.get(name, {}))
            for name, item in value.items()
        }
    return value


def _sensitive_body_strings(value: Any, schema: Any) -> list[str]:
    if not isinstance(schema, dict):
        return []
    if schema.get("writeOnly") is True or schema.get("x-sensitive") is True:
        return _body_strings(value)
    if isinstance(value, list):
        item_schema = schema.get("items", {})
        return [
            candidate
            for item in value
            for candidate in _sensitive_body_strings(item, item_schema)
        ]
    if isinstance(value, dict):
        properties = _schema_properties(schema)
        return [
            candidate
            for name, item in value.items()
            for candidate in _sensitive_body_strings(item, properties.get(name, {}))
        ]
    return []


def _body_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [candidate for item in value for candidate in _body_strings(item)]
    if isinstance(value, dict):
        return [
            candidate for item in value.values() for candidate in _body_strings(item)
        ]
    return []


def _schema_properties(schema: dict[str, Any]) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    direct = schema.get("properties")
    if isinstance(direct, dict):
        properties.update(direct)
    for keyword in ("anyOf", "oneOf"):
        variants = schema.get(keyword)
        if isinstance(variants, list):
            for variant in variants:
                if isinstance(variant, dict):
                    properties.update(_schema_properties(variant))
    return properties


def _decimal_union_schema(variants: list[Any]) -> dict[str, Any] | None:
    number: dict[str, Any] | None = None
    string: dict[str, Any] | None = None
    nullable = False
    for variant in variants:
        if not isinstance(variant, dict):
            return None
        if variant.get("type") == "number" and number is None:
            number = variant
        elif variant.get("type") == "string" and string is None:
            string = variant
        elif variant.get("type") == "null":
            nullable = True
        else:
            return None
    if number is None or string is None or not string.get("pattern"):
        return None
    return {**number, **string, "kind": "decimal", "nullable": nullable}


__all__ = [
    "HTTP_METHODS",
    "load_manifest",
    "register_module_commands",
    "render_api_result",
    "run_raw_api",
    "validate_relative_endpoint",
]

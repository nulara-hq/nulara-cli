from difflib import get_close_matches
from typing import Annotated, Any

from cyclopts import App, Parameter

from nulara.core.config import Product
from nulara.core.direct import load_manifest
from nulara.core.errors import UsageError
from nulara.core.render import render_json

BINARY_PREFIXES = ("image/", "application/pdf", "application/octet-stream")


def register_describe_command(app: App, product: Product) -> None:
    """`describe` answers from the packaged manifest, without a token or network."""

    @app.command
    def describe(
        module: str | None = None,
        command: str | None = None,
        /,
        *,
        json_output: Annotated[
            bool,
            Parameter(
                name="--json",
                negative=(),
                help="Accepted for symmetry; describe always prints JSON.",
            ),
        ] = False,
    ) -> None:
        """Print a command's parameters, request schema and an example as JSON.

        Without arguments it lists the modules, with a module its commands.
        """
        modules = {entry["name"]: entry for entry in load_manifest(product)["modules"]}
        if module is None:
            render_json(
                {
                    "modules": [
                        {
                            "name": name,
                            "commands": [
                                operation["name"] for operation in entry["operations"]
                            ],
                        }
                        for name, entry in modules.items()
                    ]
                }
            )
            return
        operations = {
            operation["name"]: operation
            for operation in _pick(modules, module, "module")["operations"]
        }
        if command is None:
            render_json(
                {
                    "module": module,
                    "commands": [
                        {
                            "name": name,
                            "summary": operation["summary"],
                            "method": operation["method"],
                            "dangerous": operation["dangerous"],
                        }
                        for name, operation in operations.items()
                    ],
                }
            )
            return
        operation = _pick(operations, command, f"{module} command")
        render_json(describe_operation(product, module, operation))


def describe_operation(
    product: Product, module: str, operation: dict[str, Any]
) -> dict[str, Any]:
    body = operation.get("body")
    arguments = [
        {
            "name": parameter["argument"],
            "required": True,
            "description": parameter.get("description"),
            "schema": parameter["schema"],
        }
        for parameter in operation["parameters"]
        if parameter["location"] == "path"
    ]
    options = [
        {
            "option": f"--{parameter['option']}",
            "in": parameter["location"],
            "required": parameter["required"],
            "description": parameter.get("description"),
            "schema": parameter["schema"],
        }
        for parameter in operation["parameters"]
        if parameter["location"] != "path"
    ]
    if isinstance(body, dict):
        options.extend(
            {
                "option": f"--{field['option']}",
                "in": "body",
                "required": field["required"],
                "description": field.get("description"),
                "schema": field["schema"],
            }
            for field in body["properties"]
            if not field.get("sensitive")
        )
    return {
        "command": f"{product.name} {module} {operation['name']}",
        "operation_id": operation["operation_id"],
        "summary": operation["summary"],
        "description": operation.get("description"),
        "method": operation["method"],
        "path": operation["path"],
        "dangerous": operation["dangerous"],
        "arguments": arguments,
        "options": options,
        "body": _body(body),
        "all_pages": bool(operation.get("pagination")),
        "response_content_types": operation["response_content_types"],
        "example": _example(product, module, operation),
    }


def _body(body: Any) -> dict[str, Any] | None:
    if not isinstance(body, dict):
        return None
    return {
        "content_type": body["content_type"],
        "required": body["required"],
        "accepts_input_file": body["content_type"] == "application/json",
        "required_fields": [
            field["name"] for field in body["properties"] if field["required"]
        ],
        "sensitive_fields": [
            field["name"] for field in body["properties"] if field.get("sensitive")
        ],
        "schema": body.get("schema", {}),
    }


def _example(product: Product, module: str, operation: dict[str, Any]) -> str:
    """One command line that satisfies every required input."""
    parts = [product.name, module, operation["name"]]
    parts.extend(
        f"<{parameter['option']}>"
        for parameter in operation["parameters"]
        if parameter["location"] == "path"
    )
    parts.extend(
        _example_option(parameter)
        for parameter in operation["parameters"]
        if parameter["location"] != "path" and parameter["required"]
    )
    body = operation.get("body")
    if isinstance(body, dict):
        fields = body["properties"]
        needs_input = (not body["structured"] and body["required"]) or any(
            field["required"] and field.get("sensitive") for field in fields
        )
        if needs_input:
            parts.append("--input body.json")
        else:
            parts.extend(
                _example_option(field) for field in fields if field["required"]
            )
    if operation["dangerous"]:
        parts.append("--yes")
    binary = any(
        content_type.startswith(BINARY_PREFIXES)
        for content_type in operation["response_content_types"]
    )
    parts.append("--output <file> --json" if binary else "--json")
    return " ".join(parts)


def _example_option(field: dict[str, Any]) -> str:
    schema = field["schema"]
    option = f"--{field['option']}"
    if schema.get("kind") == "boolean":
        return option
    if schema.get("kind") == "enum":
        return f"{option} {schema['values'][0]}"
    return f"{option} <{field['option']}>"


def _pick(choices: dict[str, Any], name: str, label: str) -> Any:
    if name in choices:
        return choices[name]
    suggestions = get_close_matches(name, list(choices), n=3)
    hint = f"; did you mean {', '.join(suggestions)}?" if suggestions else ""
    raise UsageError(f"Unknown {label} `{name}`{hint}")

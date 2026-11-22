"""What this package adds to the core: Nulara's identity, manifest and skill."""

from importlib.metadata import version

import pytest
from rich.console import Console
from xiii_cli_core.config import Surface
from xiii_cli_core.direct import load_manifest
from xiii_cli_core.main import build_app

import nulara
from nulara import PRODUCT


def test_the_product_names_nulara_and_its_production_api() -> None:
    assert PRODUCT.name == "nulara"
    assert PRODUCT.display_name == "Nulara"
    assert PRODUCT.api_url == "https://api.nulara.de/v1/app"
    assert PRODUCT.oauth_client_id == "nulara-cli"
    assert PRODUCT.version == version("nulara")


def test_main_runs_the_customer_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []
    monkeypatch.setattr(nulara, "run", calls.append)
    nulara.main()
    monkeypatch.setattr(nulara, "build_app", lambda *args: args)
    assert calls[0]() == (PRODUCT, Surface.CUSTOMER)  # type: ignore[operator]


def test_the_generated_manifest_registers_every_product_module() -> None:
    manifest = load_manifest(PRODUCT)
    assert manifest["product"] == "nulara"
    assert manifest["module_count"] == len(manifest["modules"]) > 1
    operations = [
        operation
        for module in manifest["modules"]
        for operation in module["operations"]
    ]
    assert manifest["operation_count"] == len(operations)
    # All five streaming routes belong to the dedicated thread protocol,
    # never to the generated one-response commands.
    excluded_streams = manifest["excluded_event_stream_operations"]
    assert manifest["excluded_event_stream_operation_count"] == len(excluded_streams)
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
    build_app(PRODUCT, Surface.CUSTOMER).help_print(
        ["locations", "create"], console=output
    )
    help_text = output.export_text()
    assert "--name" in help_text
    assert "warehouse" in help_text


def test_the_skill_names_itself_and_the_commands_it_teaches() -> None:
    assert PRODUCT.skill is not None
    skill = PRODUCT.skill.read_text(encoding="utf-8")
    assert skill.startswith("---\nname: nulara\ndescription: ")
    for command in ("nulara describe", "--all", "--dry-run", "get-qr-code"):
        assert command in skill

import pytest

from nulara.core.engine import parse_catalog, select_read_operation
from nulara.core.errors import OperationError


def _catalog() -> dict:
    return {
        "count": 2,
        "operations": [
            {
                "operation_id": "list_tasks",
                "method": "get",
                "path": "/tasks",
                "summary": "List tasks",
                "tags": ["app-tasks"],
                "metadata": {
                    "resource": "tasks",
                    "mode": "read",
                    "approval": "never",
                },
            },
            {
                "operation_id": "bulk_update_tasks",
                "method": "patch",
                "path": "/tasks/bulk",
                "summary": "Bulk update tasks",
                "tags": ["app-tasks"],
                "metadata": {
                    "resource": "tasks",
                    "mode": "write",
                    "approval": "always",
                },
            },
        ],
    }


def test_select_read_operation_ignores_brokered_write() -> None:
    operation = select_read_operation(parse_catalog(_catalog()), "tasks")

    assert operation.operation_id == "list_tasks"
    assert operation.path == "/tasks"


def test_unknown_resource_fails_closed() -> None:
    with pytest.raises(OperationError, match="no agent-approved read operation"):
        select_read_operation(parse_catalog(_catalog()), "contacts")


def test_catalog_rejects_invalid_shapes() -> None:
    with pytest.raises(OperationError, match="no operations list"):
        parse_catalog({})
    with pytest.raises(OperationError, match="invalid descriptor"):
        parse_catalog({"operations": [None]})


def test_selects_only_or_rejects_ambiguous_read_operations() -> None:
    catalog = _catalog()
    catalog["operations"][0]["operation_id"] = "search_tasks"
    assert select_read_operation(parse_catalog(catalog), "tasks").operation_id == (
        "search_tasks"
    )
    catalog["operations"].append(
        {
            **catalog["operations"][0],
            "operation_id": "export_tasks",
        }
    )
    with pytest.raises(OperationError, match="multiple read operations"):
        select_read_operation(parse_catalog(catalog), "tasks")

from dataclasses import dataclass
from typing import Any

from nulara.core.errors import OperationError


@dataclass(frozen=True)
class Operation:
    operation_id: str
    method: str
    path: str
    summary: str | None
    resource: str
    mode: str
    approval: str


def parse_catalog(payload: dict[str, Any]) -> tuple[Operation, ...]:
    raw_operations = payload.get("operations")
    if not isinstance(raw_operations, list):
        raise OperationError("Operation catalog has no operations list")
    operations: list[Operation] = []
    for raw in raw_operations:
        if not isinstance(raw, dict) or not isinstance(raw.get("metadata"), dict):
            raise OperationError("Operation catalog contains an invalid descriptor")
        metadata = raw["metadata"]
        operations.append(
            Operation(
                operation_id=str(raw["operation_id"]),
                method=str(raw["method"]).upper(),
                path=str(raw["path"]),
                summary=raw.get("summary"),
                resource=str(metadata["resource"]),
                mode=str(metadata["mode"]),
                approval=str(metadata["approval"]),
            )
        )
    return tuple(operations)


def select_read_operation(
    operations: tuple[Operation, ...], resource: str
) -> Operation:
    candidates = [
        operation
        for operation in operations
        if operation.resource == resource and operation.mode == "read"
    ]
    preferred_id = f"list_{resource.replace('-', '_')}"
    for operation in candidates:
        if operation.operation_id == preferred_id:
            return operation
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise OperationError(
            f"Resource `{resource}` has no agent-approved read operation."
        )
    operation_ids = ", ".join(operation.operation_id for operation in candidates)
    raise OperationError(
        f"Resource `{resource}` has multiple read operations: {operation_ids}"
    )

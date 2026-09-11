"""Call-graph enforcement for declared application-operation effect ports.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

from typing import Any


WRITE_CALLS = {
    "chmod", "mkdir", "rename", "rmdir", "symlink_to", "touch", "unlink",
    "write_bytes", "write_text",
}
SHUTIL_WRITE_CALLS = {"copy", "copy2", "move", "rmtree"}
AUTHORITY_CALL_PREFIXES = (
    "approve", "authorize", "build_release_receipt", "certify", "emit_release_receipt",
    "merge", "publish", "set_status",
)
MUTATION_CALL_PREFIXES = (
    "adopt_", "allocate_", "apply_", "attest_", "capture_", "install_",
    "migrate_", "pin_", "project_", "remove_", "scaffold_", "update_",
)


class SemanticOperationEffectError(ValueError):
    """Raised when an operation bypasses its declared effect boundary."""


def _resolve_function(
    symbol: str, functions: dict[str, dict[str, Any]]
) -> str | None:
    if symbol in functions:
        return symbol
    module, separator, function = symbol.partition("::")
    if not separator:
        return None
    module_name = module.removesuffix(".py").rsplit("/", 1)[-1]
    candidates = [
        candidate
        for candidate in functions
        if candidate.endswith(f"/{module_name}.py::{function}")
        or candidate == f"{module_name}.py::{function}"
    ]
    return candidates[0] if len(candidates) == 1 else None


def _port_identity(
    value: str, functions: dict[str, dict[str, Any]]
) -> tuple[str, str]:
    resolved = _resolve_function(value, functions)
    return ("function", resolved) if resolved is not None else ("call", value)


def validate_operation_effects(
    operation: dict[str, Any],
    entrypoint_symbol: str,
    inventory: dict[str, Any],
) -> tuple[int, int]:
    """Trace one entrypoint and require all effects to cross declared ports."""
    functions = {
        str(row["symbol"]): row for row in inventory.get("functions", [])
    }
    entrypoint = _resolve_function(entrypoint_symbol, functions)
    if entrypoint is None:
        raise SemanticOperationEffectError(
            f"operation {operation['id']} entrypoint is absent from the shared source inventory"
        )
    mutation_ports = {
        _port_identity(str(value), functions)
        for value in operation["allowed_mutation_ports"]
    }
    authority_ports = {
        _port_identity(str(value), functions)
        for value in operation["allowed_authority_ports"]
    }
    non_authoritative_ports = {
        _port_identity(str(value), functions)
        for value in operation["non_authoritative_output_effects"]
    }
    declared_ports = mutation_ports | authority_ports | non_authoritative_ports
    reached: set[tuple[str, str]] = set()
    writes: set[str] = set()
    authority: set[str] = set()
    pending = [entrypoint]
    visited: set[str] = set()
    while pending:
        symbol = pending.pop()
        if symbol in visited:
            continue
        visited.add(symbol)
        function = functions[symbol]
        if function.get("unresolved"):
            raise SemanticOperationEffectError(
                f"operation {operation['id']} contains an unresolved dynamic call path at {symbol}"
            )
        for call in function.get("calls", []):
            raw = str(call.get("called_symbol", ""))
            callee = _resolve_function(raw, functions)
            identity = ("function", callee) if callee is not None else ("call", raw)
            if identity in declared_ports:
                reached.add(identity)
                continue
            name = str(call.get("call_name", ""))
            receiver = raw.rsplit("::", 1)[-1].rsplit(".replace", 1)[0]
            file_replace = name == "replace" and (
                raw.startswith("os::")
                or receiver in {"destination", "path", "staged", "target"}
            )
            shutil_write = name in SHUTIL_WRITE_CALLS and raw.startswith("shutil::")
            unresolved_mutation = callee is None and name.startswith(
                MUTATION_CALL_PREFIXES
            )
            if name in WRITE_CALLS or file_replace or shutil_write or unresolved_mutation:
                writes.add(raw)
            if name.lower().startswith(AUTHORITY_CALL_PREFIXES):
                authority.add(raw)
            # Follow every source-resolved call until a declared effect port.
            # Module boundaries are organizational, not effect boundaries; a
            # query cannot conceal a write in an imported helper.
            if callee is not None:
                pending.append(callee)
    missing = declared_ports - reached
    if missing:
        rendered = ", ".join(sorted(value for _, value in missing))
        raise SemanticOperationEffectError(
            f"operation {operation['id']} declares unreachable effect ports: {rendered}"
        )
    if writes:
        raise SemanticOperationEffectError(
            f"operation {operation['id']} has undeclared write effects: "
            + ", ".join(sorted(writes))
        )
    if authority:
        raise SemanticOperationEffectError(
            f"operation {operation['id']} has undeclared authority effects: "
            + ", ".join(sorted(authority))
        )
    return len(mutation_ports & reached), len(authority_ports & reached)

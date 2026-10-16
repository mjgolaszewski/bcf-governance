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



def source_operation_call_population(
    entrypoint: str, inventory: dict[str, Any], *, include_initialization: bool = False,
) -> dict[str, Any]:
    """Observe discovered Python calls through ports without interpreting effects.

    The protected caller must authenticate parser inputs and their complete scope.
    Module initialization, external/native behavior and dynamic dispatch are not
    qualified here. Unknown calls remain explicit and cannot justify suppression.
    """
    def reject() -> None:
        raise SemanticOperationEffectError("operation source call population is incompatible or ambiguous")

    def digest(value: Any) -> bool:
        return isinstance(value, str) and len(value) == 64 and all(
            character in "0123456789abcdef" for character in value
        )

    if inventory.get("call_contracts_version") != "1.0" or inventory.get("authority") is not False:
        reject()
    functions: dict[str, dict[str, Any]] = {}
    if not isinstance(inventory.get("functions"), list) or not isinstance(inventory.get("files"), list):
        reject()
    for function in inventory["functions"]:
        symbol = function.get("symbol") if isinstance(function, dict) else None
        if not isinstance(symbol, str) or not symbol or symbol in functions:
            reject()
        functions[symbol] = function
    if not isinstance(entrypoint, str) or entrypoint not in functions:
        reject()
    files: dict[str, str] = {}
    for row in inventory.get("files", []):
        path = row.get("path") if isinstance(row, dict) else None
        sha = row.get("sha256") if isinstance(row, dict) else None
        if not isinstance(path, str) or not path or path in files or not digest(sha):
            reject()
        files[path] = sha
    if not files:
        reject()
    calls: list[tuple[str, str, str, int, str]] = []
    identities: set[tuple[str, str, int]] = set()
    visited: set[str] = set()
    pending = [entrypoint]
    while pending:
        caller = pending.pop()
        if caller in visited:
            continue
        visited.add(caller)
        function = functions[caller]
        if caller.partition("::")[0] not in files:
            reject()
        if function.get("language", "python") != "python" or not isinstance(function.get("calls"), list):
            reject()
        for call in function["calls"]:
            if not isinstance(call, dict):
                reject()
            callee = call.get("called_symbol")
            fact = call.get("call_contract")
            if not isinstance(fact, dict):
                reject()
            expression = fact.get("expression_sha256")
            occurrence = fact.get("occurrence")
            if (
                not isinstance(callee, str) or not callee
                or call.get("caller") != caller or fact.get("authority") is not False
                or not digest(expression) or isinstance(occurrence, bool)
                or not isinstance(occurrence, int) or occurrence < 0
            ):
                reject()
            identity = (caller, expression, occurrence)
            if identity in identities:
                reject()
            identities.add(identity)
            resolved = (
                callee in functions and call.get("dispatch_resolution") != "unresolved"
                and call.get("call_name") not in {"__import__", "eval", "exec", "<dynamic>"}
            )
            calls.append((caller, callee, expression, occurrence, "source" if resolved else "unresolved"))
            if resolved:
                pending.append(callee)
    return {
        "authority": False,
        "execution_qualified": False,
        "scope": "discovered_python_functions_only",
        "source_files": tuple(sorted(files.items())),
        "functions": tuple(sorted(visited)),
        "calls": tuple(sorted(calls)),
        "unresolved_calls": sum(row[4] == "unresolved" for row in calls),
    }


def _resolve_function(
    symbol: str, functions: dict[str, dict[str, Any]]
) -> str | None:
    if symbol in functions:
        return symbol
    module, separator, function = symbol.partition("::")
    if not separator:
        return None
    if not module.endswith(".py"):
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


def validated_operation_effect_inventory(
    operation: dict[str, Any],
    entrypoint_symbol: str,
    inventory: dict[str, Any],
    *, source_modules: tuple[str, ...] = (),
) -> tuple[tuple[str, str, str], ...]:
    """Trace and validate effects once, then expose immutable classified ports."""
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
    pending = [entrypoint, *(path + "::<module>" for path in source_modules if path + "::<module>" in functions)]
    visited: set[str] = set()
    while pending:
        symbol = pending.pop()
        if symbol in visited:
            continue
        visited.add(symbol)
        function = functions[symbol]
        if function.get("language") == "typescript":
            module = symbol.split("::", 1)[0] + "::<module>"
            if module in functions and module != symbol:
                pending.append(module)
            for effect in function.get("effects", []):
                target = f"{symbol}:{effect.get('line')}:{effect.get('target')}"
                if effect.get("kind") == "write":
                    writes.add(target)
                elif effect.get("kind") == "authority":
                    authority.add(target)
                else:
                    raise SemanticOperationEffectError(f"operation {operation['id']} contains an unresolved effect at {symbol}")
        if function.get("unresolved"):
            raise SemanticOperationEffectError(
                f"operation {operation['id']} contains an unresolved dynamic call path at {symbol}"
            )
        if any(
            failure.get("port_eligible") is not True
            for failure in function.get("effect_unresolved", [])
        ):
            raise SemanticOperationEffectError(
                f"operation {operation['id']} contains an unresolved effect call path at {symbol}"
            )
        for call in function.get("calls", []):
            raw = str(call.get("called_symbol", ""))
            callee = _resolve_function(raw, functions)
            identity = ("function", callee) if callee is not None else ("call", raw)
            hard_dispatch_failure = (
                call.get("dispatch_resolution") == "unresolved"
                and call.get("dispatch_port_eligible") is not True
            )
            if hard_dispatch_failure:
                raise SemanticOperationEffectError(
                    f"operation {operation['id']} contains an unresolved effect call path at {symbol}"
                )
            if identity in declared_ports:
                reached.add(identity)
                continue
            if call.get("dispatch_resolution") == "unresolved":
                raise SemanticOperationEffectError(
                    f"operation {operation['id']} contains an unresolved effect call path at {symbol}"
                )
            if call.get("language") == "typescript":
                if call.get("effect") == "write":
                    writes.add(raw)
                if call.get("authority_effect") is True:
                    authority.add(raw)
                if callee is not None:
                    pending.append(callee)
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
    return tuple(sorted(
        (classification, target_kind, symbol)
        for classification, ports in (
            ("mutation", mutation_ports), ("authority", authority_ports),
            ("observation", non_authoritative_ports),
        )
        for target_kind, symbol in ports & reached
    ))


def validate_operation_effects(
    operation: dict[str, Any],
    entrypoint_symbol: str,
    inventory: dict[str, Any],
    *, source_modules: tuple[str, ...] = (),
) -> tuple[int, int]:
    """Preserve the existing validator counts and fail-closed effect semantics."""

    ports = validated_operation_effect_inventory(
        operation, entrypoint_symbol, inventory, source_modules=source_modules,
    )
    return (
        sum(classification == "mutation" for classification, _, _ in ports),
        sum(classification == "authority" for classification, _, _ in ports),
    )

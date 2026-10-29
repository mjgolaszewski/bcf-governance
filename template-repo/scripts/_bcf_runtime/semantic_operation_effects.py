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


class _FunctionLookup:
    """Exact literal suffix index owned by one immutable validation inventory."""

    def __init__(self, functions: dict[str, dict[str, Any]]) -> None:
        self._direct = frozenset(functions)
        self._suffixes: dict[tuple[str, str], str | None] = {}
        for candidate in self._direct:
            # The old oracle matches literal suffixes anywhere after '/'. Do
            # not assume a normalized source grammar: even slashes or extra
            # '::' inside a qualified name must preserve its exact behavior.
            starts = [0, *(index + 1 for index, value in enumerate(candidate) if value == "/")]
            for start in starts:
                module, separator, function = candidate[start:].partition("::")
                if not separator or not module.endswith(".py") or "/" in module:
                    continue
                key = (module.removesuffix(".py"), function)
                if key not in self._suffixes:
                    self._suffixes[key] = candidate
                elif self._suffixes[key] != candidate:
                    self._suffixes[key] = None

    def resolve(self, symbol: str) -> str | None:
        if symbol in self._direct:
            return symbol
        module, separator, function = symbol.partition("::")
        if not separator or not module.endswith(".py"):
            return None
        module_name = module.removesuffix(".py").rsplit("/", 1)[-1]
        return self._suffixes.get((module_name, function))


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
    value: str, functions: dict[str, dict[str, Any]],
    *, lookup: _FunctionLookup | None = None,
) -> tuple[str, str]:
    resolved = (_resolve_function(value, functions) if lookup is None
                else lookup.resolve(value))
    return ("function", resolved) if resolved is not None else ("call", value)


def validate_operation_effects(
    operation: dict[str, Any],
    entrypoint_symbol: str,
    inventory: dict[str, Any],
    *, source_modules: tuple[str, ...] = (),
) -> tuple[int, int]:
    """Trace one entrypoint and require all effects to cross declared ports."""
    functions = {
        str(row["symbol"]): row for row in inventory.get("functions", [])
    }
    lookup = _FunctionLookup(functions)
    entrypoint = lookup.resolve(entrypoint_symbol)
    if entrypoint is None:
        raise SemanticOperationEffectError(
            f"operation {operation['id']} entrypoint is absent from the shared source inventory"
        )
    mutation_ports = {
        _port_identity(str(value), functions, lookup=lookup)
        for value in operation["allowed_mutation_ports"]
    }
    authority_ports = {
        _port_identity(str(value), functions, lookup=lookup)
        for value in operation["allowed_authority_ports"]
    }
    non_authoritative_ports = {
        _port_identity(str(value), functions, lookup=lookup)
        for value in operation["non_authoritative_output_effects"]
    }
    read_ports = {
        _port_identity(str(value), functions, lookup=lookup)
        for value in operation.get("allowed_read_ports", [])
    }
    if read_ports and operation.get("authoritative_read") is not True:
        raise SemanticOperationEffectError(
            f"operation {operation['id']} read ports require authoritative_read=true"
        )
    if read_ports & (mutation_ports | authority_ports | non_authoritative_ports):
        raise SemanticOperationEffectError(
            f"operation {operation['id']} read ports overlap another effect category"
        )
    declared_ports = mutation_ports | authority_ports | non_authoritative_ports | read_ports
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
        if function.get("constructor_context_budget_unresolved"):
            raise SemanticOperationEffectError(
                f"operation {operation['id']} contains unresolved constructor context budget at {symbol}"
            )
        for context in function.get("constructor_context_obligations", []):
            if context.get("local_ownership_resolution") == "closed_source_caller_frame":
                continue
            # The side summary is never an identity or purity grant. A declared
            # read/mutation port cannot erase an unknown caller context, and
            # receiver-state stores still need an ownership/effect proof.
            if (context.get("status") != "candidate"
                    or context.get("guards")
                    or context.get("body_effects", {}).get("writes")
                    or context.get("body_effects", {}).get("calls")
                    or context.get("body_effects", {}).get("unsupported")):
                raise SemanticOperationEffectError(
                    f"operation {operation['id']} contains unresolved constructor caller/effect obligations at {symbol}:{context.get('line')}"
                )
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
        if function.get("definition_time_obligations"):
            raise SemanticOperationEffectError(
                f"operation {operation['id']} contains unresolved definition-time effects at {symbol}"
            )
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
            callee = lookup.resolve(raw)
            identity = ("function", callee) if callee is not None else ("call", raw)
            hard_dispatch_failure = (
                call.get("dispatch_resolution") == "unresolved"
                and call.get("dispatch_port_eligible") is not True
            )
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
            known_write = (
                name in WRITE_CALLS or file_replace or shutil_write or unresolved_mutation
                or call.get("effect") == "write"
            )
            known_authority = (
                name.lower().startswith(AUTHORITY_CALL_PREFIXES)
                or call.get("authority_effect") is True
            )
            if hard_dispatch_failure:
                if identity in read_ports and (known_write or known_authority):
                    raise SemanticOperationEffectError(
                        f"operation {operation['id']} read port has a write or authority effect: {raw}"
                    )
                if identity not in declared_ports and (known_write or known_authority):
                    if known_write:
                        writes.add(raw)
                    if known_authority:
                        authority.add(raw)
                    continue
                raise SemanticOperationEffectError(
                    f"operation {operation['id']} contains an unresolved effect call path at {symbol}"
                )
            if identity in read_ports:
                reached.add(identity)
                if known_write or known_authority:
                    raise SemanticOperationEffectError(
                        f"operation {operation['id']} read port has a write or authority effect: {raw}"
                    )
                # A read declaration never conceals a source-resolved body.
                # Unsupported receiver aliases have already failed above.
                if callee is not None:
                    pending.append(callee)
                continue
            if identity in declared_ports:
                reached.add(identity)
                continue
            if (call.get("dispatch_resolution") == "exact_source_literal_default_call"
                    and call.get("literal_default_admission") is True
                    and call.get("literal_default_call_model", {}).get("local_effects_complete") is True):
                # Entire selected body modeled with literal bindings and only
                # fresh container allocations/stores. Result provenance and
                # opaque flags remain on the edge; no generic receiver grant.
                continue
            if (call.get("dispatch_resolution") == "exact_source_fresh_local_context"
                    and call.get("fresh_local_receiver_effects", {}).get("scope") == "closed_source_caller_frame"):
                # The maintained source resolver has summarized the complete
                # literal-store body for THIS fresh caller allocation. Keep
                # its stores as local effects on the edge, not a global purity
                # classification for this callee or a blanket write waiver.
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
            if known_write:
                writes.add(raw)
            if known_authority:
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

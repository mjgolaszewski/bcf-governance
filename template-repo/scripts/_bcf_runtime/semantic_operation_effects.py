"""Call-graph enforcement for declared application-operation effect ports.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import ast
import copy
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



def _additional_source_targets(
    call: dict[str, Any], functions: dict[str, dict[str, Any]]
) -> set[str]:
    """Expand obligations, never turn an annotation or shape into authority."""
    targets: set[str] = set()
    typed = call.get("typed_receiver_observation")
    if isinstance(typed, dict):
        # Neutral candidates cannot clear an existing unresolved dispatch.
        # Only source bodies can add traversal; absent runtime provenance stays
        # explicit in the inventory and is not converted into a purity result.
        targets.update(
            str(value) for value in typed.get("method_candidates", [])
            if str(value) in functions
        )
    construction = call.get("construction_effect_observation")
    if isinstance(construction, dict) and construction.get("source_class_resolved") is True:
        if construction.get("unresolved"):
            raise SemanticOperationEffectError(
                "source construction requires unresolved runtime provenance: "
                + ", ".join(str(value) for value in construction["unresolved"])
            )
        for value in construction.get("function_candidates", []):
            if value not in functions:
                raise SemanticOperationEffectError("construction source body is absent: " + str(value))
            targets.add(str(value))
    return targets

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
    read_ports = {
        _port_identity(str(value), functions)
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
    pending = [(entrypoint, True), *((path + "::<module>", True) for path in source_modules if path + "::<module>" in functions)]
    visited: set[tuple[str, bool]] = set()
    while pending:
        symbol, reachability_credit = pending.pop()
        state = symbol, reachability_credit
        if state in visited:
            continue
        visited.add(state)
        function = functions[symbol]
        if function.get("language") == "typescript":
            module = symbol.split("::", 1)[0] + "::<module>"
            if module in functions and module != symbol:
                pending.append((module, reachability_credit))
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
            if identity in read_ports:
                if reachability_credit:
                    reached.add(identity)
                if known_write or known_authority:
                    raise SemanticOperationEffectError(
                        f"operation {operation['id']} read port has a write or authority effect: {raw}"
                    )
                # A read declaration never conceals a source-resolved body.
                # Unsupported receiver aliases have already failed above.
                pending.extend((target, False) for target in sorted(_additional_source_targets(call, functions)))
                if callee is not None:
                    pending.append((callee, reachability_credit))
                continue
            if identity in declared_ports:
                if reachability_credit:
                    reached.add(identity)
                continue
            if call.get("dispatch_resolution") == "unresolved":
                raise SemanticOperationEffectError(
                    f"operation {operation['id']} contains an unresolved effect call path at {symbol}"
                )
            pending.extend((target, False) for target in sorted(_additional_source_targets(call, functions)))
            if call.get("language") == "typescript":
                if call.get("effect") == "write":
                    writes.add(raw)
                if call.get("authority_effect") is True:
                    authority.add(raw)
                if callee is not None:
                    pending.append((callee, reachability_credit))
                continue
            if known_write:
                writes.add(raw)
            if known_authority:
                authority.add(raw)
            # Follow every source-resolved call until a declared effect port.
            # Module boundaries are organizational, not effect boundaries; a
            # query cannot conceal a write in an imported helper.
            if callee is not None:
                pending.append((callee, reachability_credit))
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


def _sdk_decoder_shape(function: ast.AST) -> tuple[str, str]:
    """Derive lexical call bindings only; a matching shape grants no authority."""
    if not isinstance(function, ast.FunctionDef) or function.decorator_list:
        raise SemanticOperationEffectError("unsupported SDK decoder function shape")
    args = function.args
    parameters = [*args.posonlyargs, *args.args]
    if (len(parameters) != 2 or args.kwonlyargs or args.vararg or args.kwarg
            or args.defaults or args.kw_defaults):
        raise SemanticOperationEffectError("unsupported SDK decoder signature")
    body = list(function.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    if len(body) != 5:
        raise SemanticOperationEffectError("unsupported SDK decoder body")
    guard, token_assignment, identity_assignment, _string_guard, construction = body
    if not (isinstance(guard, ast.If) and isinstance(guard.test, ast.UnaryOp)
            and isinstance(guard.test.op, ast.Not) and isinstance(guard.test.operand, ast.Call)):
        raise SemanticOperationEffectError("SDK type guard absent")
    type_call = guard.test.operand
    if len(type_call.args) != 2 or not isinstance(type_call.args[1], ast.Name):
        raise SemanticOperationEffectError("exact SDK type binding required")
    sdk = type_call.args[1].id
    if not (isinstance(token_assignment, ast.Assign) and len(token_assignment.targets) == 1
            and isinstance(token_assignment.targets[0], ast.Name)):
        raise SemanticOperationEffectError("exact token flow required")
    token = token_assignment.targets[0].id
    if not (isinstance(identity_assignment, ast.Assign) and len(identity_assignment.targets) == 1
            and isinstance(identity_assignment.targets[0], ast.Tuple)
            and len(identity_assignment.targets[0].elts) == 2
            and all(isinstance(item, ast.Name) for item in identity_assignment.targets[0].elts)):
        raise SemanticOperationEffectError("exact tenant/subject flow required")
    tenant_node, subject_node = identity_assignment.targets[0].elts
    assert isinstance(tenant_node, ast.Name) and isinstance(subject_node, ast.Name)
    if not (isinstance(construction, ast.Try) and len(construction.body) == 1
            and isinstance(construction.body[0], ast.Return)
            and isinstance(construction.body[0].value, ast.Call)
            and isinstance(construction.body[0].value.func, ast.Name)):
        raise SemanticOperationEffectError("exact canonical constructor flow required")
    constructor = construction.body[0].value.func.id
    names = [parameters[0].arg, parameters[1].arg, token, tenant_node.id, subject_node.id, sdk, constructor]
    if len(set(names)) != len(names) or set(names) & {"isinstance", "getattr", "str", "ValueError"}:
        raise SemanticOperationEffectError("shadowed decoder bindings")
    renamed = dict(zip(names, ["_self", "_user", "_token", "_tenant", "_subject", "_SDK", "_Owner"], strict=True))

    class Normalize(ast.NodeTransformer):
        def visit_Name(self, node: ast.Name) -> ast.AST:  # noqa: N802
            return ast.copy_location(ast.Name(id=renamed.get(node.id, node.id), ctx=node.ctx), node)

    observed = Normalize().visit(copy.deepcopy(ast.Module(body=body, type_ignores=[])))
    expected = ast.parse("""
if not isinstance(_user, _SDK):
    return None
_token = _user.access_token
_tenant, _subject = getattr(_token, "tenant_id", None), getattr(_token, "principal_id", None)
if not isinstance(_tenant, str) or not isinstance(_subject, str):
    return None
try:
    return _Owner(_tenant, _subject)
except ValueError:
    return None
""")
    if ast.dump(observed, include_attributes=False) != ast.dump(expected, include_attributes=False):
        raise SemanticOperationEffectError("unsupported SDK decoder dataflow or effect")
    return sdk, constructor

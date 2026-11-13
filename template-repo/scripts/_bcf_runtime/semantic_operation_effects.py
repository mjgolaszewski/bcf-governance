"""Call-graph enforcement for declared application-operation effect ports.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

from typing import Any, cast

from .semantic_python_value_origins import value_origins

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


def validate_operation_effects(
    operation: dict[str, Any],
    entrypoint_symbol: str,
    inventory: dict[str, Any],
    *, source_modules: tuple[str, ...] = (), unresolved_dynamic_policy: str = "fail_closed",
    _origin_cache: dict[tuple[int, str, tuple[tuple[str, str], ...]], dict[str, Any]] | None = None,
) -> tuple[int, int]:
    """Trace one entrypoint and require all effects to cross declared ports."""
    if unresolved_dynamic_policy not in {'report', 'fail_closed'}:
        raise SemanticOperationEffectError('unsupported unresolved dynamic policy')
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
    pending: list[tuple[str, tuple[tuple[str, str], ...], bool]] = [(entrypoint, (), False), *((path + "::<module>", (), False) for path in source_modules if path + "::<module>" in functions)]
    visited: set[tuple[str, tuple[tuple[str, str], ...], bool]] = set()
    # The function-name population is fixed for this one fresh validation.
    # Reuse only lookup answers, never source observations or acceptance results.
    resolved_calls: dict[str, str | None] = {}
    diagnostics: list[str] = []
    diagnostic_count = 0

    def reject(message: str) -> None:
        nonlocal diagnostic_count
        diagnostic_count += 1
        # Keep ordinary validation output bounded even for a large source graph.
        # Every failure still prevents acceptance, including omitted details.
        if len(diagnostics) < 32:
            diagnostics.append(message[:2048])

    origin_cache = {} if _origin_cache is None else _origin_cache
    while pending:
        symbol, arguments, callback_required = pending.pop()
        if (symbol, arguments, callback_required) in visited:
            continue
        visited.add((symbol, arguments, callback_required))
        function = functions[symbol]
        report_new = unresolved_dynamic_policy == 'report'
        def report_observation(kind: str, line: object, target: object = '', symbol: str = symbol) -> None:
            observation = {'kind': kind, 'symbol': symbol, 'line': line,
                           'target': target, 'operation': operation['id'], 'qualified': False}
            if observation not in inventory.setdefault('unresolved', []):
                inventory['unresolved'].append(observation)
        # Neutral frame facts are independent of ports and operation policy.
        # The caller owns this bounded cache for one fixed inventory only.
        origin_key = (id(inventory), symbol, arguments)
        origins = origin_cache.get(origin_key)
        if origins is None:
            origins = value_origins(symbol, functions, arguments)
            if len(origin_cache) < 8192:
                origin_cache[origin_key] = origins
        contextual_sites = {
            (call.get('line'), call.get('called_symbol')) for call in function.get('calls', [])
            if (call.get('line'), call.get('column')) in origins['contextual_calls']
            or (call.get('line'), call.get('column')) in origins.get('native_reads', {})
        }

        frame_context: dict[str, Any] = origins

        def caller_arguments(call: dict[str, Any], context: dict[str, Any] = frame_context) -> tuple[tuple[str, str], ...]:
            frame = call.get('constructor_frame_origin')
            if frame:
                return cast(tuple[tuple[str, str], ...], context['implicit_calls'].get((frame['line'], frame['column'], frame['target']), ()))
            return cast(tuple[tuple[str, str], ...], context['calls'].get((call.get('line'), call.get('column')), ()))

        if origins.get('initializer_protocol_unknown'):
            if unresolved_dynamic_policy == 'report':
                report_observation('unqualified_initializer_runtime_protocol', 0)
            else:
                reject(
                    f"operation {operation['id']} contains an unqualified initializer runtime protocol at {symbol}"
                )
        if function.get("language") == "typescript":
            module = symbol.split("::", 1)[0] + "::<module>"
            if module in functions and module != symbol:
                pending.append((module, (), callback_required))
        for effect in function.get("effects", []):
            target = f"{symbol}:{effect.get('line')}:{effect.get('target')}"
            if effect.get("kind") == "write":
                if (effect.get("line"), effect.get("target")) not in origins["writes"]:
                    legacy = [effect.get('kind'), effect.get('line'), effect.get('target')]
                    root = str(effect.get('target', '')).split('.', 1)[0].split('[', 1)[0]
                    if (unresolved_dynamic_policy == 'report' and 'legacy_effect_sites' in function
                            and legacy not in function['legacy_effect_sites']
                            and root not in function.get('external_write_roots', [])
                            and (not callback_required or root in function.get('lexically_allocated_containers', [])
                                 or root == 'self' and symbol.endswith('.__init__'))):
                        report_observation('unqualified_container_ownership', effect.get('line'), effect.get('target'))
                    else:
                        writes.add(target)
            elif effect.get("kind") == "authority":
                authority.add(target)
            else:
                reject(f"operation {operation['id']} contains an unresolved effect at {symbol}")
        resolved_mutator_sites = {(call.get('line'), call.get('column'))
            for call in function.get('calls', [])
            if _resolve_function(str(call.get('called_symbol', '')), functions) is not None}
        remaining_obligations = [item for item in function.get('implicit_effect_obligations', [])
            if not (item.get('binding_source') == 'constructor_initializer_frame' and
                    (item.get('line'), item.get('column'), item.get('class_symbol'))
                    in origins['constructor_inputs'])
            and not (item.get('kind') == 'unqualified_generated_copy_binding' and
                     (item.get('line'), item.get('column'), item.get('class_symbol')) in origins.get('generated_copies', set()))
            and not (item.get('kind') == 'unqualified_attribute_mutator' and
                     (item.get('line'), item.get('column')) in resolved_mutator_sites)
            and not (item.get('kind') == 'unqualified_format_callback' and
                     (item.get('line'), item.get('column')) in origins['format_inputs'])]
        if report_new:
            for item in remaining_obligations:
                report_observation(str(item.get('kind')), item.get('line'), item.get('class_symbol', ''))
            remaining_obligations = []
        if remaining_obligations:
            obligations = ", ".join(
                f"{item.get('kind')}:{item.get('class_symbol', '')}:{item.get('line')}"
                for item in remaining_obligations
            )
            reject(
                f"operation {operation['id']} contains unqualified implicit execution at {symbol}: {obligations}"
            )
        if any((item.get('line'), item.get('called_symbol')) not in contextual_sites
               for item in function.get('unresolved', [])):
            if report_new and callback_required:
                report_observation('unresolved_callback_execution', 0)
            else:
                reject(
                    f"operation {operation['id']} contains an unresolved dynamic call path at {symbol}"
                )
        if any(
            failure.get("port_eligible") is not True
            and (failure.get('line'), failure.get('called_symbol')) not in contextual_sites
            for failure in function.get("effect_unresolved", [])
        ):
            if report_new and callback_required:
                report_observation('unresolved_callback_execution', 0)
            else:
                reject(
                    f"operation {operation['id']} contains an unresolved effect call path at {symbol}"
                )
        for call in function.get("calls", []):
            if (call.get('line'), call.get('column')) in origins.get('native_reads', {}):
                # Proven exact native receiver/argument protocols are reads.
                # Preserve the neutral call identity; this proof neither
                # fabricates a callee nor reaches a declared source port.
                continue
            contextual = origins['contextual_calls'].get((call.get('line'), call.get('column')))
            raw = str(contextual or call.get("called_symbol", ""))
            if raw not in resolved_calls:
                resolved_calls[raw] = _resolve_function(raw, functions)
            callee = resolved_calls[raw]
            identity = ("function", callee) if callee is not None else ("call", raw)
            hard_dispatch_failure = (
                call.get("dispatch_resolution") == "unresolved"
                and call.get("dispatch_port_eligible") is not True
                and contextual is None
            )
            if hard_dispatch_failure:
                if report_new and callback_required:
                    report_observation('unresolved_callback_dispatch', call.get('line'), raw)
                else:
                    reject(
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
                reached.add(identity)
                if known_write or known_authority:
                    reject(
                        f"operation {operation['id']} read port has a write or authority effect: {raw}"
                    )
                # A read declaration never conceals a source-resolved body.
                # Unsupported receiver aliases have already failed above.
                if callee is not None:
                    pending.append((callee, caller_arguments(call), callback_required or bool(call.get("implicit_callback"))))
                continue
            if identity in declared_ports:
                reached.add(identity)
                continue
            if call.get("dispatch_resolution") == "unresolved" and contextual is None:
                if report_new and callback_required:
                    report_observation('unresolved_callback_dispatch', call.get('line'), raw)
                else:
                    reject(
                        f"operation {operation['id']} contains an unresolved effect call path at {symbol}"
                    )
            if call.get("language") == "typescript":
                if call.get("effect") == "write":
                    writes.add(raw)
                if call.get("authority_effect") is True:
                    authority.add(raw)
                if callee is not None:
                    pending.append((callee, (), callback_required))
                continue
            if known_write:
                writes.add(raw)
            if known_authority:
                authority.add(raw)
            # Follow every source-resolved call until a declared effect port.
            # Module boundaries are organizational, not effect boundaries; a
            # query cannot conceal a write in an imported helper.
            if callee is not None:
                pending.append((callee, caller_arguments(call), callback_required or bool(call.get("implicit_callback"))))
    missing = declared_ports - reached
    if missing:
        rendered = ", ".join(sorted(value for _, value in missing))
        reject(
            f"operation {operation['id']} declares unreachable effect ports: {rendered}"
        )
    if writes:
        reject(
            f"operation {operation['id']} has undeclared write effects: "
            + ", ".join(sorted(writes))
        )
    if authority:
        reject(
            f"operation {operation['id']} has undeclared authority effects: "
            + ", ".join(sorted(authority))
        )
    if diagnostics:
        omitted = diagnostic_count - len(diagnostics)
        suffix = f"; {omitted} additional failure observations omitted" if omitted else ""
        raise SemanticOperationEffectError("; ".join(diagnostics) + suffix)
    return len(mutation_ports & reached), len(authority_ports & reached)

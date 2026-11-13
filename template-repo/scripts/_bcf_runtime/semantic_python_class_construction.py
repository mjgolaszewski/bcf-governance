"""Source-bound classmethod forwarding without changing the requested class.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

from typing import Any


def _implementation(bound: str, method: str, classes: dict[str, dict[str, Any]]) -> str | None:
    visited = set()
    while bound in classes and bound not in visited:
        visited.add(bound)
        row = classes[bound]
        if not row.get('local_class_binding'):
            return None
        definitions = [value for value in row.get('methods', []) if value['name'] == method]
        if definitions:
            value = definitions[0]
            return str(value['symbol']) if len(definitions) == 1 and value.get('binding') == 'class' and value.get('decorators') == ['classmethod'] else None
        bases = row.get('bases', [])
        if len(bases) != 1:
            return None
        bound = str(bases[0].get('called_symbol', ''))
    return None


def class_constructor_bindings(
    function: dict[str, Any], classes: dict[str, dict[str, Any]],
    calls: list[tuple[dict[str, Any], int, dict[str, Any]]],
    all_calls: dict[str, list[tuple[dict[str, Any], int, dict[str, Any]]]],
    active: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    symbol = str(function['symbol'])
    if symbol in active:
        return []
    method = symbol.rsplit('.', 1)[-1]
    result = []
    for caller, occurrence, call in calls:
        bound, _, called_method = str(call.get('called_symbol', '')).rpartition('.')
        reference = call.get('method_dispatch')
        bounds = [str(call.get('bound_class_receiver', bound))]
        if isinstance(reference, dict):
            called_method = str(reference.get('method', ''))
            if (reference.get('kind') == 'class_or_static_receiver'
                    and reference.get('standard_classmethod') and not reference.get('receiver_rebound')):
                outer = class_constructor_bindings(caller, classes,
                    all_calls.get(str(caller['symbol']).rsplit('.', 1)[-1], []), all_calls, active | {symbol})
                bounds = sorted({str(value['constructed_symbol']) for value in outer})
            else:
                declared = str(reference.get('class_symbol', ''))
                if _implementation(declared, called_method, classes) == symbol:
                    failure = {'kind': 'unresolved_class_constructor', 'symbol': caller['symbol'],
                        'line': call.get('line'), 'called_symbol': call.get('called_symbol'),
                        'factory_implementation': symbol}
                    if failure not in caller.setdefault('unresolved', []):
                        caller['unresolved'].append(failure)
                    call['dispatch_resolution'] = 'unresolved'
                    call['dispatch_port_eligible'] = False
                bounds = []
        if called_method != method:
            continue
        for actual in bounds:
            implementation = _implementation(actual, method, classes)
            if implementation == symbol:
                result.append({'constructed_symbol': actual, 'binding_caller': caller['symbol'],
                    'binding_line': call.get('line'), 'binding_occurrence': occurrence,
                    'factory_implementation': symbol})
            elif implementation is None and actual in classes:
                failure = {'kind': 'unresolved_class_constructor', 'symbol': caller['symbol'],
                    'line': call.get('line'), 'called_symbol': call.get('called_symbol'),
                    'factory_implementation': symbol}
                if failure not in caller.setdefault('unresolved', []):
                    caller['unresolved'].append(failure)
                call['dispatch_resolution'] = 'unresolved'
                call['dispatch_port_eligible'] = False
    return result


def resolve_class_receiver_forwarding(
    functions: dict[str, dict[str, Any]], classes: dict[str, dict[str, Any]],
    all_calls: dict[str, list[tuple[dict[str, Any], int, dict[str, Any]]]],
) -> None:
    for caller in functions.values():
        for call in caller.get('calls', []):
            if call.get('method_dispatch'):
                continue
            bound, _, method = str(call.get('called_symbol', '')).rpartition('.')
            target = _implementation(bound, method, classes)
            if target is not None:
                call['bound_class_receiver'] = bound
                call['called_symbol'] = target
                call['dispatch_resolution'] = 'exact_bound_class_method'
    by_method: dict[str, list[dict[str, Any]]] = {}
    for function in functions.values():
        if function.get('class_symbol'):
            by_method.setdefault(str(function['symbol']).rsplit('.', 1)[-1], []).append(function)
    for caller in functions.values():
        for occurrence, call in enumerate(caller.get('calls', [])):
            reference = call.get('method_dispatch', {})
            if (reference.get('kind') != 'class_or_static_receiver'
                    or not reference.get('standard_classmethod') or reference.get('receiver_rebound')):
                continue
            targets = set()
            for candidate in by_method.get(str(reference.get('method', '')), []):
                if class_constructor_bindings(candidate, classes, [(caller, occurrence, call)], all_calls):
                    targets.add(str(candidate['symbol']))
            if len(targets) == 1:
                call['called_symbol'] = next(iter(targets))
                call['dispatch_resolution'] = 'exact_bound_class_forwarding'

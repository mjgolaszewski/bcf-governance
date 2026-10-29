"""Source-derived local ownership for a deliberately closed execution subset."""
from __future__ import annotations

import ast
from collections.abc import Callable
from typing import Any

from .semantic_python_result_identity import _Results


def _receiver_stores(node: ast.FunctionDef) -> list[dict[str, Any]] | None:
    args = node.args
    if (node.decorator_list or getattr(node, 'type_params', [])
            or len(args.args) != 1 or args.posonlyargs or args.kwonlyargs
            or args.defaults or args.kw_defaults or args.vararg or args.kwarg
            or args.args[0].annotation is not None or node.returns is not None):
        return None
    receiver = args.args[0].arg
    stores = []
    for statement in node.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            return None
        target = statement.targets[0]
        if (not isinstance(target, ast.Attribute) or not isinstance(target.value, ast.Name)
                or target.value.id != receiver or target.attr.startswith('__')
                or not isinstance(statement.value, ast.Constant)
                or type(statement.value.value) not in {type(None), bool, int, float, str, bytes}):
            return None
        stores.append({'kind': 'receiver_state_write', 'line': statement.lineno,
                       'attribute': target.attr, 'value_AST': ast.unparse(statement.value)})
    return stores or None


def resolve_fresh_local_contexts(
    inventory: dict[str, Any], trees: dict[str, ast.Module], *,
    reference: Callable[[str, str], str | None],
) -> None:
    """Discharge only local ownership; never grant generic method purity."""
    guarded = _Results(inventory, reference)
    functions = {str(row['symbol']): row for row in inventory.get('functions', [])}
    for path, tree in trees.items():
        # Exclude imports, assignments, extra definitions and implicit module
        # callbacks from this first positive. Other modules still participate
        # in the maintained cohort mutation/escape guards above.
        if len(tree.body) != 2:
            continue
        cls, caller = tree.body
        if (not isinstance(cls, ast.ClassDef) or not isinstance(caller, ast.FunctionDef)
                or cls.bases or cls.keywords or cls.decorator_list or getattr(cls, 'type_params', [])
                or caller.decorator_list or caller.returns is not None
                or getattr(caller, 'type_params', []) or len(caller.body) != 2
                or any((caller.args.args, caller.args.posonlyargs, caller.args.kwonlyargs,
                        caller.args.defaults, caller.args.kw_defaults, caller.args.vararg, caller.args.kwarg))):
            continue
        assignment, invocation = caller.body
        if (not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1
                or not isinstance(assignment.targets[0], ast.Name)
                or not isinstance(assignment.value, ast.Call)
                or not isinstance(assignment.value.func, ast.Name)
                or assignment.value.args or assignment.value.keywords
                or not isinstance(invocation, ast.Expr) or not isinstance(invocation.value, ast.Call)):
            continue
        call = invocation.value
        if (not isinstance(call.func, ast.Attribute) or not isinstance(call.func.value, ast.Name)
                or call.func.value.id != assignment.targets[0].id or call.args or call.keywords):
            continue
        class_symbol = reference(path, assignment.value.func.id)
        if class_symbol is None or class_symbol != path + '::' + cls.name:
            continue
        method_name = call.func.attr
        if method_name.startswith('__') or len(cls.body) != 2:
            continue
        methods = {n.name: n for n in cls.body if isinstance(n, ast.FunctionDef)}
        if set(methods) != {'__init__', method_name}:
            continue
        initializer = guarded.method(class_symbol, '__init__')
        method = guarded.method(class_symbol, method_name)
        if initializer is None or method is None:
            continue
        init_stores = _receiver_stores(methods['__init__'])
        method_stores = _receiver_stores(methods[method_name])
        if (init_stores is None or method_stores is None
                or not {r['attribute'] for r in method_stores} <= {r['attribute'] for r in init_stores}):
            continue
        symbol = path + '::' + caller.name
        function = functions.get(symbol)
        if function is None or function.get('unresolved') or function.get('constructor_context_budget_unresolved'):
            continue
        obligations = function.get('constructor_context_obligations', [])
        if len(obligations) != 1:
            continue
        obligation = obligations[0]
        if (obligation['source_target'] != method or obligation['status'] != 'candidate'
                or obligation['guards'] or obligation['body_effects']['calls']
                or obligation['body_effects']['unsupported']):
            continue
        selected = []
        for node, name, target, stores in (
            (assignment.value, cls.name, initializer, init_stores),
            (call, method_name, method, method_stores),
        ):
            matches = [r for r in function.get('calls', [])
                       if r.get('line') == node.lineno and r.get('call_name') == name
                       and not r.get('descriptor_access')]
            if len(matches) != 1:
                break
            selected.append((matches[0], node, target, stores))
        if len(selected) != 2:
            continue
        markers = {(r.get('line'), r.get('called_symbol')) for r, _, _, _ in selected}
        failures = function.get('effect_unresolved', [])
        removable = [r for r in failures if r.get('kind') == 'unproven_result_receiver'
                     and (r.get('line'), r.get('called_symbol')) in markers]
        if len(removable) != len(failures):
            continue  # Never clear a different maintained resolver refusal.
        allocation = {'caller': symbol, 'line': assignment.value.lineno,
                      'column': assignment.value.col_offset, 'source_class': class_symbol}
        for edge, node, target, stores in selected:
            edge.update(called_symbol=target, source_column=node.col_offset,
                        dispatch_resolution='exact_source_fresh_local_context',
                        dispatch_port_eligible=False,
                        fresh_local_receiver_effects={'allocation': allocation, 'writes': stores,
                                                      'return_fact': 'fallthrough_none',
                                                      'scope': 'closed_source_caller_frame'})
        function['effect_unresolved'] = []  # Only exact matched refusals above.
        obligation['local_ownership_resolution'] = 'closed_source_caller_frame'
        function['fresh_local_receiver_effects'] = {
            'allocation': allocation, 'initializer_writes': init_stores,
            'method_writes': method_stores, 'escape': False,
            'native_or_runtime_receipt_authority': False,
        }

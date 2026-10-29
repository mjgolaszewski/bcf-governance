"""Join complete literal-default body models without waiving caller guards."""
from __future__ import annotations

import ast
import copy
from collections.abc import Callable, Iterator
from typing import Any

from .semantic_python_literal_call_model import UnsupportedLiteralCall, model_literal_call
from .semantic_python_result_identity import _Results


def _body_calls(node: ast.AST) -> Iterator[ast.Call]:
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(child, ast.Call):
            yield child
        yield from _body_calls(child)


def _closed_caller(node: ast.FunctionDef | ast.AsyncFunctionDef, call: ast.Call) -> bool:
    args = node.args
    if (isinstance(node, ast.AsyncFunctionDef) or node.decorator_list or node.returns is not None
            or args.args or args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg
            or getattr(node, 'type_params', []) or len(node.body) != 1):
        return False
    statement = node.body[0]
    return isinstance(statement, (ast.Return, ast.Expr)) and statement.value is call


def retain_literal_default_contexts(
    inventory: dict[str, Any], trees: dict[str, ast.Module], *,
    reference: Callable[[str, str], str | None],
) -> None:
    guarded = _Results(inventory, reference)
    targets = {path + '::' + node.name: node for path, tree in trees.items()
               for node in tree.body if isinstance(node, ast.FunctionDef)}
    functions = {str(row['symbol']): row for row in inventory.get('functions', [])}
    for path, tree in trees.items():
        population: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = [
            (node.name, node) for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        population += [(cls.name + '.' + node.name, node) for cls in tree.body if isinstance(cls, ast.ClassDef)
                       for node in cls.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for name, caller in population:
            symbol = path + '::' + name
            function = functions.get(symbol)
            if function is None:
                continue
            local_names = {n.arg for n in [*caller.args.args, *caller.args.posonlyargs, *caller.args.kwonlyargs]}
            local_names.update(n.id for statement in caller.body for n in ast.walk(statement)
                               if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store))
            for statement in caller.body:
                for syntax in _body_calls(statement):
                    if not isinstance(syntax.func, ast.Name) or syntax.func.id in local_names:
                        continue
                    target = reference(path, syntax.func.id)
                    callee = targets.get(str(target))
                    if callee is None or not (callee.args.defaults or any(d is not None for d in callee.args.kw_defaults)
                                              or any(isinstance(n, ast.Dict) for n in ast.walk(callee))):
                        continue
                    matches = [r for r in function.get('calls', []) if r.get('line') == syntax.lineno
                               and r.get('call_name') == syntax.func.id and not r.get('descriptor_access')]
                    if len(matches) != 1:
                        for edge in matches:
                            edge['dispatch_resolution'] = 'unresolved'
                            edge['dispatch_port_eligible'] = False
                        continue
                    edge = matches[0]
                    try:
                        model = model_literal_call(callee, syntax)
                        edge['literal_default_call_model'] = model
                        reason = ('caller_context_not_closed' if not _closed_caller(caller, syntax)
                                  else 'maintained_binding_guard' if target not in guarded.ordinary
                                  else 'preserved_dispatch_refusal' if edge.get('dispatch_resolution') == 'unresolved'
                                  else '')
                    except (UnsupportedLiteralCall, KeyError) as exc:
                        reason = str(exc)
                    if reason:
                        if reason == 'maintained_binding_guard':
                            edge['literal_default_binding_obligations'] = {
                                'source_target': target, 'permits_acceptance': False,
                                'whole_cohort_guards': copy.deepcopy(guarded.binding_guard_obligations),
                            }
                        edge['literal_default_admission'] = False
                        edge['literal_default_refusal'] = reason
                        edge['dispatch_resolution'] = 'unresolved'
                        edge['dispatch_port_eligible'] = False
                        function.setdefault('effect_unresolved', []).append({
                            'kind': 'unproven_literal_default_context', 'symbol': symbol,
                            'called_symbol': edge.get('called_symbol'), 'line': syntax.lineno,
                            'column': syntax.col_offset, 'port_eligible': False, 'reason': reason})
                        continue
                    edge['called_symbol'] = target
                    edge['dispatch_resolution'] = 'exact_source_literal_default_call'
                    edge['dispatch_port_eligible'] = False
                    edge['literal_default_admission'] = True

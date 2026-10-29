"""Bounded source interpretation of literal arguments and owned containers.

No application code is imported or executed. Values below belong to the model.
"""
from __future__ import annotations

import ast
import copy
import hashlib
from typing import Any


class UnsupportedLiteralCall(ValueError):
    """The entire selected source call cannot be modeled in this subset."""


def _scalar(node: ast.expr) -> Any:
    if isinstance(node, ast.Constant) and type(node.value) in {type(None), bool, int, float, str}:
        return node.value
    raise UnsupportedLiteralCall('nonliteral_argument_or_default')


def bind_literal_arguments(function: ast.FunctionDef, call: ast.Call) -> dict[str, Any]:
    args = function.args
    if function.decorator_list or args.vararg or args.kwarg or getattr(function, 'type_params', []):
        raise UnsupportedLiteralCall('unsupported_signature')
    positional = [*args.posonlyargs, *args.args]
    names = [n.arg for n in positional]
    all_names = names + [n.arg for n in args.kwonlyargs]
    defaults: dict[str, ast.expr | None] = {n.arg: d for n, d in zip(positional[-len(args.defaults):] if args.defaults else [], args.defaults, strict=True)}
    defaults.update({n.arg: d for n, d in zip(args.kwonlyargs, args.kw_defaults, strict=True)})
    for value in defaults.values():
        if value is not None:
            _scalar(value)  # Never conceal a nonliteral definition-time default.
    if len(call.args) > len(names):
        raise UnsupportedLiteralCall('excess_positional_arguments')
    bound = {name: {'value': _scalar(value), 'source': 'explicit_positional', 'parameter': name}
             for name, value in zip(names, call.args, strict=False)}
    for keyword in call.keywords:
        name = keyword.arg
        if (name is None or name in bound or name not in all_names
                or name in {n.arg for n in args.posonlyargs}):
            raise UnsupportedLiteralCall('duplicate_unknown_or_expanded_keyword')
        bound[name] = {'value': _scalar(keyword.value), 'source': 'explicit_keyword', 'parameter': name}
    for name in all_names:
        if name not in bound:
            value = defaults.get(name)
            if value is None:
                raise UnsupportedLiteralCall('missing_required_argument:' + name)
            bound[name] = {'value': _scalar(value), 'source': 'omitted_default', 'parameter': name,
                           'default_AST': ast.unparse(value)}
    return bound


class _Model:
    def __init__(self, bindings: dict[str, Any]) -> None:
        self.env: dict[str, tuple[Any, dict[str, Any]]] = {
            name: (row['value'], dict(row)) for name, row in bindings.items()}
        self.owned: set[int] = set()
        self.effects: list[dict[str, Any]] = []
        self.branches: list[dict[str, Any]] = []
        self.remaining = 256

    def expression(self, node: ast.expr) -> tuple[Any, dict[str, Any]]:
        self.remaining -= 1
        if self.remaining < 0:
            raise UnsupportedLiteralCall('expression_budget')
        if isinstance(node, ast.Constant):
            return _scalar(node), {'source': 'body_literal', 'line': node.lineno, 'value': _scalar(node)}
        if isinstance(node, ast.Name) and node.id in self.env:
            return self.env[node.id]
        if isinstance(node, ast.Dict):
            value: dict[str, Any] = {}
            fields: dict[str, Any] = {}
            for key, expression in zip(node.keys, node.values, strict=True):
                if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                    raise UnsupportedLiteralCall('nonliteral_or_expanded_dictionary_key')
                item, provenance = self.expression(expression)
                if type(item) not in {type(None), bool, int, float, str}:
                    raise UnsupportedLiteralCall('non_scalar_dictionary_value')
                value[key.value], fields[key.value] = item, provenance
            self.owned.add(id(value))
            self.effects.append({'kind': 'local_dict_allocation', 'line': node.lineno})
            return value, {'kind': 'dict', 'ownership': 'fresh_local', 'fields': fields}
        if isinstance(node, ast.List):
            values, elements = [], []
            for expression in node.elts:
                value, provenance = self.expression(expression)
                if type(value) not in {type(None), bool, int, float, str} and id(value) not in self.owned:
                    raise UnsupportedLiteralCall('external_container_escape')
                values.append(value)
                elements.append(provenance)
            self.owned.add(id(values))
            self.effects.append({'kind': 'local_list_allocation', 'line': node.lineno})
            return values, {'kind': 'list', 'ownership': 'fresh_local', 'elements': elements}
        raise UnsupportedLiteralCall('unsupported_expression:' + type(node).__name__)

    def block(self, statements: list[ast.stmt]) -> tuple[Any, dict[str, Any]] | None:
        for node in statements:
            self.remaining -= 1
            if self.remaining < 0:
                raise UnsupportedLiteralCall('statement_budget')
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                continue
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if len(targets) != 1 or node.value is None:
                    raise UnsupportedLiteralCall('unsupported_assignment')
                value, provenance = self.expression(node.value)
                target = targets[0]
                if isinstance(target, ast.Name):
                    self.env[target.id] = (value, provenance)
                elif (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                      and isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str)):
                    container, container_provenance = self.env[target.value.id]
                    if (type(container) is not dict or id(container) not in self.owned
                            or type(value) not in {type(None), bool, int, float, str}):
                        raise UnsupportedLiteralCall('unowned_or_recursive_store')
                    container[target.slice.value] = value
                    container_provenance['fields'][target.slice.value] = provenance
                    self.effects.append({'kind': 'local_container_write', 'line': node.lineno,
                                         'key': target.slice.value, 'value_provenance': provenance})
                else:
                    raise UnsupportedLiteralCall('nonlocal_store')
            elif isinstance(node, ast.If):
                value, provenance = self.expression(node.test)
                if type(value) is not bool:
                    raise UnsupportedLiteralCall('opaque_condition')
                self.branches.append({'line': node.lineno, 'taken': value, 'condition_provenance': provenance})
                result = self.block(node.body if value else node.orelse)
                if result is not None:
                    return result
            elif isinstance(node, ast.Return) and node.value is not None:
                return self.expression(node.value)
            else:
                raise UnsupportedLiteralCall('unsupported_statement:' + type(node).__name__)
        return None


def literal_context_applicable(function: ast.FunctionDef) -> bool:
    """Select the literal subset without erasing any source-store obligation.

    This is analysis applicability, never a call or effect grant. Unsupported
    ordinary bodies retain their original resolver facts and transitive walk.
    Unsafe stores, definition defaults, suspensions and exhausted scope remain
    candidates so their existing hard refusal cannot be bypassed.
    """
    defaults = [*function.args.defaults,
                *[value for value in function.args.kw_defaults if value is not None]]
    for value in defaults:
        if not isinstance(value, ast.Constant) or type(value.value) not in {type(None), bool, int, float, str}:
            return True
    supported = (ast.Expr, ast.Constant, ast.Name, ast.Load, ast.Store, ast.Dict,
                 ast.List, ast.Assign, ast.AnnAssign, ast.Subscript, ast.If, ast.Return)
    ordinary_body = False
    count = 0
    for statement in function.body:
        for node in ast.walk(statement):
            count += 1
            if count > 4096:
                return True
            if isinstance(node, (ast.Global, ast.Nonlocal, ast.Yield, ast.YieldFrom,
                                 ast.Await, ast.Lambda, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef, ast.AugAssign, ast.Delete)):
                return True
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if not isinstance(target, ast.Name):
                        return True
            if not isinstance(node, supported):
                ordinary_body = True
    return not ordinary_body


def model_literal_call(function: ast.FunctionDef, call: ast.Call) -> dict[str, Any]:
    if not literal_context_applicable(function):
        raise UnsupportedLiteralCall('callee_outside_literal_subset')
    if sum(1 for _ in ast.walk(function)) > 256:
        raise UnsupportedLiteralCall('function_node_budget')
    if any(isinstance(n, (ast.Global, ast.Nonlocal, ast.Yield, ast.YieldFrom, ast.Await,
                          ast.Lambda, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
           for statement in function.body for n in ast.walk(statement)):
        raise UnsupportedLiteralCall('compile_time_scope_or_suspension_obligation')
    bindings = bind_literal_arguments(function, call)
    model = _Model(bindings)
    result = model.block(function.body)
    if result is None:
        raise UnsupportedLiteralCall('missing_explicit_return')
    value, provenance = result
    if type(value) not in {type(None), bool, int, float, str} and id(value) not in model.owned:
        raise UnsupportedLiteralCall('unowned_return')
    return copy.deepcopy({'bindings': bindings, 'result_value': value, 'result_provenance': provenance,
                          'effects': model.effects, 'branches': model.branches,
                          'local_effects_complete': True, 'external_effects': [],
                          'callee_AST_sha256': hashlib.sha256(ast.dump(function, include_attributes=False).encode()).hexdigest(),
                          'runtime_or_native_authority': False})

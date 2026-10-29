"""Neutral AST return and local-flow facts; never receiver or effect authority.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

import ast
import copy
import json
from typing import Any

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_LIMIT = 64


def _contains_opaque_input(rows: Any) -> bool:
    pending = [rows]
    count = 0
    while pending:
        item = pending.pop()
        count += 1
        if count > 512:
            return True
        if isinstance(item, dict):
            if item.get("kind") in {"parameter", "self"} or item.get("opaque_parameter") is True:
                return True
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return False


def _unknown(reason: str, opaque: bool = False) -> list[dict[str, Any]]:
    row: dict[str, Any] = {"kind": "unknown", "reason": reason}
    if opaque:
        row["opaque_parameter"] = True
    return [row]


def _union(values: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    unique = {json.dumps(row, sort_keys=True): row for group in values for row in group}
    if len(unique) > _LIMIT:
        return _unknown("alternative_limit", _contains_opaque_input(values))
    return [unique[key] for key in sorted(unique)]


def _owned(node: ast.AST) -> list[ast.AST]:
    result = [node]
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (*_FUNCTIONS, ast.ClassDef, ast.Lambda)):
            result.append(child)
        else:
            result.extend(_owned(child))
    return result


def _value_names(node: ast.AST) -> set[str]:
    children: list[ast.AST]
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Call):
        children = [*node.args, *(keyword.value for keyword in node.keywords)]
    else:
        children = list(ast.iter_child_nodes(node))
    return {name for child in children for name in _value_names(child)}


class _Flow:
    def __init__(self, node: ast.FunctionDef | ast.AsyncFunctionDef,
                 *, path: str, class_name: str | None, classes: set[str]) -> None:
        self.node = node
        self.path = path
        self.classes = classes
        self.class_name = class_name
        self.parameters = [argument.arg for argument in
                           [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]]
        self.parameters.extend(argument.arg for argument in (node.args.vararg, node.args.kwarg)
                               if argument is not None)
        self.calls: list[dict[str, Any]] = []
        self.returns: list[dict[str, Any]] = []
        self.bindings: list[dict[str, Any]] = []
        self.unsupported: set[str] = set()
        self.source_escapes: list[dict[str, Any]] = []
        if isinstance(node, ast.AsyncFunctionDef):
            self.unsupported.add("async_function")
        if node.decorator_list:
            self.unsupported.add("decorated_function")
        if node.args.vararg or node.args.kwarg or getattr(node, "type_params", []):
            self.unsupported.add("variadic_or_generic_function")
        nodes = [value for statement in node.body for value in _owned(statement)]
        self.locals = {value.id for value in nodes
                       if isinstance(value, ast.Name) and isinstance(value.ctx, (ast.Store, ast.Del))}
        for value in nodes:
            if isinstance(value, (ast.Global, ast.Nonlocal, ast.Yield, ast.YieldFrom,
                                  ast.Await, ast.NamedExpr, ast.Lambda, *_FUNCTIONS, ast.ClassDef)):
                self.unsupported.add(type(value).__name__)

    def bounded(self, values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        pending: list[Any] = [values]
        count = 0
        while pending:
            item = pending.pop()
            count += 1
            if count > 512:
                self.unsupported.add("origin_budget")
                return _unknown("origin_budget", _contains_opaque_input(values))
            if isinstance(item, dict):
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
        return values

    def expression(self, value: ast.expr | None,
                   env: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
        if value is None or isinstance(value, ast.Constant) and value.value is None:
            return [{"kind": "none"}]
        if isinstance(value, ast.Name):
            return copy.deepcopy(self.bounded(env.get(value.id, [{"kind": "source_name", "name": value.id}])))
        if isinstance(value, ast.Constant):
            return [{"kind": "literal", "type": type(value.value).__name__}]
        if isinstance(value, ast.IfExp):
            self.expression(value.test, env)
            left, right = copy.deepcopy(env), copy.deepcopy(env)
            origins = _union([self.expression(value.body, left), self.expression(value.orelse, right)])
            env.update(self.join(left, right))
            return origins
        if isinstance(value, ast.Call):
            receiver = (self.expression(value.func.value, env)
                        if isinstance(value.func, ast.Attribute) else [])
            callee = (self.expression(value.func, env)
                      if isinstance(value.func, ast.Name) else [])
            arguments = [self.expression(argument, env) for argument in value.args]
            keywords = [{"name": keyword.arg, "origins": self.expression(keyword.value, env)}
                        for keyword in value.keywords]
            argument_expressions = [*value.args, *(keyword.value for keyword in value.keywords)]
            complex_arguments = any(not isinstance(argument, (ast.Constant, ast.Name))
                                    for argument in argument_expressions)
            if complex_arguments:
                arguments = [_unknown("argument_after_evaluation", _contains_opaque_input(row)) for row in arguments]
                keywords = [{"name": keyword["name"],
                             "origins": _unknown("argument_after_evaluation", _contains_opaque_input(keyword["origins"]))}
                            for keyword in keywords]
                if isinstance(value.func, ast.Attribute):
                    receiver = _unknown("receiver_after_argument_evaluation", _contains_opaque_input(receiver))
            for argument in argument_expressions:
                for name in _value_names(argument):
                    if name not in env:
                        self.source_escapes.append({"name": name, "role": "argument",
                                                    "line": value.lineno})
            if isinstance(value.func, ast.Attribute) and isinstance(value.func.value, ast.Name):
                name = value.func.value.id
                if name not in env:
                    self.source_escapes.append({"name": name, "role": "receiver", "line": value.lineno})
            row = {"kind": "call_result", "callee": ast.unparse(value.func),
                   "callee_kind": type(value.func).__name__, "callee_origins": callee,
                   "receiver_origins": receiver, "arguments": arguments, "keywords": keywords,
                   "line": value.lineno, "column": value.col_offset,
                   "constructor_syntax_candidate": isinstance(value.func, ast.Name)
                   and value.func.id in self.classes and value.func.id not in env,
                   "identity_authority": False}
            bounded = self.bounded([row])
            if bounded[0]["kind"] == "unknown":
                row["arguments"] = [_unknown("origin_budget")]
                row["keywords"] = []
                row["receiver_origins"] = _unknown("origin_budget")
                row["callee_origins"] = _unknown("origin_budget")
            self.calls.append(copy.deepcopy(row))
            if isinstance(value.func, ast.Name) and value.func.id == self.node.name:
                self.unsupported.add("recursive_call")
            # Arguments and bound receivers can escape into a call. The return
            # expression retains its pre-call symbolic inputs; later aliases do not.
            escaped = [*value.args, *(keyword.value for keyword in value.keywords)]
            if isinstance(value.func, ast.Attribute):
                escaped.append(value.func.value)
            if isinstance(value.func, ast.Name):
                escaped.append(value.func)
            if any(isinstance(part, ast.Name) and part.id in env
                   for expression in escaped for part in ast.walk(expression)):
                # Any local may share the escaped object. Without heap identity
                # proof, invalidating one spelling leaves stale alias permission.
                env.update({name: _unknown("escaped_to_call", _contains_opaque_input(origins))
                            for name, origins in env.items()})
            return bounded
        if isinstance(value, ast.Attribute):
            return [{"kind": "unknown", "reason": "attribute_value",
                     "attribute": value.attr, "receiver_origins": self.expression(value.value, env)}]
        origins = []
        for child in ast.iter_child_nodes(value):
            if isinstance(child, ast.expr):
                origins.extend(self.expression(child, env))
        return _unknown("unsupported_expression:" + type(value).__name__, _contains_opaque_input(origins))

    def join(self, left: dict[str, list[dict[str, Any]]],
             right: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
        return {name: _union([left.get(name, _unknown("unbound_branch")),
                              right.get(name, _unknown("unbound_branch"))])
                for name in left.keys() | right.keys()}

    def block(self, statements: list[ast.stmt], env: dict[str, list[dict[str, Any]]]
              ) -> dict[str, list[dict[str, Any]]] | None:
        for statement in statements:
            if isinstance(statement, ast.Return):
                self.returns.append({"line": statement.lineno, "column": statement.col_offset,
                                     "implicit": False,
                                     "expression": ast.unparse(statement.value) if statement.value else None,
                                     "alternatives": self.expression(statement.value, env)})
                return None
            if isinstance(statement, ast.Raise):
                self.expression(statement.exc, env)
                self.expression(statement.cause, env)
                return None
            if isinstance(statement, ast.If):
                self.expression(statement.test, env)
                left = self.block(statement.body, copy.deepcopy(env))
                right = self.block(statement.orelse, copy.deepcopy(env))
                if left is None:
                    if right is None:
                        return None
                    env = right
                elif right is None:
                    env = left
                else:
                    env = self.join(left, right)
            elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                origins = self.expression(statement.value, env)
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = copy.deepcopy(origins)
                        self.bindings.append({"name": target.id, "line": statement.lineno,
                                              "column": target.col_offset, "alternatives": origins})
                    else:
                        self.unsupported.add("nonlocal_or_destructuring_assignment")
            elif isinstance(statement, ast.Expr):
                self.expression(statement.value, env)
            elif isinstance(statement, ast.Assert):
                self.expression(statement.test, env)
                self.expression(statement.msg, env)
            elif isinstance(statement, ast.Pass):
                continue
            else:
                self.unsupported.add("statement:" + type(statement).__name__)
                # Keep source call sites, but never invent supported control flow.
                for value in _owned(statement):
                    if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                            and (value.func.id in self.locals or value.func.id in self.parameters
                                 or _contains_opaque_input(env.get(value.func.id, [])))):
                        self.calls.append({
                            "kind": "call_result", "callee": value.func.id,
                            "callee_kind": "Name", "receiver_origins": [],
                            "callee_origins": _unknown("unsupported_control_flow", True),
                            "arguments": [], "keywords": [], "line": value.lineno,
                            "column": value.col_offset, "identity_authority": False,
                            "constructor_syntax_candidate": False,
                        })
                    if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
                        # Unsupported flow cannot justify a binding. Retain a
                        # bounded call obligation without recursively expanding
                        # every nested call's symbolic argument tree again.
                        self.calls.append({
                            "kind": "call_result", "callee": ast.unparse(value.func),
                            "callee_kind": "Attribute", "callee_origins": [],
                            "receiver_origins": _unknown("unsupported_control_flow", True),
                            "arguments": [], "keywords": [], "line": value.lineno,
                            "column": value.col_offset, "identity_authority": False,
                            "constructor_syntax_candidate": False,
                        })
                    if isinstance(value, ast.Return):
                        self.returns.append({"line": value.lineno, "column": value.col_offset,
                                             "implicit": False, "expression": None,
                                             "alternatives": _unknown("unsupported_control_flow")})
                env = {name: _unknown("unsupported_control_flow", _contains_opaque_input(origins))
                       for name, origins in env.items()}
        return env

    def facts(self) -> dict[str, Any]:
        env = {name: _unknown("unbound_local") for name in self.locals}
        env.update({name: [{"kind": "parameter", "name": name}] for name in self.parameters})
        if self.class_name and self.parameters and not self.node.decorator_list:
            env[self.parameters[0]] = [{"kind": "self", "name": self.parameters[0]}]
        nodes = [value for statement in self.node.body for value in _owned(statement)]
        pending: list[tuple[ast.AST, int]] = [(statement, 0) for statement in self.node.body]
        branch_depth = 0
        while pending:
            current, depth = pending.pop()
            depth += int(isinstance(current, ast.If))
            branch_depth = max(branch_depth, depth)
            if not isinstance(current, (*_FUNCTIONS, ast.ClassDef, ast.Lambda)):
                pending.extend((child, depth) for child in ast.iter_child_nodes(current))
        remaining: dict[str, list[dict[str, Any]]] | None
        if len(nodes) > 4096 or len(self.locals) > 128 or branch_depth > 16:
            self.unsupported.add("function_budget")
            remaining = env
        else:
            remaining = self.block(self.node.body, env)
        if remaining is not None:
            self.returns.append({"line": self.node.end_lineno, "column": None, "implicit": True,
                                 "expression": None, "alternatives": [{"kind": "none"}]})
        if self.unsupported:
            for row in self.returns:
                row["alternatives"] = _unknown("unsupported_function_flow")
        suffix = (self.class_name + "." if self.class_name else "") + self.node.name
        return {"symbol": self.path + "::" + suffix, "line": self.node.lineno,
                "end_line": self.node.end_lineno, "parameters": self.parameters,
                "class_name": self.class_name, "returns": self.returns,
                "call_sites": self.calls, "local_bindings": self.bindings,
                "source_escapes": self.source_escapes,
                "unsupported": sorted(self.unsupported), "identity_authority": False,
                "defaults": bool(self.node.args.defaults or self.node.args.kw_defaults)}


def discover_return_facts(tree: ast.Module, *, path: str) -> list[dict[str, Any]]:
    """Describe top-level functions/methods without executing source or annotations."""
    classes = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
    result = []
    for node in tree.body:
        if isinstance(node, _FUNCTIONS):
            result.append(_Flow(node, path=path, class_name=None, classes=classes).facts())
        elif isinstance(node, ast.ClassDef):
            for member in node.body:
                if isinstance(member, _FUNCTIONS):
                    result.append(_Flow(member, path=path, class_name=node.name, classes=classes).facts())
    return result

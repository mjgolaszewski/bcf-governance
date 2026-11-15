"""Closed source proof for primitive admission and private-set key invariants.

This finite body grammar proves every operation in the admitted body. Matching
names, annotations, an individual guard, or a constructor alone is insufficient.
"""
from __future__ import annotations

import ast
import copy
import json
from typing import Any

from .semantic_python_constructor_callbacks import scalar_guard_parts

INSTANCE = "source-instance:"
_TEMPLATE = '''
def admitted(owner, key, *, selector):
 if owner.failed:
  raise ValueError('error')
 if type(key) is int:
  valid = -(1 << 63) <= key < (1 << 63)
 elif type(key) is str:
  try:
   valid = 0 < len(key.encode('utf-8')) <= 256
  except UnicodeError:
   valid = False
 else:
  valid = False
 if not valid:
  owner.failed = True
  raise ValueError('error')
 assert isinstance(key, str | int)
 selected = owner.second if selector else owner.first
 kind = owner.second_type if selector else owner.first_type
 if kind is not None and type(key) is not kind:
  owner.failed = True
  raise ValueError('error')
 if key in selected:
  owner.failed = True
  raise ValueError('error')
 if len(owner.first) + len(owner.second) >= owner.capacity:
  owner.failed = True
  raise ValueError('error')
 selected.add(key)
 if selector:
  owner.second_type = type(key)
 else:
  owner.first_type = type(key)
'''


def _body(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.stmt]:
    return [node for node in function.body if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str))]


def normal_guard_refinements(row: dict[str, Any]) -> dict[str, str]:
    """Only a stable sync helper whose entire body is rejecting scalar guards."""
    if not row.get("source_binding_stable") or row.get("decorators"):
        return {}
    source = row.get("python_value_source")
    if not source:
        return {}
    function = ast.parse(source).body[0]
    if not isinstance(function, ast.FunctionDef) or function.args.vararg or function.args.kwarg:
        return {}
    body = _body(function)
    if body and isinstance(body[-1], ast.Return) and (body[-1].value is None or isinstance(body[-1].value, ast.Constant) and body[-1].value.value is None):
        body = body[:-1]
    result = {}
    parameters = {arg.arg for arg in [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]}
    native = set(row.get("unshadowed_container_builtins", []))
    if not body or "type" not in native or "ValueError" not in native:
        return {}
    for guard in body:
        parts = scalar_guard_parts(guard)
        if parts is None or parts[0] not in parameters or len(parts[1]) != 1 or not parts[1] <= native:
            return {}
        assert isinstance(guard, ast.If)
        if len(guard.body) != 1 or not isinstance(guard.body[0], ast.Raise):
            return {}
        error = guard.body[0].exc
        if not (isinstance(error, ast.Call) and isinstance(error.func, ast.Name)
                and error.func.id == "ValueError" and not error.keywords
                and all(isinstance(arg, ast.Constant) for arg in error.args)):
            return {}
        result[parts[0]] = next(iter(parts[1]))
    return result


def key_body_roles(row: dict[str, Any]) -> dict[str, Any] | None:
    """Recover roles, then compare the complete normalized executable AST."""
    if not row.get("source_binding_stable") or row.get("decorators"):
        return None
    native = set(row.get("unshadowed_container_builtins", []))
    if not {"type", "int", "str", "len", "ValueError", "UnicodeError", "isinstance"} <= native:
        return None
    function = ast.parse(row.get("python_value_source", "pass")).body[0]
    if not isinstance(function, ast.FunctionDef) or function.args.vararg or function.args.kwarg or function.args.defaults or any(function.args.kw_defaults):
        return None
    args = [*function.args.posonlyargs, *function.args.args]
    if len(args) != 2 or len(function.args.kwonlyargs) != 1:
        return None
    body = _body(function)
    if len(body) != 11:
        return None
    try:
        owner, key = [arg.arg for arg in args]
        selector = function.args.kwonlyargs[0].arg
        first_guard, type_guard = body[0], body[1]
        assert isinstance(first_guard, ast.If) and isinstance(first_guard.test, ast.Attribute)
        assert isinstance(type_guard, ast.If) and isinstance(type_guard.body[0], ast.Assign)
        valid = type_guard.body[0].targets[0]
        selected, kind = body[4], body[5]
        assert isinstance(valid, ast.Name) and isinstance(selected, ast.Assign) and isinstance(kind, ast.Assign)
        assert isinstance(selected.targets[0], ast.Name) and isinstance(kind.targets[0], ast.Name)
        assert isinstance(selected.value, ast.IfExp) and isinstance(kind.value, ast.IfExp)
        assert isinstance(selected.value.body, ast.Attribute) and isinstance(selected.value.orelse, ast.Attribute)
        assert isinstance(kind.value.body, ast.Attribute) and isinstance(kind.value.orelse, ast.Attribute)
        capacity_guard = body[8]
        assert isinstance(capacity_guard, ast.If) and isinstance(capacity_guard.test, ast.Compare)
        capacity = capacity_guard.test.comparators[0]
        assert isinstance(capacity, ast.Attribute)
        names = {owner: "owner", key: "key", selector: "selector", valid.id: "valid", selected.targets[0].id: "selected", kind.targets[0].id: "kind"}
        fields = {first_guard.test.attr: "failed", selected.value.orelse.attr: "first", selected.value.body.attr: "second", kind.value.orelse.attr: "first_type", kind.value.body.attr: "second_type", capacity.attr: "capacity"}
        if len(names) != 6 or len(fields) != 6:
            return None
    except (AssertionError, AttributeError, IndexError, TypeError):
        return None

    class Normalize(ast.NodeTransformer):
        def visit_Name(self, node: ast.Name) -> ast.AST:  # noqa: N802
            return ast.copy_location(ast.Name(id=names.get(node.id, node.id), ctx=node.ctx), node)

        def visit_Attribute(self, node: ast.Attribute) -> ast.AST:  # noqa: N802
            owned = isinstance(node.value, ast.Name) and node.value.id == owner
            self.generic_visit(node)
            if owned:
                node.attr = fields.get(node.attr, node.attr)
            return node

        def visit_Call(self, node: ast.Call) -> ast.AST:  # noqa: N802
            self.generic_visit(node)
            if isinstance(node.func, ast.Name) and node.func.id == "ValueError":
                node.args = [ast.Constant(value="error") if isinstance(arg, ast.Constant) and isinstance(arg.value, str) else arg for arg in node.args]
            return node

    candidate = Normalize().visit(ast.Module(body=copy.deepcopy(body), type_ignores=[]))
    template = ast.parse(_TEMPLATE).body[0]
    assert isinstance(template, ast.FunctionDef)
    expected = ast.Module(body=_body(template), type_ignores=[])
    if ast.dump(candidate, include_attributes=False) != ast.dump(expected, include_attributes=False):
        return None
    return {"owner": owner, "key": key, "selector": selector, "fields": {role: name for name, role in fields.items()}, "function": function}


def class_key_fields(functions: dict[str, dict[str, Any]], subject: str, states: dict[str, str]) -> list[str]:
    """An all-writer check establishes the inductive key invariant, never emptiness."""
    members = [row for row in functions.values() if row.get("class_symbol") == subject]
    writers = [(row, roles) for row in members if (roles := key_body_roles(row)) is not None]
    if not writers:
        return []
    key_fields = {roles["fields"][name] for _, roles in writers for name in ("first", "second")}
    if any(states.get(field) != "native-set" for field in key_fields):
        return []
    writer_symbols = {row["symbol"] for row, _ in writers}
    for row in members:
        source = row.get("python_value_source")
        if not source or row["symbol"] in writer_symbols:
            continue
        function = ast.parse(source).body[0]
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return []
        args = [*function.args.posonlyargs, *function.args.args]
        if not args:
            continue
        receiver = args[0].arg
        parents = {id(child): parent for parent in ast.walk(function) for child in ast.iter_child_nodes(parent)}
        for node in ast.walk(function):
            if isinstance(node, ast.Name) and node.id == receiver and isinstance(node.ctx, ast.Load):
                if not isinstance(parents.get(id(node)), ast.Attribute):
                    return []
            if isinstance(node, ast.Name) and node.id in {"getattr", "setattr", "delattr", "globals", "locals", "vars", "exec", "eval"}:
                return []
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == receiver:
                if node.attr in {"__dict__", "__class__", "__getattribute__", "__setattr__"}:
                    return []
                if node.attr not in key_fields:
                    continue
                if function.name == "__init__" and isinstance(node.ctx, ast.Store):
                    continue
                parent = parents.get(id(node))
                if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not) and parent.operand is node:
                    continue
                if not (isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name)
                        and parent.func.id == "len" and parent.args == [node] and not parent.keywords
                        and "len" in row.get("unshadowed_container_builtins", [])):
                    return []
    return sorted(key_fields)


def owned_key_body_proof(row: dict[str, Any], arguments: tuple[tuple[str, str], ...]) -> dict[str, Any] | None:
    roles = key_body_roles(row)
    if roles is None:
        return None
    bound = dict(arguments)
    origin = bound.get(roles["owner"], "")
    if not origin.startswith(INSTANCE) or bound.get(roles["selector"]) != "scalar":
        return None
    owner = json.loads(origin.removeprefix(INSTANCE))
    if owner["subject"] != row.get("class_symbol"):
        return None
    fields = roles["fields"]
    states = owner.get("private_fields", {})
    if any(states.get(fields[name]) != "scalar" for name in ("failed", "capacity", "first_type", "second_type")):
        return None
    if any(states.get(fields[name]) != "native-set" or fields[name] not in owner.get("private_key_fields", []) for name in ("first", "second")):
        return None
    function = roles["function"]
    positions = {id(node): point for node, point in zip(ast.walk(function), row.get("python_value_sites", []), strict=False)}
    writes = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
            writes.add((positions[id(node)][0], ast.unparse(node)))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add":
            writes.add((positions[id(node)][0], ast.unparse(node.func)))
    return {"native_calls": {tuple(positions[id(node)]) for node in ast.walk(function) if isinstance(node, ast.Call)}, "writes": writes}

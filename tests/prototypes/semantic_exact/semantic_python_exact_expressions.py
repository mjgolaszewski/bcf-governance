"""Fail-closed native expression checking with borrowed children retained.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

import ast
import hashlib
from typing import Any, Protocol

from .semantic_python_exact_guards import refine_guard, value_path
from .semantic_python_exact_values import (
    BOOL,
    BOTTOM,
    INT,
    NONE,
    SCALARS,
    SEQUENCES,
    STR,
    ExactProtocolRefusal,
    ExactState,
    ExactValue,
    callback_free,
    native_element,
    native_truth,
    union,
)


class ExactDriver(Protocol):
    def binding(self, frame: ExactExpressions, name: str) -> ExactValue: ...
    def attribute(self, frame: ExactExpressions, receiver: ExactValue, name: str) -> ExactValue: ...
    def invoke(self, frame: ExactExpressions, node: ast.Call, receiver: ExactValue | None,
               arguments: list[ExactValue], keywords: dict[str, ExactValue]) -> ExactValue: ...
    def comparable(self, left: ExactValue, right: ExactValue) -> bool: ...


class ExactExpressions:
    def __init__(self, row: dict[str, Any], state: ExactState, driver: ExactDriver,
                 type_bindings: dict[str, str], identity: str) -> None:
        self.row, self.state, self.driver = row, state, driver
        self.type_bindings, self.identity = type_bindings, identity
        parsed = ast.parse(str(row["python_value_source"])).body[0]
        if not isinstance(parsed, (ast.FunctionDef, ast.AsyncFunctionDef)):
            raise ExactProtocolRefusal("source frame is not a function")
        digest = hashlib.sha256(ast.dump(parsed, include_attributes=False).encode()).hexdigest()
        if digest != row["python_value_shape_sha256"]:
            raise ExactProtocolRefusal("source frame shape does not match its inventory")
        self.function = parsed
        sites = iter(row["python_value_sites"])
        self.positions = {id(node): tuple(next(sites, (0, 0))) for node in ast.walk(parsed)}
        self.calls = {(row.get("line"), row.get("column")): row for row in row.get("calls", [])
                      if not row.get("implicit_callback")}
        self.work = 10000

    def refusal(self, node: ast.AST, reason: str) -> ExactProtocolRefusal:
        return ExactProtocolRefusal(f"{self.row['symbol']}:{self.positions.get(id(node), (0, 0))[0]}: {reason}")

    def fresh(self, node: ast.AST, shape: ExactValue) -> ExactValue:
        return self.state.allocate(f"{self.identity}:{self.positions[id(node)]}", shape)

    def resolved(self, node: ast.AST) -> ExactValue:
        return self.state.resolve(self.expression(node))

    def condition(self, node: ast.AST, state: ExactState | None = None) -> tuple[list[ExactState], list[ExactState]]:
        original = self.state
        self.state = original if state is None else state
        try:
            if isinstance(node, ast.Constant) and type(node.value) is bool:
                return ([self.state.copy()], []) if node.value else ([], [self.state.copy()])
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
                yes, no = self.condition(node.operand)
                return no, yes
            if isinstance(node, ast.BoolOp):
                pending, finished = [self.state.copy()], []
                for operand in node.values:
                    continuing = []
                    for current in pending:
                        yes, no = self.condition(operand, current)
                        continuing.extend(yes if isinstance(node.op, ast.And) else no)
                        finished.extend(no if isinstance(node.op, ast.And) else yes)
                    pending = continuing
                    if len(pending) + len(finished) > 16:
                        raise self.refusal(node, "condition path budget")
                return (pending, finished) if isinstance(node.op, ast.And) else (finished, pending)
            value = self.state.resolve(self.expression(node))
            if not native_truth(value):
                raise self.refusal(node, "foreign truth protocol")
            return (refine_guard(node, True, self.state, self.type_bindings),
                    refine_guard(node, False, self.state, self.type_bindings))
        finally:
            self.state = original

    def _generator(self, node: ast.GeneratorExp | ast.ListComp | ast.SetComp | ast.DictComp) -> ExactValue:
        if len(node.generators) != 1:
            raise self.refusal(node, "nested comprehension clauses are not qualified")
        clause = node.generators[0]
        if clause.is_async:
            raise self.refusal(node, "foreign async iterator")
        source = self.resolved(clause.iter)
        if source.kind not in SEQUENCES | {"dict"}:
            raise self.refusal(node, "foreign comprehension iterator")
        original = self.state
        inner = original.copy()
        self.state = inner
        try:
            self.assign(clause.target, native_element(source))
            states = [inner]
            for predicate in clause.ifs:
                states = [outcome for current in states for outcome in self.condition(predicate, current)[0]]
            values, keys = [], []
            for current in states:
                self.state = current
                if isinstance(node, ast.DictComp):
                    key = self.resolved(node.key)
                    if not callback_free(key):
                        raise self.refusal(node.key, "foreign comprehension key")
                    keys.append(key)
                    values.append(self.expression(node.value))
                else:
                    if isinstance(node.elt, ast.BoolOp):
                        self.condition(node.elt)
                        values.append(BOOL)
                    else:
                        values.append(self.expression(node.elt))
            # Comprehension mutations of a captured owned allocation are real.
            # Join them into the outer heap instead of discarding their effects.
            if states:
                original.heap.update(ExactState.join(states).heap)
            if isinstance(node, ast.DictComp):
                shape = ExactValue("dict", (union(*keys), union(*values)))
            else:
                kind = "generator" if isinstance(node, ast.GeneratorExp) else "list" if isinstance(node, ast.ListComp) else "set"
                shape = ExactValue(kind, (union(*values),))
            return shape if isinstance(node, ast.GeneratorExp) else original.allocate(f"{self.identity}:{self.positions[id(node)]}", shape)
        finally:
            self.state = original

    def expression(self, node: ast.AST | None) -> ExactValue:
        self.work -= 1
        if self.work < 0:
            raise ExactProtocolRefusal("exact expression budget exhausted")
        if node is None:
            return NONE
        if isinstance(node, ast.Constant):
            kind = "none" if node.value is None else type(node.value).__name__
            if kind not in SCALARS:
                raise self.refusal(node, "unsupported literal")
            return ExactValue(kind, subject=repr(node.value))
        if isinstance(node, ast.Name):
            return self.state.env[node.id] if node.id in self.state.env else self.driver.binding(self, node.id)
        if isinstance(node, ast.Attribute):
            receiver = self.resolved(node.value)
            if receiver.kind == "record" and node.attr in dict(receiver.fields):
                return receiver.member(node.attr)
            return self.driver.attribute(self, receiver, node.attr)
        if isinstance(node, ast.Await):
            value = self.resolved(node.value)
            if value.kind != "awaitable" or len(value.children) != 1:
                raise self.refusal(node, "foreign await protocol")
            return value.children[0]
        if isinstance(node, (ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp)):
            return self._generator(node)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            if any(isinstance(item, ast.Starred) for item in node.elts):
                raise self.refusal(node, "starred container construction")
            elements = [self.expression(item) for item in node.elts]
            kind = type(node).__name__.lower()
            if kind == "set" and not all(callback_free(self.state.resolve(item)) for item in elements):
                raise self.refusal(node, "foreign set key")
            shape = ExactValue(kind, (union(*elements),), fields=tuple((str(index), item) for index, item in enumerate(elements)) if kind == "tuple" else ())
            return shape if kind == "tuple" else self.fresh(node, shape)
        if isinstance(node, ast.Dict):
            keys, values = [], []
            fields: dict[str, ExactValue] = {}
            for key_node, value_node in zip(node.keys, node.values, strict=True):
                value = self.expression(value_node)
                if key_node is None:
                    shape = self.state.resolve(value)
                    if shape.kind != "dict" or not callback_free(shape.children[0]):
                        raise self.refusal(node, "foreign mapping expansion")
                    keys.append(shape.children[0])
                    values.append(shape.children[1])
                    fields.update(shape.fields)
                else:
                    key = self.resolved(key_node)
                    if not callback_free(key):
                        raise self.refusal(key_node, "foreign dictionary key")
                    keys.append(key)
                    values.append(value)
                    if isinstance(key_node, ast.Constant) and type(key_node.value) is str:
                        fields[key_node.value] = value
            return self.fresh(node, ExactValue("dict", (union(*keys), union(*values)), fields=tuple(sorted(fields.items()))))
        if isinstance(node, ast.Subscript):
            receiver = self.resolved(node.value)
            if receiver.kind == "binding" and receiver.subject in {"builtins::dict", "builtins::list", "builtins::tuple"}:
                arguments = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
                if all(self.resolved(arg).kind in {"binding", "type_expression"} for arg in arguments):
                    return ExactValue("type_expression")
                raise self.refusal(node, "foreign type subscription")
            if isinstance(node.slice, ast.Slice):
                bounds = [self.resolved(item) for item in (node.slice.lower, node.slice.upper, node.slice.step) if item is not None]
                if receiver.kind not in {"str", "bytes", "list", "tuple"} or not all(item.kind == "int" for item in bounds):
                    raise self.refusal(node, "foreign slicing protocol")
                return receiver
            key = self.resolved(node.slice)
            if not callback_free(key):
                raise self.refusal(node, "foreign lookup key")
            if receiver.kind == "dict" and callback_free(receiver.children[0]):
                if isinstance(node.slice, ast.Constant) and type(node.slice.value) is str:
                    return dict(receiver.fields).get(node.slice.value, receiver.children[1])
                return receiver.children[1]
            if receiver.kind in {"list", "tuple"} and key.kind == "int":
                return native_element(receiver)
            if receiver.kind in {"str", "bytes"} and key.kind == "int":
                return STR if receiver.kind == "str" else INT
            raise self.refusal(node, "foreign subscript protocol")
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            self.condition(node.operand)
            return BOOL
        if isinstance(node, ast.UnaryOp):
            value = self.resolved(node.operand)
            if value.kind not in {"int", "float", "complex", "bool"}:
                raise self.refusal(node, "foreign unary protocol")
            return value
        if isinstance(node, ast.BinOp):
            left, right = self.resolved(node.left), self.resolved(node.right)
            if not callback_free(left) or not callback_free(right):
                raise self.refusal(node, "foreign binary protocol")
            if (left.kind == right.kind and left.kind in {"int", "str", "bytes", "float", "complex"}
                    and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult))
                    and (left.kind not in {"str", "bytes"} or isinstance(node.op, ast.Add))):
                return ExactValue(left.kind)
            raise self.refusal(node, "unqualified native binary result")
        if isinstance(node, ast.Compare):
            left = self.resolved(node.left)
            for operator, comparator in zip(node.ops, node.comparators, strict=True):
                right = self.resolved(comparator)
                if not isinstance(operator, (ast.Is, ast.IsNot)):
                    compared = native_element(right) if isinstance(operator, (ast.In, ast.NotIn)) else right
                    if not (callback_free(left) and callback_free(compared) or self.driver.comparable(left, compared)):
                        raise self.refusal(node, "foreign comparison protocol")
                left = right
            return BOOL
        if isinstance(node, ast.IfExp):
            yes, no = self.condition(node.test)
            values = []
            original = self.state
            for state, body in [(item, node.body) for item in yes] + [(item, node.orelse) for item in no]:
                self.state = state
                values.append(self.expression(body))
            self.state = original
            original.heap.update(ExactState.join([*yes, *no]).heap)
            return union(*values)
        if isinstance(node, ast.JoinedStr):
            for item in node.values:
                if isinstance(item, ast.FormattedValue):
                    if not callback_free(self.resolved(item.value)):
                        raise self.refusal(item, "foreign format protocol")
                    if item.format_spec is not None:
                        self.expression(item.format_spec)
            return STR
        if isinstance(node, ast.Call):
            if any(isinstance(item, ast.Starred) for item in node.args) or any(item.arg is None for item in node.keywords):
                raise self.refusal(node, "starred invocation")
            receiver_arg = self.expression(node.func.value) if isinstance(node.func, ast.Attribute) else None
            values = [self.expression(item) for item in node.args]
            keywords = {str(item.arg): self.expression(item.value) for item in node.keywords}
            if (isinstance(node.func, ast.Name) and node.func.id not in self.state.env
                    and node.func.id in self.row.get("unshadowed_container_builtins", [])):
                name = node.func.id
                resolved = [self.state.resolve(item) for item in values]
                if name == "type" and len(values) == 1 and not keywords:
                    return ExactValue("type")
                if name == "len" and len(values) == 1 and not keywords and all(native_truth(item) for item in resolved):
                    return INT
                if name in {"any", "all"} and len(values) == 1 and not keywords:
                    shape = resolved[0]
                    if shape.kind in SEQUENCES and native_truth(self.state.resolve(native_element(shape))):
                        return BOOL
                if name in {"ValueError", "RuntimeError", "Exception"} and not keywords:
                    return ExactValue("exception", subject=name)
                if name in {"set", "frozenset", "tuple", "list"} and len(values) <= 1 and not keywords:
                    element = native_element(resolved[0]) if values else BOTTOM
                    if not values or resolved[0].kind in SEQUENCES | {"dict"}:
                        if name in {"set", "frozenset"} and not callback_free(self.state.resolve(element)):
                            raise self.refusal(node, "foreign constructed key")
                        shape = ExactValue(name, (element,))
                        return shape if name in {"tuple", "frozenset"} else self.fresh(node, shape)
                if name == "ord" and len(values) == 1 and not keywords and resolved[0].kind == "str":
                    return INT
            if isinstance(node.func, ast.Attribute) and receiver_arg is not None:
                native = self.native_method(node, receiver_arg, values, keywords)
                if native is not None:
                    return native
            return self.driver.invoke(self, node, receiver_arg, values, keywords)
        raise self.refusal(node, f"unsupported expression {type(node).__name__}")

    def native_method(self, node: ast.Call, receiver: ExactValue, values: list[ExactValue], keywords: dict[str, ExactValue]) -> ExactValue | None:
        assert isinstance(node.func, ast.Attribute)
        shape, name = self.state.resolve(receiver), node.func.attr
        if keywords:
            return None
        if shape.kind == "dict" and callback_free(shape.children[0]):
            if name == "get" and len(values) in {1, 2} and callback_free(self.state.resolve(values[0])):
                value = shape.children[1]
                if isinstance(node.args[0], ast.Constant) and type(node.args[0].value) is str:
                    value = dict(shape.fields).get(node.args[0].value, value)
                return union(value, values[1] if len(values) == 2 else NONE)
            if name in {"items", "keys", "values"} and not values:
                element = shape.children[0] if name == "keys" else shape.children[1]
                if name == "items":
                    element = ExactValue("tuple", (union(*shape.children),), fields=(("0", shape.children[0]), ("1", shape.children[1])))
                return ExactValue("view", (element,))
            if name == "setdefault" and len(values) == 2 and receiver.kind == "owned" and callback_free(self.state.resolve(values[0])):
                result = union(shape.children[1], values[1])
                self.state.heap[receiver.subject] = ExactValue("dict", (union(shape.children[0], values[0]), result))
                return result
        if shape.kind == "list" and receiver.kind == "owned":
            if name == "append" and len(values) == 1:
                self.state.heap[receiver.subject] = ExactValue("list", (union(shape.children[0], values[0]),))
                return NONE
            if name == "extend" and len(values) == 1:
                source = self.state.resolve(values[0])
                if source.kind in SEQUENCES | {"dict"}:
                    self.state.heap[receiver.subject] = ExactValue("list", (union(shape.children[0], native_element(source)),))
                    return NONE
        if shape.kind == "str" and all(self.state.resolve(item).kind in {"str", "int"} for item in values):
            if name in {"casefold", "lower", "upper", "strip", "lstrip", "rstrip"} and not values:
                return STR
            if name in {"startswith", "endswith"} and len(values) == 1:
                return BOOL
        return None

    def assign(self, target: ast.AST, value: ExactValue) -> None:
        if isinstance(target, ast.Name):
            self.state.aliases = {name: path for name, path in self.state.aliases.items()
                                  if name != target.id and path[0] != target.id}
            self.state.env[target.id] = value
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            shape = self.state.resolve(value)
            fields = dict(shape.fields)
            if shape.kind != "tuple" or set(fields) != {str(index) for index in range(len(target.elts))}:
                raise self.refusal(target, "foreign unpacking protocol")
            for index, item in enumerate(target.elts):
                self.assign(item, fields[str(index)])
            return
        if isinstance(target, ast.Subscript):
            receiver, key = self.expression(target.value), self.resolved(target.slice)
            shape = self.state.resolve(receiver)
            if receiver.kind == "owned" and shape.kind == "dict" and callback_free(shape.children[0]) and callback_free(key):
                fields = dict(shape.fields)
                if isinstance(target.slice, ast.Constant) and type(target.slice.value) is str:
                    fields[target.slice.value] = value
                self.state.heap[receiver.subject] = ExactValue("dict", (union(shape.children[0], key), union(shape.children[1], value)), fields=tuple(sorted(fields.items())))
                return
        raise self.refusal(target, "write through borrowed or unqualified receiver")

    def assignment_alias(self, target: ast.AST, source: ast.AST | None) -> None:
        if isinstance(target, ast.Name) and source is not None and (path := value_path(source)):
            path = (*self.state.aliases[path[0]], *path[1:]) if path[0] in self.state.aliases else path
            if path[0] != target.id:
                self.state.aliases[target.id] = path

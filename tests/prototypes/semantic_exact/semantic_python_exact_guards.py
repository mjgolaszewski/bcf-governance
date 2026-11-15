"""Normal-path refinements; these facts never discharge execution protocols.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

import ast

from .semantic_python_exact_values import (
    BOTTOM,
    UNKNOWN,
    ExactState,
    ExactValue,
    alternatives,
    native_element,
    union,
)


def value_path(node: ast.AST) -> tuple[str, ...] | None:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Attribute) and (parent := value_path(node.value)) is not None:
        return (*parent, node.attr)
    return None


def path_value(state: ExactState, path: tuple[str, ...]) -> ExactValue:
    if path[0] in state.aliases:
        path = (*state.aliases[path[0]], *path[1:])
    value = state.env.get(path[0], UNKNOWN)
    for name in path[1:]:
        value = state.resolve(value).member(name)
    return state.resolve(value)


def set_path(state: ExactState, path: tuple[str, ...], value: ExactValue) -> None:
    if path[0] in state.aliases:
        path = (*state.aliases[path[0]], *path[1:])
    def replace(original: ExactValue, names: tuple[str, ...]) -> ExactValue:
        if not names:
            return value
        if original.kind != "record":
            return original
        fields = dict(original.fields)
        fields[names[0]] = replace(fields.get(names[0], UNKNOWN), names[1:])
        return ExactValue(original.kind, original.children, original.subject, tuple(sorted(fields.items())))
    old = state.env.get(path[0], UNKNOWN)
    if not path[1:] and old.kind == "owned":
        state.heap[old.subject] = value
    else:
        state.env[path[0]] = replace(old, path[1:])
    for name, source in state.aliases.items():
        state.env[name] = path_value(state, source)


def _typed(value: ExactValue, kind: str, selected: bool) -> ExactValue:
    subject = kind.removeprefix("record:") if kind.startswith("record:") else ""
    kind = "record" if subject else kind
    if value == UNKNOWN:
        if not selected:
            return UNKNOWN
        children = (UNKNOWN, UNKNOWN) if kind == "dict" else (UNKNOWN,) if kind in {"list", "tuple", "set", "frozenset"} else ()
        return ExactValue(kind, children, subject)
    return union(*(item for item in alternatives(value)
                   if (item.kind == kind and (not subject or item.subject == subject)) == selected))


def refine_guard(
    test: ast.AST, selected: bool, state: ExactState,
    type_bindings: dict[str, str], *, budget: int = 24,
) -> list[ExactState]:
    """Return possible continuing states after an already checked predicate.

    Execution qualification belongs to the expression checker. In particular,
    recognizing a generator guard cannot certify a foreign iterator or key.
    """
    if budget <= 0:
        return [state.copy()]
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return refine_guard(test.operand, not selected, state, type_bindings, budget=budget - 1)
    if isinstance(test, ast.BoolOp):
        sequential = selected == isinstance(test.op, ast.And)
        pending = [state.copy()]
        finished: list[ExactState] = []
        for value in test.values:
            next_states = []
            for current in pending:
                if not sequential:
                    finished.extend(refine_guard(value, selected, current, type_bindings, budget=budget - 1))
                next_states.extend(refine_guard(value, selected if sequential else not selected,
                                                current, type_bindings, budget=budget - 1))
            pending = next_states
            if len(finished) + len(pending) > 16:
                return [state.copy()]
        return pending if sequential else finished
    if isinstance(test, ast.Compare) and len(test.ops) == len(test.comparators) == 1:
        operator, right = test.ops[0], test.comparators[0]
        path = None
        kind = None
        if isinstance(test.left, ast.Call) and isinstance(test.left.func, ast.Name):
            call = test.left
            assert isinstance(call.func, ast.Name)
            if call.func.id == "type" and "type" in type_bindings and len(call.args) == 1 and not call.keywords:
                path = value_path(call.args[0])
                if isinstance(right, ast.Name):
                    kind = type_bindings.get(right.id)
        elif isinstance(right, ast.Constant) and right.value is None:
            path, kind = value_path(test.left), "none"
        if path is not None and kind is not None and isinstance(operator, (ast.Is, ast.IsNot)):
            result = state.copy()
            refined = _typed(path_value(result, path), kind, selected == isinstance(operator, ast.Is))
            if refined == BOTTOM:
                return []
            set_path(result, path, refined)
            return [result]
    if (not selected and isinstance(test, ast.Call) and isinstance(test.func, ast.Name)
            and test.func.id == "any" and "any" in type_bindings and len(test.args) == 1
            and not test.keywords and isinstance(test.args[0], ast.GeneratorExp)):
        generator = test.args[0]
        if len(generator.generators) == 1:
            clause = generator.generators[0]
            path = value_path(clause.iter)
            if not clause.is_async and not clause.ifs and isinstance(clause.target, ast.Name) and path:
                container = path_value(state, path)
                if container.kind in {"list", "tuple", "dict"}:
                    inner = state.copy()
                    inner.env[clause.target.id] = native_element(container)
                    outcomes = refine_guard(generator.elt, False, inner, type_bindings, budget=budget - 1)
                    element = union(*(row.env.get(clause.target.id, UNKNOWN) for row in outcomes))
                    if element != BOTTOM:
                        result = state.copy()
                        children = (element, container.children[1]) if container.kind == "dict" else (element,)
                        set_path(result, path, ExactValue(container.kind, children))
                        return [result]
    return [state.copy()]

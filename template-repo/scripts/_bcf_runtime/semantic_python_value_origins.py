"""Bounded source-derived container ownership, independent of effect purity.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

import ast
from typing import Any

# Only exact literal-built containers and their literal-built children qualify.
# A value origin never qualifies a protocol callback or a filesystem effect.
UNKNOWN = "unknown"
SCALAR = "scalar"
CONTAINERS = {"list", "dict", "set", "tuple"}
MUTATORS = {"append", "extend", "insert", "clear", "pop", "remove", "add",
            "discard", "update", "setdefault", "popitem", "reverse"}


def value_origins(
    symbol: str, functions: dict[str, dict[str, Any]],
    arguments: tuple[tuple[str, str], ...] = (),
    active: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Return conservative write sites and caller bindings for one invocation.

    Unsupported control flow, escaping calls, and recursive results remain
    unknown. No project code is imported or executed to obtain these facts.
    """
    empty: dict[str, Any] = {"writes": set(), "calls": {}, "return": UNKNOWN}
    row = functions.get(symbol, {})
    source = row.get("python_value_source")
    if not source or symbol in active or len(active) >= 24:
        return empty
    function = ast.parse(source).body[0]
    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return empty
    if ast.dump(function, include_attributes=False) != row.get("python_value_shape"):
        return empty
    # The first bounded implementation refuses branch/loop/protocol joins.
    if any(isinstance(node, (ast.For, ast.AsyncFor, ast.While, ast.Try,
                            ast.TryStar, ast.With, ast.AsyncWith, ast.Match,
                            ast.Global, ast.Nonlocal, ast.Yield, ast.YieldFrom))
           for node in ast.walk(function)):
        return empty
    env = dict(arguments)
    safe: set[tuple[int, str]] = set()
    calls: dict[tuple[int, int], tuple[tuple[str, str], ...]] = {}
    # ast.unparse changes positions. Original call/effect positions are carried
    # in a parallel preorder inventory, never inferred from reconstructed lines.
    sites = iter(row.get("python_value_sites", []))
    positions = {id(node): next(sites, [0, 0]) for node in ast.walk(function)}
    facts = {(call.get("line"), call.get("column")): call
             for call in row.get("calls", []) if not call.get("implicit_callback")}
    retained = False
    unsupported_condition = False

    def invalidate() -> None:
        nonlocal retained
        retained = True
        for name, origin in list(env.items()):
            if origin in CONTAINERS:
                env[name] = UNKNOWN

    def expression(node: ast.AST | None) -> str:
        if isinstance(node, ast.Constant):
            return SCALAR
        if isinstance(node, ast.Name):
            return env.get(node.id, UNKNOWN)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            children = ([*node.keys, *node.values] if isinstance(node, ast.Dict)
                        else node.elts)
            origins = [expression(child) for child in children]
            if all(origin == SCALAR or origin in CONTAINERS for origin in origins):
                return type(node).__name__.lower()
            return UNKNOWN
        if isinstance(node, ast.Call):
            site = tuple(positions[id(node)])
            fact = facts.get(site, {})
            callee = str(fact.get("called_symbol", ""))
            values = [expression(value) for value in node.args]
            keywords = {keyword.arg: expression(keyword.value)
                        for keyword in node.keywords if keyword.arg is not None}
            target = functions.get(callee, {})
            if (target.get("python_value_source") and
                    not any(isinstance(value, ast.Starred) for value in node.args) and
                    all(keyword.arg is not None for keyword in node.keywords)):
                declaration = ast.parse(target["python_value_source"]).body[0]
                if not isinstance(declaration, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    invalidate()
                    return UNKNOWN
                names = [argument.arg for argument in
                         [*declaration.args.posonlyargs, *declaration.args.args]]
                # Receiver binding is deliberately left to a later qualified
                # slice; never bind a positional argument as an implicit self.
                if not names or names[0] not in {"self", "cls"}:
                    bound = dict(zip(names, values, strict=False))
                    bound.update(keywords)
                    context = tuple(sorted(bound.items()))
                    calls[site] = context
                    result = value_origins(callee, functions, context, active | {symbol})
                    if result.get("retained", True):
                        invalidate()
                    return str(result["return"])
            if isinstance(node.func, ast.Attribute):
                receiver = expression(node.func.value)
                name = node.func.attr
                if receiver in CONTAINERS and name in MUTATORS:
                    # Unknown inserted elements, keys, comparison callbacks,
                    # and iterable protocols cannot inherit literal ownership.
                    if all(value == SCALAR or value in CONTAINERS for value in values) and not keywords:
                        safe.add((positions[id(node)][0], ast.unparse(node.func)))
                        return SCALAR if name == "clear" else UNKNOWN
                    invalidate()
            if any(value in CONTAINERS for value in [*values, *keywords.values()]):
                invalidate()
            return UNKNOWN
        # Visit nested calls even when the containing expression is unsupported.
        for child in ast.iter_child_nodes(node) if node is not None else ():
            expression(child)
        return UNKNOWN

    returns: list[str] = []

    def statements(body: list[ast.stmt]) -> None:
        nonlocal unsupported_condition
        for statement in body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = expression(statement.value)
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = value
                    elif isinstance(target, ast.Subscript) and expression(target.value) in {"list", "dict"}:
                        if expression(target.slice) == SCALAR:
                            safe.add((positions[id(target)][0], ast.unparse(target)))
                        if value == UNKNOWN:
                            invalidate()
                    else:
                        invalidate()
            elif isinstance(statement, ast.Expr):
                expression(statement.value)
            elif isinstance(statement, ast.Return):
                returns.append(expression(statement.value))
                break
            elif isinstance(statement, ast.If):
                if expression(statement.test) != SCALAR:
                    unsupported_condition = True
                before = dict(env)
                statements(statement.body)
                left = dict(env)
                env.clear()
                env.update(before)
                statements(statement.orelse)
                right = dict(env)
                env.clear()
                env.update({name: left.get(name, UNKNOWN)
                            if left.get(name, UNKNOWN) == right.get(name, UNKNOWN)
                            else UNKNOWN for name in left.keys() | right.keys()})
            elif not isinstance(statement, ast.Pass):
                invalidate()
    statements(function.body)
    if unsupported_condition:
        return {**empty, "retained": True}
    # Falling through or returning different origins cannot prove fresh output.
    returned = returns[0] if returns and all(value == returns[0] for value in returns) else UNKNOWN
    return {"writes": safe, "calls": calls, "return": returned, "retained": retained}

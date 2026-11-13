"""Bounded source-derived container ownership, independent of effect purity.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

import ast
import hashlib
from typing import Any

from .semantic_python_constructor_callbacks import literal_constructor_frames

# Only exact source-allocated builtin containers qualify for structural writes.
# Borrowed children never inherit the parent's ownership.
# A value origin never qualifies a protocol callback or a filesystem effect.
UNKNOWN = "unknown"
SCALAR = "scalar"
CONTAINERS = {"list", "dict", "set", "tuple"}
OWNED = CONTAINERS | {kind + "_owned" for kind in CONTAINERS}
MUTATORS = {"append", "extend", "insert", "clear", "pop", "remove", "add",
            "discard", "update", "setdefault", "popitem", "reverse"}


def _join(left: str, right: str) -> str:
    if left == right:
        return left
    if left in OWNED and right in OWNED and left.split("_")[0] == right.split("_")[0]:
        return left.split("_")[0] + "_owned"
    return UNKNOWN


def value_origins(
    symbol: str, functions: dict[str, dict[str, Any]],
    arguments: tuple[tuple[str, str], ...] = (),
    active: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Return conservative write sites and caller bindings for one invocation.

    Unsupported control flow, escaping calls, and recursive results remain
    unknown. No project code is imported or executed to obtain these facts.
    """
    empty: dict[str, Any] = {"writes": set(), "calls": {}, "return": UNKNOWN,
                             "constructor_inputs": set(), "implicit_calls": {}, "contextual_calls": {}}
    row = functions.get(symbol, {})
    source = row.get("python_value_source")
    if not source or symbol in active or len(active) >= 24:
        return empty
    function = ast.parse(source).body[0]
    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return empty
    if hashlib.sha256(ast.dump(function, include_attributes=False).encode()).hexdigest() != row.get("python_value_shape_sha256"):
        return empty
    sites = iter(row.get("python_value_sites", []))
    positions = {id(node): next(sites, [0, 0]) for node in ast.walk(function)}
    constructor_inputs, implicit_calls = literal_constructor_frames(row, function, positions, functions)
    empty.update(constructor_inputs=constructor_inputs, implicit_calls=implicit_calls)
    env = dict(arguments)
    initializer_frame = (function.name == '__init__' and
                         env.get('$constructor_owner') == row.get('class_symbol'))
    # Protocol-driven and unbounded control flow remains unsupported.
    if any(isinstance(node, (ast.AsyncFor, ast.While, ast.Try,
                            ast.TryStar, ast.With, ast.AsyncWith, ast.Match,
                            ast.Global, ast.Nonlocal, ast.Yield, ast.YieldFrom,
                            ast.Break, ast.Continue))
           for node in ast.walk(function)):
        return {**empty, 'initializer_protocol_unknown': initializer_frame}
    safe: set[tuple[int, str]] = set()
    calls: dict[tuple[int, int], tuple[tuple[str, str], ...]] = {}
    # ast.unparse changes positions. Original call/effect positions are carried
    # in a parallel preorder inventory, never inferred from reconstructed lines.
    facts = {(call.get("line"), call.get("column")): call
             for call in row.get("calls", []) if not call.get("implicit_callback")}
    retained = False
    degraded = False
    unsupported_condition = False
    initializer_protocol_unknown = False
    contextual_calls: dict[tuple[Any, ...], str] = {}
    field_counts: dict[str, int] = {}
    for item in ast.walk(function):
        if isinstance(item, ast.Attribute) and isinstance(item.ctx, ast.Store):
            field_counts[item.attr] = field_counts.get(item.attr, 0) + 1

    def invalidate() -> None:
        nonlocal retained
        retained = True
        for name, origin in list(env.items()):
            if origin in OWNED or origin.startswith('new-object:') or origin == 'native':
                env[name] = UNKNOWN

    def degrade() -> None:
        nonlocal degraded
        degraded = True
        for name, origin in list(env.items()):
            if origin in CONTAINERS:
                env[name] = origin + "_owned"

    def expression(node: ast.AST | None) -> str:
        nonlocal initializer_protocol_unknown
        if isinstance(node, ast.Constant):
            return SCALAR
        if isinstance(node, ast.Name):
            return env.get(node.id, UNKNOWN)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            receiver = expression(node.value)
            key = expression(node.slice) if isinstance(node, ast.Subscript) else SCALAR
            if receiver in CONTAINERS | {SCALAR, 'native'} and key in CONTAINERS | {SCALAR, 'native'}:
                return 'native'
            initializer_protocol_unknown |= initializer_frame
            return UNKNOWN
        if isinstance(node, (ast.UnaryOp, ast.BinOp, ast.Compare, ast.BoolOp, ast.JoinedStr)):
            operands = [expression(child) for child in ast.iter_child_nodes(node)
                        if isinstance(child, ast.expr)]
            if operands and all(value in CONTAINERS | {SCALAR, 'native'} for value in operands):
                return SCALAR if isinstance(node, (ast.UnaryOp, ast.Compare, ast.JoinedStr)) else 'native'
            initializer_protocol_unknown |= initializer_frame
            return UNKNOWN
        if isinstance(node, ast.FormattedValue):
            value = expression(node.value)
            if value in CONTAINERS | {SCALAR, 'native'}:
                return SCALAR
            initializer_protocol_unknown |= initializer_frame
            return UNKNOWN
        if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            children = ([*node.keys, *node.values] if isinstance(node, ast.Dict)
                        else node.elts)
            origins = [expression(child) for child in children]
            if all(origin == SCALAR or origin in CONTAINERS for origin in origins):
                return type(node).__name__.lower()
            if isinstance(node, (ast.List, ast.Tuple)):
                return type(node).__name__.lower() + "_owned"
            if isinstance(node, ast.Dict) and all(expression(key) == SCALAR for key in node.keys):
                return "dict_owned"
            initializer_protocol_unknown |= initializer_frame
            return UNKNOWN
        if isinstance(node, ast.Call):
            site = tuple(positions[id(node)])
            fact = facts.get(site, {})
            callee = str(fact.get("called_symbol", ""))
            values = [expression(value) for value in node.args]
            keywords = {keyword.arg: expression(keyword.value)
                        for keyword in node.keywords if keyword.arg is not None}
            target = functions.get(callee, {})
            if (initializer_frame and isinstance(node.func, ast.Attribute) and node.func.attr == '__init__'
                    and isinstance(node.func.value, ast.Call) and isinstance(node.func.value.func, ast.Name)
                    and node.func.value.func.id == 'super' and not node.func.value.args
                    and not node.func.value.keywords and not keywords
                    and 'super' in row.get('unshadowed_container_builtins', [])
                    and env.get('$constructor_super') == 'builtins::BaseException.__init__'
                    and function.args.args and env.get(function.args.args[0].arg, '').startswith('new-object:')):
                contextual_calls[site] = 'builtins::BaseException.__init__'
                return SCALAR
            spec = fact.get('source_constructor_frame', {})
            if (spec.get('native_exception_initializer') and (*site, spec.get('subject')) in constructor_inputs):
                return UNKNOWN
            if (isinstance(node.func, ast.Name)
                    and node.func.id in row.get("unshadowed_container_builtins", [])
                    and not any(isinstance(value, ast.Starred) for value in node.args)
                    and all(keyword.arg is not None for keyword in node.keywords)):
                name = node.func.id
                if name in {"len", "bool"} and len(values) == 1 and not keywords:
                    if values[0] in OWNED | {SCALAR}:
                        return SCALAR
                if name in CONTAINERS and not values and not keywords:
                    return name
                if name in {"list", "tuple"} and len(values) == 1 and not keywords:
                    if values[0] in OWNED:
                        return name if values[0] in CONTAINERS else name + "_owned"
                if name == "dict" and not values and keywords:
                    return "dict" if all(value in CONTAINERS | {SCALAR}
                                         for value in keywords.values()) else "dict_owned"
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
                    initializer_protocol_unknown |= initializer_frame
                    bound = dict(zip(names, values, strict=False))
                    bound.update(keywords)
                    context = tuple(sorted(bound.items()))
                    calls[site] = context
                    result = value_origins(callee, functions, context, active | {symbol})
                    if result.get("retained", True):
                        invalidate()
                    elif result.get("degraded"):
                        degrade()
                    return str(result["return"])
            if isinstance(node.func, ast.Attribute):
                receiver = expression(node.func.value)
                name = node.func.attr
                if receiver in {SCALAR, 'native'} and name in {
                    'startswith', 'endswith', 'strip', 'lstrip', 'rstrip',
                    'lower', 'upper', 'casefold', 'replace'
                } and not keywords and all(value in CONTAINERS | {SCALAR, 'native'} for value in values):
                    return SCALAR
                if receiver in {"list", "list_owned"} and not keywords:
                    structural = (
                        (name == "append" and len(values) == 1)
                        or (name == "insert" and len(values) == 2 and values[0] == SCALAR)
                        or (name == "extend" and len(values) == 1 and values[0] in OWNED)
                        or (name == "reverse" and not values)
                    )
                    if structural:
                        safe.add((positions[id(node)][0], ast.unparse(node.func)))
                        if any(value not in CONTAINERS | {SCALAR} for value in values):
                            degrade()
                        return UNKNOWN
                if receiver in CONTAINERS and name in MUTATORS:
                    # Unknown inserted elements, keys, comparison callbacks,
                    # and iterable protocols cannot inherit literal ownership.
                    if all(value == SCALAR or value in CONTAINERS for value in values) and not keywords:
                        safe.add((positions[id(node)][0], ast.unparse(node.func)))
                        return SCALAR if name == "clear" else UNKNOWN
                    invalidate()
            # An unsupported expression may conceal an alias of a live local
            # (for example box['child']). Absence of a recognized owned argument
            # is not proof that an external callback cannot retain that alias.
            invalidate()
            initializer_protocol_unknown |= initializer_frame
            return UNKNOWN
        # Visit nested calls even when the containing expression is unsupported.
        if isinstance(node, ast.expr):
            initializer_protocol_unknown |= initializer_frame
        for child in ast.iter_child_nodes(node) if node is not None else ():
            expression(child)
        return UNKNOWN

    returns: list[str] = []

    def statements(body: list[ast.stmt], loop_depth: int = 0) -> bool:
        nonlocal unsupported_condition
        for statement in body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = expression(statement.value)
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = value
                    elif (initializer_frame and isinstance(target, ast.Attribute)
                          and expression(target.value).startswith('new-object:')
                          and field_counts.get(target.attr) == 1
                          and not target.attr.startswith('__') and target.attr != 'args'):
                        safe.add((positions[id(target)][0], ast.unparse(target)))
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
                return False
            elif isinstance(statement, ast.Raise):
                expression(statement.exc)
                expression(statement.cause)
                return False
            elif isinstance(statement, ast.If):
                if expression(statement.test) != SCALAR:
                    unsupported_condition = True
                before = dict(env)
                left_continues = statements(statement.body, loop_depth)
                left = dict(env)
                env.clear()
                env.update(before)
                right_continues = statements(statement.orelse, loop_depth)
                right = dict(env)
                env.clear()
                if left_continues and right_continues:
                    env.update({name: _join(left.get(name, UNKNOWN), right.get(name, UNKNOWN))
                                for name in left.keys() | right.keys()})
                elif left_continues:
                    env.update(left)
                elif right_continues:
                    env.update(right)
                else:
                    return False
            elif isinstance(statement, ast.For):
                iterator = expression(statement.iter)
                if iterator not in OWNED or loop_depth >= 3:
                    unsupported_condition = True
                    continue
                before = dict(env)
                base_safe, base_calls, base_returns = set(safe), dict(calls), list(returns)
                # The ownership lattice loses precision at joins; three rounds
                # cover owned -> shallow -> unknown. Publish only the final
                # fixed-point observation, never optimistic first-iteration sites.
                guess = dict(before)
                converged = False
                for _ in range(4):
                    env.clear()
                    env.update(guess)
                    if isinstance(statement.target, ast.Name):
                        env[statement.target.id] = UNKNOWN
                    else:
                        unsupported_condition = True
                    safe.clear()
                    safe.update(base_safe)
                    calls.clear()
                    calls.update(base_calls)
                    returns[:] = base_returns
                    statements(statement.body, loop_depth + 1)
                    joined = {name: _join(before.get(name, UNKNOWN), env.get(name, UNKNOWN))
                              for name in before.keys() | env.keys()}
                    if joined == guess:
                        converged = True
                        break
                    guess = joined
                if not converged:
                    unsupported_condition = True
                env.clear()
                env.update(guess)
                statements(statement.orelse, loop_depth)
            elif not isinstance(statement, ast.Pass):
                invalidate()
                if initializer_frame:
                    unsupported_condition = True
        return True
    statements(function.body)
    if unsupported_condition:
        return {**empty, "retained": True, 'initializer_protocol_unknown': initializer_frame}
    # Falling through or returning different origins cannot prove fresh output.
    returned = returns[0] if returns and all(value == returns[0] for value in returns) else UNKNOWN
    return {"writes": safe, "calls": calls, "return": returned,
            "retained": retained, "degraded": degraded, 'constructor_inputs': constructor_inputs,
            'implicit_calls': implicit_calls, 'contextual_calls': contextual_calls,
            'initializer_protocol_unknown': initializer_protocol_unknown}

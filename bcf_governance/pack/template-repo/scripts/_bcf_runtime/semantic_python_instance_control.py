"""Identity-only control joins; unresolved execution never confers heap ownership."""
from __future__ import annotations

import ast
import json
from typing import Any

from .semantic_python_private_fields import (
    FIELD,
    SCALAR,
    apply_owner_states,
    field_origin,
    instance_key,
    join_instances,
    lose_field_ownership,
    merge_field_alternatives,
    owner_states,
    update_private_field,
)

PREFIX = "source-instance:"
UNKNOWN = "unknown"


def instance_control_contexts(
    row: dict[str, Any], function: ast.FunctionDef | ast.AsyncFunctionDef,
    functions: dict[str, dict[str, Any]], arguments: tuple[tuple[str, str], ...],
    positions: dict[int, list[int]], active: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Retain only constructor identities valid at every continuing join."""
    from .semantic_python_callable_frames import scoped_nodes
    nodes = scoped_nodes(function)
    def factory_candidate(symbol: str) -> bool:
        target_row = functions.get(symbol, {})
        return bool(target_row.get("source_binding_stable")) and any(
            call.get("source_constructor_frame", {}).get("instance_methods")
            for call in target_row.get("calls", []))
    has_factory = any(factory_candidate(str(call.get("called_symbol", "")))
                      for call in row.get("calls", []))
    if not (has_factory and any(isinstance(node, (ast.With, ast.AsyncWith, ast.For, ast.AsyncFor)) for node in nodes)
            or any(value.startswith(PREFIX) for _, value in arguments)):
        return {}
    if row["symbol"] in active or len(active) >= 12:
        return {"instance_control_obligations": {(0, "recursive_identity")},
                "instance_escaped": {value for _, value in arguments if value.startswith(PREFIX)}}
    active = active | {str(row["symbol"])}
    env = dict(arguments)
    calls: dict[tuple[int, int], tuple[tuple[str, str], ...]] = {}
    contextual: dict[tuple[int, int], str] = {}
    obligations: set[tuple[int, str]] = set()
    escaped: set[str] = set()
    returned: list[str] = []
    private_writes: dict[tuple[int, str], bool] = {}
    private_loss = [False]
    facts = {(call.get("line"), call.get("column")): call for call in row.get("calls", []) if not call.get("implicit_callback")}
    globals_ = {name for node in nodes if isinstance(node, (ast.Global, ast.Nonlocal)) for name in node.names}
    work = [5000]

    def site(node: ast.AST) -> tuple[int, int]:
        return tuple(positions.get(id(node), [0, 0]))  # type: ignore[return-value]

    def is_escaped(value: str) -> bool:
        return value.startswith(PREFIX) and any(instance_key(value) == instance_key(old) for old in escaped)

    def lose_private(value: str) -> None:
        private_loss[0] = True
        lose_field_ownership(env, value)

    def kill(value: str | None = None) -> None:
        victims = {value} if value and value.startswith(PREFIX) else {v for v in env.values() if v.startswith(PREFIX)}
        escaped.update(victims)
        for name, origin in list(env.items()):
            if any(instance_key(origin) and instance_key(origin) == instance_key(victim) for victim in victims):
                env[name] = UNKNOWN

    def join(paths: list[dict[str, str]]) -> dict[str, str]:
        if not paths:
            return {}
        names = set().union(*(path.keys() for path in paths))
        joined = {}
        for name in names:
            values = [path.get(name, UNKNOWN) for path in paths]
            if any(is_escaped(value) for value in values):
                joined[name] = UNKNOWN
            elif len(set(values)) == 1:
                joined[name] = values[0]
            else:
                joined[name] = join_instances(values)
        return joined

    def assign(target: ast.AST, value: str) -> None:
        if isinstance(target, ast.Name):
            if target.id in globals_:
                kill(value)
                env[target.id] = UNKNOWN
            else:
                env[target.id] = value if not is_escaped(value) else UNKNOWN
        elif isinstance(target, ast.Attribute):
            owner = expression(target.value)
            if value.startswith(PREFIX):
                kill(value)
            elif value.startswith(FIELD):
                lose_private(value)
            if owner.startswith(PREFIX):
                spec = json.loads(owner.removeprefix(PREFIX))
                if target.attr not in spec.get("fields", []) or target.attr in spec["methods"]:
                    kill(owner)
                else:
                    safe = update_private_field(env, owner, target.attr, value)
                    key = (site(target)[0], ast.unparse(target))
                    private_writes[key] = private_writes.get(key, True) and safe
                    private_loss[0] |= not safe
        else:
            if value.startswith(PREFIX):
                kill(value)
            elif value.startswith(FIELD):
                lose_private(value)
            for child in ast.iter_child_nodes(target):
                expression(child)

    def expression(node: ast.AST | None) -> str:
        if node is None:
            return UNKNOWN
        work[0] -= 1
        if work[0] < 0:
            kill()
            obligations.add((site(node)[0], "identity_budget"))
            return UNKNOWN
        if isinstance(node, ast.Name):
            origin = env.get(node.id, UNKNOWN)
            if is_escaped(origin):
                return UNKNOWN
            if origin.startswith(FIELD):
                field = json.loads(origin.removeprefix(FIELD))
                state = owner_states(env).get(field["owner"], {})
                return origin if all(state.get(name) == "native-set" for name in field["fields"]) else UNKNOWN
            return origin
        if isinstance(node, ast.Constant):
            return SCALAR if type(node.value) in {str, bytes, int, float, complex, bool, type(None)} else UNKNOWN
        if isinstance(node, ast.IfExp):
            expression(node.test)
            return merge_field_alternatives(expression(node.body), expression(node.orelse))
        if isinstance(node, ast.Attribute):
            origin = expression(node.value)
            if origin.startswith(PREFIX):
                payload = json.loads(origin.removeprefix(PREFIX))
                known = field_origin(origin, node.attr)
                if known != UNKNOWN:
                    return known
                if node.attr not in payload.get("fields", []):
                    # Bound handles, properties and reflective attributes can
                    # carry or expose the receiver; only direct calls bind it.
                    kill(origin)
            return UNKNOWN
        if isinstance(node, ast.Await):
            result = expression(node.value)
            if any(value.startswith(PREFIX) for value in env.values()):
                obligations.add((site(node)[0], "await"))
            return result
        if isinstance(node, ast.Call):
            point = site(node)
            call = facts.get(point, {})
            receiver = expression(node.func.value) if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, (ast.Name, ast.Attribute)) else UNKNOWN
            target = str(call.get("called_symbol", ""))
            if receiver.startswith(PREFIX) and isinstance(node.func, ast.Attribute):
                target = str(json.loads(receiver.removeprefix(PREFIX))["methods"].get(node.func.attr, ""))
                if target in functions:
                    contextual[point] = target
                else:
                    kill(receiver)
            values = [expression(arg) for arg in node.args]
            keywords = {arg.arg: expression(arg.value) for arg in node.keywords if arg.arg is not None}
            for argument in [*values, *keywords.values()]:
                if argument.startswith(FIELD):
                    lose_private(argument)
            reflective = isinstance(node.func, ast.Name) and node.func.id in {"globals", "locals", "vars", "eval", "exec", "getattr", "setattr", "delattr", "__import__"}
            if reflective or any(isinstance(arg, ast.Starred) for arg in node.args) or any(arg.arg is None for arg in node.keywords):
                kill()
                obligations.add((point[0], "uncertain_identity_call"))
                return UNKNOWN
            source = functions.get(target, {}).get("python_value_source")
            shadowed = isinstance(node.func, ast.Name) and node.func.id in env
            if source and not shadowed and functions[target].get("source_binding_stable") and not functions[target].get("decorators"):
                declaration = ast.parse(source).body[0]
                if isinstance(declaration, (ast.FunctionDef, ast.AsyncFunctionDef)) and not declaration.args.vararg and not declaration.args.kwarg:
                    names = [arg.arg for arg in [*declaration.args.posonlyargs, *declaration.args.args]]
                    bound_method = bool(names and names[0] == "self" and isinstance(node.func, ast.Attribute) and (receiver.startswith(PREFIX) or call.get("dispatch_resolution") == "exact_same_instance"))
                    formal_names = names[1:] if bound_method else names
                    bound = dict(zip(formal_names, values, strict=False))
                    bound.update(keywords)
                    if bound_method:
                        bound[names[0]] = receiver
                    carries = any(value.startswith(PREFIX) for value in bound.values())
                    if carries:
                        bound["$source_callable_proof"] = "true"
                        calls[point] = tuple(sorted(bound.items()))
                        child_positions = {id(child): position for child, position in zip(ast.walk(declaration), functions[target].get("python_value_sites", []), strict=False)}
                        child_result = instance_control_contexts(functions[target], declaration, functions, tuple(sorted(bound.items())), child_positions, active)
                        for lost in child_result.get("instance_escaped", set()):
                            kill(lost)
                        apply_owner_states(env, child_result.get("instance_owner_states", {}))
                        private_loss[0] |= bool(child_result.get("instance_private_loss"))
                        return str(child_result.get("instance_return", UNKNOWN))
                    # Existing constructor/factory analysis remains the only
                    # producer. This analysis cannot mint an instance identity.
                    if not factory_candidate(target):
                        return UNKNOWN
                    from .semantic_python_value_origins import value_origins
                    factory_result = value_origins(target, functions, tuple(sorted(bound.items())), active)
                    origin = str(factory_result.get("return", UNKNOWN))
                    return origin if origin.startswith(PREFIX) else UNKNOWN
            for value in [receiver, *values, *keywords.values()]:
                if value.startswith(PREFIX):
                    kill(value)
                elif value.startswith(FIELD):
                    lose_private(value)
                    obligations.add((point[0], "private_set_protocol"))
            if not isinstance(node.func, (ast.Name, ast.Attribute)):
                expression(node.func)
            elif isinstance(node.func, ast.Attribute) and not isinstance(node.func.value, ast.Name):
                expression(node.func.value)
            return UNKNOWN
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            # Creating a capture is conservative until its nonescape proof is
            # connected to this separate identity lattice.
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                    origin = env.get(child.id, UNKNOWN)
                    if origin.startswith(PREFIX):
                        kill(origin)
                    elif origin.startswith(FIELD):
                        lose_private(origin)
            return UNKNOWN
        for child in ast.iter_child_nodes(node):
            origin = expression(child)
            if origin.startswith(PREFIX):
                # Containers, operators, f-strings and unpacking cannot conceal
                # an identity alias from a subsequent external call.
                kill(origin)
            elif origin.startswith(FIELD):
                lose_private(origin)
                obligations.add((site(node)[0], "private_set_protocol"))
        return UNKNOWN

    def block(body: list[ast.stmt], prefixes: list[dict[str, str]] | None = None) -> str:
        for node in body:
            if prefixes is not None:
                prefixes.append(dict(env))
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = expression(node.value)
                for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                    assign(target, value)
            elif isinstance(node, ast.AugAssign):
                old_value = expression(node.target)
                value = expression(node.value)
                if old_value.startswith(PREFIX):
                    kill(old_value)
                assign(node.target, value)
                obligations.add((site(node)[0], "augmented_protocol"))
            elif isinstance(node, ast.Assert):
                expression(node.test)
                expression(node.msg)
                obligations.add((site(node)[0], "assertion_protocol"))
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    assign(target, UNKNOWN)
                obligations.add((site(node)[0], "deletion_protocol"))
            elif isinstance(node, ast.Expr):
                expression(node.value)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                expression(node)
                env[node.name] = UNKNOWN
            elif isinstance(node, ast.If):
                expression(node.test)
                start = dict(env)
                left_status = block(node.body, prefixes)
                left = dict(env)
                env.clear()
                env.update(start)
                right_status = block(node.orelse, prefixes)
                right = dict(env)
                continuing = [path for status, path in [(left_status, left), (right_status, right)] if status == "continue"]
                env.clear()
                env.update(join(continuing or [left, right]))
                if not continuing:
                    return left_status if left_status == right_status else "raise"
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    value = expression(item.context_expr)
                    if value.startswith(PREFIX):
                        kill(value)
                    if item.optional_vars is not None:
                        assign(item.optional_vars, UNKNOWN)
                if any(value.startswith(PREFIX) for value in env.values()):
                    obligations.add((site(node)[0], "async_context" if isinstance(node, ast.AsyncWith) else "context"))
                start = dict(env)
                paths = [start]
                status = block(node.body, paths)
                paths.append(dict(env))
                # __exit__/__aexit__ may suppress an exception at any prefix.
                env.clear()
                env.update(join(paths))
                if status in {"return", "break", "loop_continue"}:
                    return status
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                expression(node.test if isinstance(node, ast.While) else node.iter)
                if any(value.startswith(PREFIX) for value in env.values()):
                    obligations.add((site(node)[0], "iteration"))
                entry = dict(env)
                guess = dict(entry)
                base_calls, base_contextual = dict(calls), dict(contextual)
                base_private_writes = dict(private_writes)
                for _ in range(3):
                    calls.clear()
                    calls.update(base_calls)
                    private_writes.clear()
                    private_writes.update(base_private_writes)
                    contextual.clear()
                    contextual.update(base_contextual)
                    env.clear()
                    env.update(guess)
                    if not isinstance(node, ast.While):
                        assign(node.target, UNKNOWN)
                    block(node.body, prefixes)
                    merged = join([entry, dict(env)])
                    if merged == guess:
                        break
                    guess = merged
                else:
                    kill()
                    calls.clear()
                    calls.update(base_calls)
                    private_writes.clear()
                    private_writes.update(base_private_writes)
                    contextual.clear()
                    contextual.update(base_contextual)
                    obligations.add((site(node)[0], "identity_fixed_point"))
                env.clear()
                env.update(merged)
                block(node.orelse, prefixes)
            elif isinstance(node, ast.Try):
                start = dict(env)
                partial = [start]
                status = block(node.body, partial)
                paths = [dict(env)] if status == "continue" else []
                for handler in node.handlers:
                    env.clear()
                    env.update(join(partial))
                    if handler.name:
                        env[handler.name] = UNKNOWN
                    if block(handler.body, prefixes) == "continue":
                        paths.append(dict(env))
                env.clear()
                env.update(join(paths or partial))
                block(node.orelse, prefixes)
                block(node.finalbody, prefixes)
            elif isinstance(node, ast.Return):
                value = expression(node.value)
                if value.startswith((PREFIX, FIELD)):
                    lose_private(value)
                    value = UNKNOWN if value.startswith(FIELD) else next((origin for origin in env.values() if origin.startswith(PREFIX) and instance_key(origin) == instance_key(value)), UNKNOWN)
                returned.append(value)
                return "return"
            elif isinstance(node, ast.Raise):
                value = expression(node.exc)
                if value.startswith(PREFIX):
                    kill(value)
                expression(node.cause)
                return "raise"
            elif isinstance(node, ast.Break):
                return "break"
            elif isinstance(node, ast.Continue):
                return "loop_continue"
            elif isinstance(node, (ast.Global, ast.Nonlocal, ast.Pass)):
                continue
            else:
                expression(node)
                kill()
                obligations.add((site(node)[0], "unsupported_identity_control"))
            if prefixes is not None:
                prefixes.append(dict(env))
        return "continue"

    block(function.body)
    return {"instance_calls": calls, "instance_contextual_calls": contextual,
            "instance_control_obligations": obligations, "instance_escaped": escaped,
            "instance_return": returned[0] if returned and len(set(returned)) == 1 else UNKNOWN,
            "instance_owner_states": owner_states(env), "instance_private_loss": private_loss[0],
            "instance_private_writes": {key for key, safe in private_writes.items() if safe}}

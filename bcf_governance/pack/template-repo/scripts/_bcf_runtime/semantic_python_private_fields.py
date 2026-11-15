"""Private field origins never authorize unknown keys or container mutation."""
from __future__ import annotations

import ast
import json
from typing import Any

INSTANCE = "source-instance:"
FIELD = "private-set:"
UNKNOWN = "unknown"
SCALAR = "scalar"


def instance_key(origin: str) -> str:
    if not origin.startswith(INSTANCE):
        return ""
    row = json.loads(origin.removeprefix(INSTANCE))
    return json.dumps([row["subject"], row["site"]], sort_keys=True)


def initial_private_fields(initializer: dict[str, Any], allowed_fields: set[str]) -> dict[str, str]:
    """Only unconditional single assignments establish initial field facts."""
    source = initializer.get("python_value_source")
    if not source:
        return {}
    function = ast.parse(source).body[0]
    if not isinstance(function, ast.FunctionDef):
        return {}
    args = [*function.args.posonlyargs, *function.args.args]
    if not args:
        return {}
    receiver = args[0].arg
    writes: dict[str, list[ast.AST | None]] = {}
    for node in ast.walk(function):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == receiver:
                    writes.setdefault(target.attr, []).append(node.value)
    result = {}
    for node in function.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        if isinstance(node, ast.Assign) and len(node.targets) != 1:
            continue
        for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
            if not (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                    and target.value.id == receiver and len(writes.get(target.attr, [])) == 1):
                continue
            value = node.value
            state = UNKNOWN
            if isinstance(value, ast.Constant) and type(value.value) in {str, bytes, int, float, complex, bool, type(None)}:
                state = SCALAR
            elif (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                  and value.func.id == "set" and not value.args and not value.keywords
                  and "set" in initializer.get("unshadowed_container_builtins", [])):
                # Native object identity only: no empty-content snapshot is
                # reapplied on subsequent calls and no key protocol is granted.
                state = "native-set"
            result[target.attr] = state
    for node in ast.walk(function):
        if (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load)
                and isinstance(node.value, ast.Name) and node.value.id == receiver
                and result.get(node.attr) == "native-set"):
            result[node.attr] = UNKNOWN
    return {name: state for name, state in result.items() if name in allowed_fields}


def field_origin(owner: str, name: str) -> str:
    if not owner.startswith(INSTANCE):
        return UNKNOWN
    payload = json.loads(owner.removeprefix(INSTANCE))
    state = payload.get("private_fields", {}).get(name, UNKNOWN) if name in payload.get("fields", []) else UNKNOWN
    if state == SCALAR:
        return SCALAR
    if state == "native-set":
        return FIELD + json.dumps({"owner": instance_key(owner), "fields": [name]}, sort_keys=True)
    return UNKNOWN


def merge_field_alternatives(left: str, right: str) -> str:
    if left == right:
        return left
    if left.startswith(FIELD) and right.startswith(FIELD):
        a, b = [json.loads(value.removeprefix(FIELD)) for value in (left, right)]
        if a["owner"] == b["owner"]:
            return FIELD + json.dumps({"owner": a["owner"], "fields": sorted(set(a["fields"]) | set(b["fields"]))}, sort_keys=True)
    return UNKNOWN


def owner_states(env: dict[str, str]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for value in env.values():
        if not value.startswith(INSTANCE):
            continue
        state = json.loads(value.removeprefix(INSTANCE)).get("private_fields", {})
        key = instance_key(value)
        if key not in result:
            result[key] = dict(state)
        else:
            result[key] = {name: state.get(name, UNKNOWN) if state.get(name, UNKNOWN) == result[key].get(name, UNKNOWN) else UNKNOWN for name in state.keys() | result[key].keys()}
    return result


def apply_owner_states(env: dict[str, str], states: dict[str, dict[str, str]]) -> None:
    """Ownership can only be retained or lost; another allocation cannot restore it."""
    for name, value in list(env.items()):
        if value.startswith(INSTANCE) and instance_key(value) in states:
            payload = json.loads(value.removeprefix(INSTANCE))
            prior = payload.get("private_fields", {})
            incoming = states[instance_key(value)]
            payload["private_fields"] = {field: prior.get(field, UNKNOWN) if prior.get(field, UNKNOWN) == incoming.get(field, UNKNOWN) else UNKNOWN for field in prior.keys() | incoming.keys()}
            env[name] = INSTANCE + json.dumps(payload, sort_keys=True)
        elif value.startswith(FIELD):
            payload = json.loads(value.removeprefix(FIELD))
            if payload["owner"] in states and any(states[payload["owner"]].get(field) != "native-set" for field in payload["fields"]):
                env[name] = UNKNOWN


def lose_field_ownership(env: dict[str, str], value: str) -> None:
    states = owner_states(env)
    if value.startswith(FIELD):
        payload = json.loads(value.removeprefix(FIELD))
        state = states.get(payload["owner"], {})
        for field in payload["fields"]:
            state[field] = UNKNOWN
        states[payload["owner"]] = state
    elif value.startswith(INSTANCE):
        key = instance_key(value)
        states[key] = {field: UNKNOWN for field in states.get(key, {})}
    apply_owner_states(env, states)


def update_private_field(env: dict[str, str], owner: str, field: str, replacement: str) -> bool:
    """Both decref of the old value and storage of the replacement need proof."""
    if not owner.startswith(INSTANCE):
        return False
    state = json.loads(owner.removeprefix(INSTANCE)).get("private_fields", {})
    safe = state.get(field) == SCALAR and replacement == SCALAR
    if not safe:
        states = owner_states(env)
        key = instance_key(owner)
        prior = states.setdefault(key, dict(state))
        prior[field] = UNKNOWN
        apply_owner_states(env, states)
    return safe


def join_instances(values: list[str]) -> str:
    """Field-state loss must not manufacture a different instance identity."""
    if not values or not all(value.startswith(INSTANCE) for value in values):
        return UNKNOWN
    key = instance_key(values[0])
    if not all(instance_key(value) == key for value in values):
        return UNKNOWN
    payloads = [json.loads(value.removeprefix(INSTANCE)) for value in values]
    if any({k: v for k, v in item.items() if k != "private_fields"} != {k: v for k, v in payloads[0].items() if k != "private_fields"} for item in payloads):
        return UNKNOWN
    fields = set().union(*(item.get("private_fields", {}).keys() for item in payloads))
    payloads[0]["private_fields"] = {field: payloads[0].get("private_fields", {}).get(field, UNKNOWN) if all(item.get("private_fields", {}).get(field, UNKNOWN) == payloads[0].get("private_fields", {}).get(field, UNKNOWN) for item in payloads) else UNKNOWN for field in fields}
    return INSTANCE + json.dumps(payloads[0], sort_keys=True)


def without_private_ownership(origin: str) -> str:
    """Returning an alias cannot reintroduce a field frame lost by the callee."""
    if origin.startswith(FIELD):
        return UNKNOWN
    if origin.startswith(INSTANCE):
        payload = json.loads(origin.removeprefix(INSTANCE))
        payload["private_fields"] = {name: UNKNOWN for name in payload.get("private_fields", {})}
        return INSTANCE + json.dumps(payload, sort_keys=True)
    return origin

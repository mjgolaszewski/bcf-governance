"""Neutral deferred source callables and closed lexical capture frames.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

import ast
import json
from typing import Any

from .semantic_python_effect_obligations import extend_python_effect_facts
from .semantic_python_execution_inventory import _FunctionVisitor


def callable_default_origin(node: ast.AST) -> str:
    """Recognize a literal value, without qualifying a callable's body."""
    if isinstance(node, ast.Constant):
        return "scalar"
    if isinstance(node, ast.Tuple) and not node.elts:
        return "tuple"
    return "unknown"


def source_callable_origin(definition: dict[str, Any], env: dict[str, str]) -> str:
    """Bind a stable recursive cell after definition, without recursive JSON."""
    if not definition.get("stable"):
        return "unknown"
    recursive = ([definition["name"]] if definition.get("kind") == "function"
                 and definition["name"] in definition.get("captures", []) else [])
    return "callable:" + json.dumps({"symbol": definition["symbol"],
        "captures": {name: env.get(name, "unknown") for name in definition.get("captures", []) if name not in recursive},
        "recursive_cells": recursive}, sort_keys=True)


def source_callable_captures(origin: str) -> tuple[str, dict[str, str]]:
    payload = json.loads(origin.removeprefix("callable:"))
    captured = dict(payload["captures"])
    for name in payload.get("recursive_cells", []):
        captured[name] = origin
    return str(payload["symbol"]), captured


def scoped_nodes(root: ast.AST) -> list[ast.AST]:
    result: list[ast.AST] = []
    def visit(node: ast.AST) -> None:
        result.append(node)
        if node is not root and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            return
        for child in ast.iter_child_nodes(node):
            visit(child)
    visit(root)
    return result



def lexical_parent_receiver(
    node: ast.FunctionDef | ast.AsyncFunctionDef, fact: dict[str, Any],
    captures: set[str], stable: bool,
) -> str | None:
    """Describe one unchanged lexical instance cell, never its dynamic type."""
    args = [*node.args.posonlyargs, *node.args.args]
    if (not stable or not args or not fact.get("class_symbol")
            or fact.get("scope_kind") == "source_callable_frame" or node.decorator_list):
        return None
    receiver = args[0].arg
    if receiver not in captures:
        return None
    nodes = scoped_nodes(node)
    parents = {id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)}
    for value in nodes:
        if isinstance(value, (ast.Nonlocal, ast.Global)) or (
            isinstance(value, ast.Name) and value.id in {
                "globals", "locals", "vars", "eval", "exec", "getattr", "setattr", "delattr"
            }
        ):
            return None
        if isinstance(value, ast.Name) and value.id == receiver:
            parent = parents.get(id(value))
            if (not isinstance(value.ctx, ast.Load) or not isinstance(parent, ast.Attribute)
                    or parent.value is not value):
                return None
    return receiver


def discover_source_callable_frames(
    tree: ast.Module, roots: list[dict[str, Any]], *, path: str,
    imports: dict[str, str], import_bindings: dict[str, dict[str, Any]],
    local_types: set[str], builtin_names: list[str],
) -> list[dict[str, Any]]:
    """Add deferred bodies without replacing existing source ownership facts."""
    result: list[dict[str, Any]] = []
    by_line = {node.lineno: node for node in ast.walk(tree)
               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}

    def descend(node: ast.FunctionDef | ast.AsyncFunctionDef, fact: dict[str, Any], inherited: set[str]) -> None:
        nodes = scoped_nodes(node)
        local = {arg.arg for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]}
        local.update(value.id for value in nodes if isinstance(value, ast.Name) and isinstance(value.ctx, (ast.Store, ast.Del)))
        local.update(value.name for value in nodes if value is not node and isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef)))
        lexical = local | inherited
        definitions = []
        for child in nodes:
            if child is node or not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            lambda_node = isinstance(child, ast.Lambda)
            name = f"<lambda@{child.lineno}.{child.col_offset}>" if isinstance(child, ast.Lambda) else child.name
            symbol = str(fact["symbol"]) + "." + name
            if not lambda_node and sum(
                isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef))
                and value.name == name for value in nodes
            ) > 1:
                # Distinct branch-local declarations are separate source facts.
                # Their lexical binding remains unstable below; a unique site
                # identity never selects which body a dynamic call will invoke.
                symbol += f"@{child.lineno}.{child.col_offset}"
            if isinstance(child, ast.Lambda):
                body = ast.copy_location(ast.Return(value=child.body), child)
                declaration = ast.parse("def source_lambda(): pass").body[0]
                assert isinstance(declaration, ast.FunctionDef)
                declaration.args = child.args
                declaration.body = [body]
                ast.copy_location(declaration, child)
                ast.fix_missing_locations(declaration)
            else:
                declaration = child
            child_nodes = scoped_nodes(declaration)
            parameters = {arg.arg for arg in [*declaration.args.posonlyargs, *declaration.args.args, *declaration.args.kwonlyargs]}
            bound = parameters | {value.id for value in child_nodes if isinstance(value, ast.Name) and isinstance(value.ctx, (ast.Store, ast.Del))}
            free = {value.id for value in child_nodes if isinstance(value, ast.Name) and isinstance(value.ctx, ast.Load)} - bound
            captures = free & lexical
            stable = not declaration.decorator_list and not declaration.args.vararg and not declaration.args.kwarg
            stable &= all(callable_default_origin(value) != "unknown" for value in [*declaration.args.defaults, *declaration.args.kw_defaults] if value is not None)
            stable &= not any(isinstance(value, (ast.Nonlocal, ast.Global)) for value in child_nodes)
            if not lambda_node:
                stable &= sum(isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef)) and value.name == name for value in nodes) == 1
                stable &= not any(isinstance(value, ast.Name) and value.id == name and isinstance(value.ctx, (ast.Store, ast.Del)) for value in nodes)
            stable &= not any(isinstance(value, ast.Name) and value.id in captures and isinstance(value.ctx, (ast.Store, ast.Del)) and value.lineno > child.lineno for value in nodes)
            visitor = _FunctionVisitor(path=path, imports=imports, import_bindings=import_bindings,
                local_types=local_types, class_name=None, function=declaration, initializer_symbol=symbol)
            for capture in captures:
                visitor.assignments[capture] = {"parameter:" + capture}
            parent_receiver = lexical_parent_receiver(node, fact, captures, bool(stable))
            if parent_receiver is not None:
                visitor.class_symbol = str(fact["class_symbol"])
                visitor.receiver = parent_receiver
                visitor.method_binding_kind = "instance"
                visitor.receiver_rebound = False
            for statement in declaration.body:
                visitor.visit(statement)
            child_fact = visitor.facts()
            if parent_receiver is not None:
                child_fact["lexical_parent_instance_capture"] = {
                    "parent_symbol": fact["symbol"], "receiver": parent_receiver,
                    "class_symbol": fact["class_symbol"],
                }
            extend_python_effect_facts(tree, declaration, child_fact, path, builtin_names=builtin_names)
            child_fact["scope_kind"] = "source_callable_frame"
            definitions.append({"kind": "lambda" if lambda_node else "function", "name": name,
                "line": child.lineno, "column": child.col_offset, "symbol": symbol,
                "captures": sorted(captures), "stable": bool(stable)})
            result.append(child_fact)
            descend(declaration, child_fact, captures)
        fact["source_callable_definitions"] = definitions

    for fact in roots:
        sites = fact.get("python_value_sites", [])
        node = by_line.get(sites[0][0]) if sites else None
        if node is not None and ast.unparse(node) != fact.get("python_value_source"):
            node = None
        if node is not None:
            descend(node, fact, set())
    return result



def lexical_callable_contexts(
    row: dict[str, Any], function: ast.FunctionDef | ast.AsyncFunctionDef,
    functions: dict[str, dict[str, Any]], arguments: tuple[tuple[str, str], ...],
    positions: dict[int, list[int]],
) -> dict[str, Any]:
    """Only single-use fresh definitions and nonescaping callable parameters qualify.

    Captured values stay unknown in this fallback; it never grants native or
    receiver ownership from an annotation or a surrounding opaque call.
    """
    nodes = scoped_nodes(function)
    parents = {id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)}
    env = dict(arguments)
    bound_names = {value.id for value in nodes if isinstance(value, ast.Name) and isinstance(value.ctx, (ast.Store, ast.Del))}
    bound_names.update(value.name for value in nodes if value is not function and isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef)))
    definitions = row.get("source_callable_definitions", [])
    facts = {(value.get("line"), value.get("column")): value for value in row.get("calls", []) if not value.get("implicit_callback")}
    calls: dict[tuple[int, int], tuple[tuple[str, str], ...]] = {}
    contextual: dict[tuple[int, int], str] = {}
    inactive_calls: set[tuple[int, int]] = set()
    unresolved_bindings: set[tuple[int, int]] = set()
    inactive_lines: set[int] = set()

    def known(node: ast.AST) -> bool | None:
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.Is, ast.IsNot)) and len(node.comparators) == 1:
            left, right = node.left, node.comparators[0]
            if isinstance(left, ast.Name) and left.id not in bound_names and isinstance(right, ast.Constant) and right.value is None:
                absent = env.get("$none:" + left.id) == "true"
                present = env.get(left.id, "").startswith("callable:")
                if absent or present:
                    return absent if isinstance(node.ops[0], ast.Is) else present
        if isinstance(node, ast.BoolOp):
            values = [known(value) for value in node.values]
            if isinstance(node.op, ast.And):
                return False if False in values else True if all(value is True for value in values) else None
            return True if True in values else False if all(value is False for value in values) else None
        return None

    for statement in nodes:
        if not isinstance(statement, ast.If):
            continue
        condition = known(statement.test)
        if condition is None:
            continue
        omitted = statement.orelse if condition else statement.body
        condition_lines = {positions[id(value)][0] for value in ast.walk(statement.test)}
        for body in omitted:
            for value in ast.walk(body):
                if id(value) not in positions:
                    continue
                if positions[id(value)][0] not in condition_lines:
                    inactive_lines.add(positions[id(value)][0])
                if isinstance(value, ast.Call):
                    inactive_calls.add((positions[id(value)][0], positions[id(value)][1]))

    def origin(node: ast.AST) -> str:
        if isinstance(node, ast.Constant):
            return "scalar"
        definition = next((value for value in definitions if
            isinstance(node, ast.Name) and value["kind"] == "function" and value["name"] == node.id
            or isinstance(node, ast.Lambda) and value["kind"] == "lambda" and (value["line"], value["column"]) == tuple(positions[id(node)])), None)
        if definition is None or not definition.get("stable"):
            return "unknown"
        if isinstance(node, ast.Name):
            uses = [value for value in nodes if isinstance(value, ast.Name) and value.id == node.id and isinstance(value.ctx, ast.Load)]
            if len(uses) != 1:
                return "unknown"
            if any(isinstance(value, ast.Call) and definition["line"] < value.lineno < node.lineno for value in nodes):
                return "unknown"
        return source_callable_origin(definition, {})

    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        site = (positions[id(node)][0], positions[id(node)][1])
        if site in inactive_calls:
            continue
        if isinstance(node.func, ast.Name) and any(
            value["name"] == node.func.id and not value.get("stable")
            for value in definitions
        ):
            unresolved_bindings.add(site)
        target = str(facts.get(site, {}).get("called_symbol", ""))
        captured: dict[str, str] = {}
        if isinstance(node.func, ast.Name) and env.get(node.func.id, "").startswith("callable:") and node.func.id not in bound_names:
            uses = [value for value in nodes if isinstance(value, ast.Name) and value.id == node.func.id and isinstance(value.ctx, ast.Load)]
            safe = True
            for value in uses:
                parent = parents.get(id(value))
                if not (isinstance(parent, ast.Call) and parent.func is value
                        or isinstance(parent, ast.Compare) and known(parent) is not None):
                    safe = False
            if not safe:
                continue
            target, captured = source_callable_captures(env[node.func.id])
            if functions.get(target, {}).get("scope_kind") != "source_callable_frame":
                continue
            contextual[site] = target
        source = functions.get(target, {}).get("python_value_source")
        if not source or any(isinstance(value, ast.Starred) for value in node.args) or any(value.arg is None for value in node.keywords):
            continue
        declaration = ast.parse(source).body[0]
        if not isinstance(declaration, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        names = [value.arg for value in [*declaration.args.posonlyargs, *declaration.args.args]]
        if names and names[0] in {"self", "cls"}:
            continue
        bound = {name: origin(value) for name, value in zip(names, node.args, strict=False)}
        bound.update({keyword.arg: origin(keyword.value) for keyword in node.keywords if keyword.arg is not None})
        bound.update(captured)
        if functions.get(target, {}).get("scope_kind") == "source_callable_frame" or env.get("$source_callable_proof") == "true":
            bound["$source_callable_proof"] = "true"
        defaults = list(zip(names[-len(declaration.args.defaults):], declaration.args.defaults, strict=True)) if declaration.args.defaults else []
        defaults.extend((value.arg, default) for value, default in zip(declaration.args.kwonlyargs, declaration.args.kw_defaults, strict=True) if default is not None)
        for name, default in defaults:
            if name not in bound:
                bound[name] = callable_default_origin(default)
                if isinstance(default, ast.Constant) and default.value is None:
                    bound["$none:" + name] = "true"
        if any(value.startswith("callable:") for value in bound.values()) or captured:
            calls[site] = tuple(sorted(bound.items()))
    unqualified_awaits = set()
    for node in nodes:
        if not isinstance(node, ast.Await) or not isinstance(node.value, ast.Call):
            continue
        site = (positions[id(node.value)][0], positions[id(node.value)][1])
        await_target = functions.get(contextual.get(site, ""), {})
        if await_target.get("scope_kind") == "source_callable_frame" and not isinstance(ast.parse(await_target["python_value_source"]).body[0], ast.AsyncFunctionDef):
            unqualified_awaits.add((positions[id(node)][0], positions[id(node)][1]))
    return {"calls": calls, "contextual_calls": contextual,
            "inactive_calls": inactive_calls, "inactive_lines": inactive_lines,
            "unqualified_source_awaits": unqualified_awaits,
            "unresolved_source_callables": unresolved_bindings}

"""Exact, fail-closed identities for Python same-instance method calls.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import ast
from typing import Any


def root_name(node: ast.AST) -> str | None:
    """Return the lexical root of a simple attribute/call expression."""
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        if isinstance(node, ast.Attribute):
            node = node.value
        elif isinstance(node, ast.Subscript):
            node = node.value
        elif isinstance(node.func, ast.Attribute):
            node = node.func.value
        else:
            break
    return node.id if isinstance(node, ast.Name) else None


def call_name(node: ast.Call) -> str:
    """Return the direct lexical call name, or a closed dynamic marker."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return "<dynamic>"


def call_reference(
    function: ast.expr, bindings: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    """Describe a call rooted at one neutral import binding."""
    parts: list[str] = []
    current = function
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name) or current.id not in bindings:
        return None
    return {
        "local": current.id,
        "attributes": list(reversed(parts)),
        "binding": bindings[current.id],
    }


def source_symbol(function: ast.expr, path: str, imports: dict[str, str]) -> str:
    """Render the source-first identity known before root qualification."""
    if isinstance(function, ast.Name):
        return imports.get(function.id, f"{path}::{function.id}")
    if isinstance(function, ast.Attribute):
        root = root_name(function)
        imported = imports.get(root or "")
        if imported:
            return f"{imported}.{function.attr}"
        return f"{path}::{ast.unparse(function)}"
    return f"{path}::<dynamic>"


def method_binding(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, str | None]:
    """Classify the lexical binding without executing decorators."""
    decorators = {
        ast.unparse(decorator).rsplit(".", 1)[-1]
        for decorator in function.decorator_list
    }
    arguments = [*function.args.posonlyargs, *function.args.args]
    if "staticmethod" in decorators:
        return "static", None
    if "classmethod" in decorators:
        return "class", arguments[0].arg if arguments else None
    return "instance", arguments[0].arg if arguments else None


def discover_class_facts(
    tree: ast.Module,
    *,
    path: str,
    imports: dict[str, str],
    import_bindings: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collect neutral class/method facts during the existing AST pass."""
    rows: list[dict[str, Any]] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        bases: list[dict[str, Any]] = []
        for base in node.bases:
            fact: dict[str, Any] = {
                "called_symbol": source_symbol(base, path, imports),
                "line": base.lineno,
            }
            reference = call_reference(base, import_bindings)
            if reference is not None:
                fact["import_reference"] = reference
            bases.append(fact)
        methods = []
        class_rebindings: set[str] = set()
        for member in node.body:
            if isinstance(member, (ast.Assign, ast.AnnAssign)):
                targets = member.targets if isinstance(member, ast.Assign) else [member.target]
                class_rebindings.update(
                    target.id for target in targets if isinstance(target, ast.Name)
                )
            if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            kind, receiver = method_binding(member)
            methods.append(
                {
                    "name": member.name,
                    "symbol": f"{path}::{node.name}.{member.name}",
                    "binding": kind,
                    "receiver": receiver,
                    "decorators": sorted(ast.unparse(value) for value in member.decorator_list),
                }
            )
        rows.append(
            {
                "symbol": f"{path}::{node.name}",
                "bases": bases,
                "methods": methods,
                "class_decorators": sorted(
                    ast.unparse(value) for value in node.decorator_list
                ),
                "class_rebindings": sorted(class_rebindings),
                "metaclass_keywords": sorted(
                    keyword.arg or "**" for keyword in node.keywords
                ),
            }
        )
    return rows


def bound_method_origins(
    expression: ast.AST,
    *,
    class_symbol: str | None,
    receiver: str | None,
    assignments: dict[str, set[str]],
) -> set[str] | None:
    """Retain an alias to a receiver method as unsupported dispatch evidence."""
    if (
        class_symbol is None
        or receiver is None
        or not isinstance(expression, ast.Attribute)
        or not isinstance(expression.value, ast.Name)
        or expression.value.id != receiver
    ):
        return None
    origins = assignments.get(receiver, {f"local:{receiver}"})
    prefix = "bound_method" if origins == {f"parameter:{receiver}"} else "ambiguous_bound_method"
    return {f"{prefix}:{class_symbol}.{expression.attr}"}


def method_dispatch_reference(
    function: ast.expr,
    *,
    class_symbol: str | None,
    method_binding_kind: str,
    receiver: str | None,
    assignments: dict[str, set[str]],
) -> dict[str, Any] | None:
    """Classify direct receiver dispatch; unsupported forms remain explicit."""
    if class_symbol is None:
        return None
    if (
        receiver is not None
        and isinstance(function, ast.Attribute)
        and isinstance(function.value, ast.Attribute)
        and root_name(function.value) == receiver
        and function.value.attr in {"__class__", "__dict__"}
    ):
        return {
            "kind": "dynamic_receiver_expression",
            "class_symbol": class_symbol,
            "method": ast.unparse(function),
        }
    if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Call):
        inner = function.value
        if isinstance(inner.func, ast.Name) and inner.func.id == "super":
            return {"kind": "super", "class_symbol": class_symbol, "method": function.attr}
        if (
            receiver is not None
            and isinstance(inner.func, ast.Name)
            and inner.func.id == "type"
            and inner.args
            and isinstance(inner.args[0], ast.Name)
            and inner.args[0].id == receiver
        ):
            return {
                "kind": "dynamic_receiver_expression",
                "class_symbol": class_symbol,
                "method": ast.unparse(function),
            }
    if isinstance(function, ast.Attribute):
        root = root_name(function.value)
        if root is None or receiver is None:
            return None
        origins = assignments.get(root, {f"local:{root}"})
        receiver_origin = f"parameter:{receiver}"
        if root == receiver:
            if method_binding_kind != "instance":
                return {
                    "kind": "class_or_static_receiver",
                    "class_symbol": class_symbol,
                    "method": function.attr,
                }
            if origins != {receiver_origin}:
                return {
                    "kind": "receiver_rebound",
                    "class_symbol": class_symbol,
                    "method": function.attr,
                }
            if not isinstance(function.value, ast.Name):
                return {
                    "kind": "chained_receiver",
                    "class_symbol": class_symbol,
                    "method": function.attr,
                }
            return {
                "kind": "same_instance",
                "class_symbol": class_symbol,
                "method": function.attr,
                "receiver": receiver,
            }
        if receiver_origin in origins:
            return {
                "kind": "receiver_alias",
                "class_symbol": class_symbol,
                "method": function.attr,
            }
    if isinstance(function, ast.Name):
        origins = assignments.get(function.id, {f"local:{function.id}"})
        if any(
            value.startswith(("bound_method:", "ambiguous_bound_method:"))
            for value in origins
        ):
            return {
                "kind": "method_alias",
                "class_symbol": class_symbol,
                "method": function.id,
            }
    if (
        receiver is not None
        and isinstance(function, ast.Call)
        and isinstance(function.func, ast.Name)
        and function.func.id == "getattr"
        and function.args
        and isinstance(function.args[0], ast.Name)
        and function.args[0].id == receiver
    ):
        return {
            "kind": "dynamic_receiver_expression",
            "class_symbol": class_symbol,
            "method": ast.unparse(function),
        }
    return None


def _hierarchy_sensitive_classes(classes: dict[str, dict[str, Any]]) -> set[str]:
    sensitive: set[str] = set()
    adjacency: dict[str, set[str]] = {symbol: set() for symbol in classes}
    for child, row in classes.items():
        bases = row.get("bases", [])
        method_names = {str(value.get("name", "")) for value in row.get("methods", [])}
        if (
            bases
            or row.get("class_decorators")
            or row.get("metaclass_keywords")
            or method_names & {"__getattr__", "__getattribute__"}
        ):
            sensitive.add(child)
        for base in bases:
            parent = str(base.get("called_symbol", ""))
            if parent not in classes:
                continue
            sensitive.add(parent)
            adjacency[child].add(parent)
            adjacency[parent].add(child)
    pending = list(sensitive)
    while pending:
        symbol = pending.pop()
        for related in adjacency[symbol] - sensitive:
            sensitive.add(related)
            pending.append(related)
    return sensitive


def resolve_method_dispatch(inventory: dict[str, Any]) -> None:
    """Resolve safe same-instance calls and mark every ambiguous form fail-closed."""
    classes = {str(row["symbol"]): row for row in inventory.get("classes", [])}
    functions = {str(row["symbol"]): row for row in inventory.get("functions", [])}
    sensitive = _hierarchy_sensitive_classes(classes)
    method_facts = {
        str(method["symbol"]): method
        for row in classes.values()
        for method in row.get("methods", [])
    }
    instance_rebindings: dict[str, set[str]] = {symbol: set() for symbol in classes}
    for function in functions.values():
        class_symbol = str(function.get("class_symbol") or "")
        if class_symbol in instance_rebindings:
            instance_rebindings[class_symbol].update(
                str(value) for value in function.get("receiver_attribute_mutations", [])
            )
    for function in inventory.get("functions", []):
        custom_function_decorators = {
            str(value).rsplit(".", 1)[-1]
            for value in function.get("decorators", [])
        } - {"classmethod", "staticmethod"}
        failures: list[dict[str, Any]] = []
        if custom_function_decorators:
            failures.append(
                {
                    "kind": "ambiguous_method_definition",
                    "dispatch_kind": "decorated_method",
                    "symbol": function["symbol"],
                    "decorators": sorted(custom_function_decorators),
                }
            )
        for call in function.get("calls", []):
            reference = call.get("method_dispatch")
            if not isinstance(reference, dict):
                continue
            kind = str(reference.get("kind", "unknown"))
            class_symbol = str(reference.get("class_symbol", ""))
            method = str(reference.get("method", ""))
            target = f"{class_symbol}.{method}"
            target_fact = method_facts.get(target, {})
            decorators = {
                value.rsplit(".", 1)[-1]
                for value in target_fact.get("decorators", [])
            }
            custom_decorators = decorators - {"classmethod", "staticmethod"}
            rebound = (
                method in set(classes.get(class_symbol, {}).get("class_rebindings", []))
                or method in instance_rebindings.get(class_symbol, set())
                or "*" in instance_rebindings.get(class_symbol, set())
            )
            if (
                kind == "same_instance"
                and class_symbol not in sensitive
                and target in functions
                and not custom_decorators
                and not rebound
            ):
                call["called_symbol"] = target
                call["dispatch_resolution"] = "exact_same_instance"
                continue
            if custom_decorators:
                kind = "decorated_method"
            elif rebound:
                kind = "receiver_attribute_rebound"
            port_eligible = kind in {"same_instance", "chained_receiver"}
            call["dispatch_resolution"] = "unresolved"
            call["dispatch_port_eligible"] = port_eligible
            failures.append(
                {
                    "kind": "ambiguous_method_dispatch",
                    "dispatch_kind": kind,
                    "symbol": function["symbol"],
                    "called_symbol": call.get("called_symbol"),
                    "line": call.get("line"),
                    "port_eligible": port_eligible,
                }
            )
        function["effect_unresolved"] = failures

"""Exact, fail-closed identities for Python same-instance method calls.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import ast
from typing import Any

_OVERLOAD_DECORATORS = {
    "typing::module.overload",
    "typing::overload",
    "typing_extensions::module.overload",
    "typing_extensions::overload",
}


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


def runtime_function_scopes(
    tree: ast.Module,
    *,
    path: str,
    imports: dict[str, str],
) -> tuple[
    list[tuple[str | None, list[ast.FunctionDef | ast.AsyncFunctionDef]]],
    list[str],
]:
    """Return runtime definitions while rejecting type-only overload identities."""

    scopes = [
        (
            None,
            [
                node
                for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ],
        ),
        *[
            (
                node.name,
                [
                    member
                    for member in node.body
                    if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                ],
            )
            for node in tree.body
            if isinstance(node, ast.ClassDef)
        ],
    ]
    result = []
    missing: list[str] = []
    for class_name, members in scopes:
        def is_overload(member: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
            return any(
                source_symbol(decorator, path, imports) in _OVERLOAD_DECORATORS
                for decorator in member.decorator_list
            )

        overloads = {
            member.name
            for member in members
            if is_overload(member)
        }
        runtime = [member for member in members if not is_overload(member)]
        implementations = {member.name for member in runtime}
        scope = f"{class_name}." if class_name else ""
        missing.extend(
            f"{path}::{scope}{name}" for name in sorted(overloads - implementations)
        )
        result.append((class_name, runtime))
    return result, missing


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


def _closed_class_binding(node: ast.ClassDef, tree: ast.Module, path: str,
                          imports: dict[str, str], *, allow_bases: bool = False) -> bool:
    """Prove the local class binding; subclass closure is checked after imports."""
    if (node.bases and not allow_bases) or node.keywords:
        return False
    for member in node.body:
        if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if member.name in {"__new__", "__init__", "__post_init__", "__setattr__",
                               "__getattr__", "__getattribute__"}:
                return False
            if any(isinstance(decorator, ast.Name) and decorator.id == "property"
                   for decorator in member.decorator_list):
                return False
        if isinstance(member, (ast.Assign, ast.AnnAssign)):
            default_value = member.value
            if default_value is not None and not all(
                isinstance(value, (ast.Constant, ast.Tuple, ast.Load, ast.UnaryOp, ast.UAdd, ast.USub))
                for value in ast.walk(default_value)
            ):
                return False
            if isinstance(member, ast.AnnAssign) and any(
                isinstance(value, ast.Call) for value in ast.walk(member.annotation)
            ):
                return False
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if source_symbol(target, path, imports) not in {
            "dataclasses::dataclass", "dataclasses::module.dataclass",
        }:
            return False
        if isinstance(decorator, ast.Call) and (
            decorator.args or any(keyword.arg is None
                or not isinstance(keyword.value, ast.Constant)
                or not isinstance(keyword.value.value, bool)
                for keyword in decorator.keywords)
        ):
            return False
    for value in ast.walk(tree):
        if isinstance(value, ast.Name) and isinstance(value.ctx, (ast.Store, ast.Del)):
            if value.id in {node.name, "classmethod", *imports}:
                return False
        if isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if value is not node and value.name in {node.name, "classmethod"}:
                return False
        if (isinstance(value, ast.Attribute) and isinstance(value.ctx, (ast.Store, ast.Del))
                and root_name(value) == node.name):
            return False
        if (isinstance(value, ast.Call) and call_name(value) in {"setattr", "delattr"}
                and value.args and isinstance(value.args[0], ast.Name)
                and value.args[0].id == node.name):
            return False
    return "classmethod" not in imports


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
        standard_generic_base = (
            len(node.bases) == 1 and isinstance(node.bases[0], ast.Subscript)
            and source_symbol(node.bases[0].value, path, imports) in
            {"typing::Generic", "typing::module.Generic"}
        )
        plain_generic = (bool(getattr(node, "type_params", False)) or standard_generic_base) and not (
            (node.bases and not standard_generic_base) or node.keywords or "__class_getitem__" in class_rebindings
            or any(method["name"] == "__class_getitem__" for method in methods)
        )
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for value in ast.walk(statement):
                if (isinstance(value, ast.Attribute) and isinstance(value.ctx, (ast.Store, ast.Del))
                        and root_name(value) == node.name):
                    plain_generic = False
                if (isinstance(value, ast.Call) and call_name(value) in {"setattr", "delattr"}
                        and value.args and isinstance(value.args[0], ast.Name)
                        and value.args[0].id == node.name):
                    plain_generic = False
        proofs = [*node.decorator_list, *(node.bases if standard_generic_base else [])]
        for proof in proofs:
            is_base = isinstance(proof, ast.Subscript)
            target = proof.value if isinstance(proof, ast.Subscript) else proof.func if isinstance(proof, ast.Call) else proof
            if not is_base and source_symbol(target, path, imports) not in {
                "dataclasses::dataclass", "dataclasses::module.dataclass",
            }:
                plain_generic = False
            roots = {value.id for value in ast.walk(target) if isinstance(value, ast.Name)}
            for statement in tree.body:
                if statement is node:
                    break
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if statement.name in roots:
                        plain_generic = False
                    continue
                if any(isinstance(value, ast.Name) and isinstance(value.ctx, ast.Store)
                       and value.id in roots for value in ast.walk(statement)):
                    plain_generic = False
            if isinstance(proof, ast.Call) and (
                proof.args or any(
                    keyword.arg is None or not isinstance(keyword.value, ast.Constant)
                    or not isinstance(keyword.value.value, bool)
                    for keyword in proof.keywords
                )
            ):
                plain_generic = False
        rows.append(
            {
                "symbol": f"{path}::{node.name}",
                **({"plain_generic": True} if plain_generic else {}),
                "bases": bases,
                "closed_class_binding": _closed_class_binding(node, tree, path, imports),
                "local_class_binding": _closed_class_binding(node, tree, path, imports, allow_bases=True),
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
        and isinstance(function, ast.Subscript)
        and root_name(function) == receiver
    ):
        return {
            "kind": "dynamic_receiver_expression",
            "class_symbol": class_symbol,
            "method": ast.unparse(function),
        }
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


def _class_constructor_bindings(
    function: dict[str, Any], classes: dict[str, dict[str, Any]],
    functions: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Bind inherited class methods only at exact source-visible class calls."""
    method = str(function["symbol"]).rsplit(".", 1)[-1]
    owner = str(function.get("class_symbol", ""))
    result: list[dict[str, Any]] = []
    for caller in functions.values():
        for occurrence, call in enumerate(caller.get("calls", [])):
            bound, separator, called_method = str(call.get("called_symbol", "")).rpartition(".")
            if not separator or called_method != method or bound not in classes:
                continue
            current = bound
            visited: set[str] = set()
            while current in classes and current not in visited:
                visited.add(current)
                row = classes[current]
                if not row.get("local_class_binding"):
                    break
                definitions = [entry for entry in row.get("methods", []) if entry["name"] == method]
                if definitions:
                    if current == owner and len(definitions) == 1:
                        result.append({"constructed_symbol": bound,
                                       "binding_caller": caller["symbol"],
                                       "binding_line": call.get("line"),
                                       "binding_occurrence": occurrence,
                                       "factory_implementation": function["symbol"]})
                    break
                bases = row.get("bases", [])
                if len(bases) != 1:
                    break
                current = str(bases[0].get("called_symbol", ""))
    return result


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
            if kind == "class_constructor":
                class_fact = classes.get(class_symbol, {})
                bindings = _class_constructor_bindings(function, classes, functions)
                if (not reference.get("receiver_rebound") and not custom_function_decorators
                        and class_fact.get("closed_class_binding")
                        and bindings):
                    call["class_constructor_bindings"] = bindings
                    call["dispatch_resolution"] = "exact_bound_class_constructor"
                    for binding in bindings:
                        fact = {**call, **binding}
                        if fact not in function.setdefault("constructors", []):
                            function["constructors"].append(fact)
                    continue
                failure = {"kind": "unresolved_class_constructor",
                           "symbol": function["symbol"], "line": call.get("line"),
                           "called_symbol": call.get("called_symbol")}
                if failure not in function.setdefault("unresolved", []):
                    function["unresolved"].append(failure)
                call["dispatch_resolution"] = "unresolved"
                call["dispatch_port_eligible"] = False
                failures.append({**failure, "port_eligible": False})
                continue
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


def receiver_attribute_targets(target: ast.AST, receiver: str | None) -> set[str]:
    """Retain every receiver attribute written by an assignment target."""
    if isinstance(target, (ast.Tuple, ast.List)):
        return {
            name
            for element in target.elts
            for name in receiver_attribute_targets(element, receiver)
        }
    if isinstance(target, ast.Starred):
        return receiver_attribute_targets(target.value, receiver)
    if (
        receiver is not None
        and isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id == receiver
    ):
        return {target.attr}
    return set()

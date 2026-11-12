"""Exact, fail-closed identities for Python same-instance method calls.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import ast
from typing import Any


# These source bodies are traced directly; this grants no runtime authority.
SOURCE_CONSTRUCTION_BODY_HOOKS = frozenset({
    "__new__", "__init__", "__post_init__", "__setattr__",
})


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
    missing = []
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


def _source_class_scopes(tree: ast.Module) -> list[tuple[ast.ClassDef, str, str | None]]:
    """Enumerate source class identities, including deferred lexical definitions."""
    rows: list[tuple[ast.ClassDef, str, str | None]] = []

    def visit(node: ast.AST, prefix: str, parent: str | None) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualified = prefix + node.name
            for child in node.body:
                visit(child, qualified + ".<locals>.", qualified)
        elif isinstance(node, ast.ClassDef):
            qualified = prefix + node.name
            rows.append((node, qualified, parent))
            for child in node.body:
                visit(child, qualified + ".", parent)
        elif not isinstance(node, ast.Lambda):
            for child in ast.iter_child_nodes(node):
                visit(child, prefix, parent)

    visit(tree, "", None)
    return rows


def _native_literal_value(node: ast.AST, names: set[str]) -> bool:
    """Recognize only closed builtin values; names here were bound locally."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        return node.id in names
    if isinstance(node, ast.UnaryOp):
        return _native_literal_value(node.operand, names)
    if isinstance(node, ast.Compare):
        return all(_native_literal_value(value, names) for value in [node.left, *node.comparators])
    if isinstance(node, ast.BoolOp):
        return all(_native_literal_value(value, names) for value in node.values)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_native_literal_value(value, names) for value in node.elts)
    if isinstance(node, ast.Dict):
        return all((key is None or _native_literal_value(key, names))
                   and _native_literal_value(value, names)
                   for key, value in zip(node.keys, node.values))
    if isinstance(node, ast.Starred):
        return _native_literal_value(node.value, names)
    if isinstance(node, ast.Subscript):
        return _native_literal_value(node.value, names) and _native_literal_value(node.slice, names)
    if isinstance(node, ast.Slice):
        return all(value is None or _native_literal_value(value, names)
                   for value in (node.lower, node.upper, node.step))
    return False


# Version 1.1 adds explicit suspension/exception observations; legacy kinds stay 1.0.
IMPLICIT_PROTOCOL_KIND_VERSIONS = {"await": "1.1", "exception": "1.1"}


def implicit_runtime_protocols(
    node: ast.AST, native: set[str], call_targets: set[int],
) -> tuple[str, ...]:
    """Retain unknown runtime dispatch in the existing source call population."""
    known = lambda value: _native_literal_value(value, native)
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
        return () if id(node) in call_targets else ("attribute_read",)
    if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
        return () if known(node) else ("subscript_read",)
    if isinstance(node, ast.Dict):
        unknown = any(not known(value if key is None else key)
                      for key, value in zip(node.keys, node.values))
        return ("collection",) if unknown else ()
    if isinstance(node, ast.Set):
        return ("collection",) if any(not known(value) for value in node.elts) else ()
    if isinstance(node, (ast.DictComp, ast.SetComp)):
        bound = set(native)
        for generator in node.generators:
            if generator.is_async or not known(generator.iter):
                return ("collection",)
            bound.update(value.id for value in ast.walk(generator.target) if isinstance(value, ast.Name))
        key = node.key if isinstance(node, ast.DictComp) else node.elt
        return () if _native_literal_value(key, bound) else ("collection",)
    if isinstance(node, ast.comprehension):
        return ("iteration",) if node.is_async or not known(node.iter) else ()
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return ("iteration",) if isinstance(node, ast.AsyncFor) or not known(node.iter) else ()
    if isinstance(node, ast.Starred) and isinstance(node.ctx, ast.Load):
        return () if known(node.value) else ("iteration",)
    if isinstance(node, ast.Assign) and any(isinstance(target, (ast.Tuple, ast.List)) for target in node.targets):
        return () if known(node.value) else ("iteration",)
    if isinstance(node, ast.YieldFrom):
        return () if known(node.value) else ("iteration",)
    if isinstance(node, ast.Await):
        return ("await",)
    if isinstance(node, ast.Raise) and node.exc is not None:
        return () if known(node.exc) else ("exception",)
    if isinstance(node, ast.UnaryOp):
        return () if known(node.operand) else (("truth",) if isinstance(node.op, ast.Not) else ("operator",))
    if isinstance(node, ast.Compare):
        if all(isinstance(operator, (ast.Is, ast.IsNot)) for operator in node.ops):
            return ()
        return () if all(known(value) for value in [node.left, *node.comparators]) else ("operator",)
    if isinstance(node, ast.BoolOp):
        return () if all(known(value) for value in node.values[:-1]) else ("truth",)
    if isinstance(node, ast.BinOp):
        return () if known(node.left) and known(node.right) else ("operator",)
    if isinstance(node, (ast.If, ast.IfExp, ast.While, ast.Assert)):
        return () if known(node.test) else ("truth",)
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return ("context_manager",)
    if isinstance(node, ast.FormattedValue):
        return () if known(node.value) and (node.format_spec is None or known(node.format_spec)) else ("format",)
    return ()


def runtime_function_contexts(
    tree: ast.Module, *, path: str, imports: dict[str, str],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Extend existing runtime scopes with neutral lexical identity and bindings."""
    outer, missing = runtime_function_scopes(tree, path=path, imports=imports)
    old_classes = {name for name, _ in outer if name is not None}
    for declaration, qualified, parent in _source_class_scopes(tree):
        if parent is not None or qualified in old_classes:
            continue
        methods = [node for node in declaration.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        runtime = [node for node in methods if not any(source_symbol(value, path, imports) in _OVERLOAD_DECORATORS for value in node.decorator_list)]
        missing.extend(path + "::" + qualified + "." + name for name in sorted(
            {node.name for node in methods} - {node.name for node in runtime}))
        outer.append((qualified, runtime))
    contexts: list[dict[str, Any]] = []

    def children(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, bool]]:
        found = []
        pending: list[tuple[ast.AST, bool]] = [(node, True) for node in function.body]
        while pending:
            node, direct = pending.pop(0)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found.append((node, direct))
            elif not isinstance(node, (ast.ClassDef, ast.Lambda)):
                pending.extend((child, False) for child in ast.iter_child_nodes(node))
        return found

    def local_classes(function: ast.FunctionDef | ast.AsyncFunctionDef, qualified: str) -> list[tuple[ast.ClassDef, str]]:
        found: list[tuple[ast.ClassDef, str]] = []
        pending: list[tuple[ast.AST, str]] = [(node, qualified + '.<locals>.') for node in function.body]
        while pending:
            node, prefix = pending.pop(0)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(node, ast.ClassDef):
                target = prefix + node.name
                found.append((node, target))
                pending.extend((child, target + '.') for child in node.body)
            else:
                pending.extend((child, prefix) for child in ast.iter_child_nodes(node))
        return found

    def add(function: ast.FunctionDef | ast.AsyncFunctionDef, class_name: str | None,
            qualified: str, parent: str | None, inherited: dict[str, Any],
            captured_parameters: dict[str, str | None]) -> None:
        declared = children(function)
        names = {node.name for node, _ in declared} | set(inherited)
        pending = list(function.body)
        shadows: set[str] = set()
        assigned: set[str] = set()
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(node, ast.ClassDef):
                if node.name in names:
                    shadows.add(node.name)
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                assigned.add(node.id)
                if node.id in names:
                    shadows.add(node.id)
            if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
                assigned.add(node.name)
                if node.name in names:
                    shadows.add(node.name)
            if isinstance(node, ast.MatchMapping) and node.rest:
                assigned.add(node.rest)
                if node.rest in names:
                    shadows.add(node.rest)
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                shadows.update((alias.asname or alias.name.split('.')[0]) for alias in node.names if (alias.asname or alias.name.split('.')[0]) in names)
            pending.extend(ast.iter_child_nodes(node))
        bindings = {name: {**value, 'ambiguous': value['ambiguous'] or name in shadows}
                    for name, value in inherited.items()}
        runtime = []
        overloads: set[str] = set()
        for node, direct in declared:
            target = qualified + '.<locals>.' + node.name
            if any(source_symbol(value, path, imports) in _OVERLOAD_DECORATORS for value in node.decorator_list):
                overloads.add(node.name)
                continue
            runtime.append((node, target))
            ambiguous = (not direct or node.name in shadows
                         or sum(other.name == node.name for other, _ in declared if not any(source_symbol(value, path, imports) in _OVERLOAD_DECORATORS for value in other.decorator_list)) != 1)
            bindings[node.name] = {'symbol': path + '::' + target,
                                   'ambiguous': ambiguous, 'line': node.lineno}
        missing.extend(path + '::' + qualified + '.<locals>.' + name
                       for name in sorted(overloads - {node.name for node, _ in runtime}))
        contexts.append({'class_name': class_name, 'qualified_name': qualified,
                         'lexical_parent': parent, 'function': function,
                         'bindings': bindings, 'closure_parameters': captured_parameters, 'assigned_names': sorted(assigned)})
        parameters = dict(captured_parameters)
        parameters.update({arg.arg: None for arg in [*function.args.posonlyargs, *function.args.args,
                                                    *function.args.kwonlyargs,
                                                    *([function.args.vararg] if function.args.vararg else []),
                                                    *([function.args.kwarg] if function.args.kwarg else [])]})
        for node, target in runtime:
            add(node, None, target, path + '::' + qualified, bindings, parameters)
        for local_class, target in local_classes(function, qualified):
            methods = [node for node in local_class.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
            runtime_methods = [node for node in methods if not any(source_symbol(value, path, imports) in _OVERLOAD_DECORATORS for value in node.decorator_list)]
            for method in runtime_methods:
                add(method, target, target + '.' + method.name, path + '::' + qualified, bindings, parameters)

    for class_name, members in outer:
        for function in members:
            qualified = (class_name + '.' if class_name else '') + function.name
            add(function, class_name, qualified, None, {}, {})
    return contexts, missing


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
    for node, qualified, _ in _source_class_scopes(tree):
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
        descriptor_bindings: set[str] = set()
        for member in node.body:
            if isinstance(member, (ast.Assign, ast.AnnAssign)):
                targets = member.targets if isinstance(member, ast.Assign) else [member.target]
                class_rebindings.update(
                    target.id for target in targets if isinstance(target, ast.Name)
                )
                if member.value is not None and not isinstance(member.value, ast.Constant):
                    descriptor_bindings.update(
                        target.id for target in targets if isinstance(target, ast.Name)
                    )
            if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            kind, receiver = method_binding(member)
            methods.append(
                {
                    "name": member.name,
                    "symbol": f"{path}::{qualified}.{member.name}",
                    "binding": kind,
                    "receiver": receiver,
                    "decorators": sorted(ast.unparse(value) for value in member.decorator_list),
                }
            )
        rows.append(
            {
                "symbol": f"{path}::{qualified}",
                "bases": bases,
                "methods": methods,
                "class_decorators": sorted(
                    ast.unparse(value) for value in node.decorator_list
                ),
                "class_rebindings": sorted(class_rebindings),
                "descriptor_bindings": sorted(descriptor_bindings),
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
        }
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
            custom_decorators = decorators
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


def extend_constructor_effect_obligations(inventory: dict[str, Any]) -> None:
    """Add source-visible construction obligations without resolving runtime types.

    Candidate targets can only expand the existing effect traversal. Decorated,
    external, cyclic or rebound constructors retain explicit missing provenance.
    These observations never change dispatch decisions or grant decoder authority.
    """
    class_rows = inventory.get("classes", [])
    function_rows = inventory.get("functions", [])
    classes = {str(row["symbol"]): row for row in class_rows}
    functions = {str(row["symbol"]): row for row in function_rows}
    ambiguous = len(classes) != len(class_rows) or len(functions) != len(function_rows)
    def site(row: dict[str, Any]) -> tuple[Any, ...]:
        return tuple(row.get(key) for key in ("line", "column", "end_line", "end_column"))

    # Resolved class identity is independent of local/imported identifier spelling.
    for function in function_rows:
        constructors = function.setdefault("constructors", [])
        for call in function.get("calls", []):
            target = call.get("called_symbol")
            if target in classes and not any(site(fact) == site(call) for fact in constructors):
                constructors.append({**call, "constructed_symbol": target})
    lifecycle = SOURCE_CONSTRUCTION_BODY_HOOKS | {"__del__"}
    interception = {"__getattribute__", "__getattr__", "__delattr__", "__get__", "__set__", "__delete__"}

    def closure(symbol: str, seen: frozenset[str]) -> tuple[set[str], set[str], set[str]]:
        if symbol in seen:
            return set(), {symbol + ":cyclic_hierarchy"}, {symbol}
        row = classes.get(symbol)
        if row is None:
            return set(), {symbol + ":external_class_provenance_required"}, {symbol}
        targets: set[str] = set()
        missing: set[str] = set()
        population = {symbol}
        if row.get("class_decorators"):
            missing.add(symbol + ":decorated_class_runtime_provenance_required")
        if row.get("metaclass_keywords"):
            missing.add(symbol + ":metaclass_runtime_provenance_required")
        if row.get("descriptor_bindings"):
            missing.add(symbol + ":class_attribute_descriptor_provenance_required")
        rebound = set(row.get("class_rebindings", []))
        if rebound & (lifecycle | interception):
            missing.add(symbol + ":lifecycle_binding_rebound")
        for method in row.get("methods", []):
            name = str(method.get("name", ""))
            decorators = set(method.get("decorators", []))
            special_method = name.startswith("__") and name.endswith("__")
            if name not in lifecycle | interception and not decorators and not special_method:
                continue
            target = str(method.get("symbol", ""))
            if target in functions:
                targets.add(target)
            else:
                missing.add(target + ":source_body_missing")
            if special_method and name not in lifecycle | interception:
                missing.add(target + ":implicit_protocol_runtime_provenance_required")
            if name == "__del__":
                missing.add(target + ":finalization_runtime_provenance_required")
            if name in interception:
                missing.add(target + ":descriptor_runtime_provenance_required")
            if decorators:
                missing.add(target + ":decorator_runtime_provenance_required")
        for base in row.get("bases", []):
            target = base.get("called_symbol")
            if not isinstance(target, str) or not target:
                missing.add(symbol + ":base_identity_missing")
                continue
            inherited, errors, identities = closure(target, seen | {symbol})
            targets.update(inherited)
            missing.update(errors)
            population.update(identities)
        return targets, missing, population

    for function in function_rows:
        call_sites: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
        for call in function.get("calls", []):
            call_sites.setdefault((call.get("line"), call.get("column"), call.get("end_line"), call.get("end_column")), []).append(call)
        for constructor in function.get("constructors", []):
            target = str(constructor.get("constructed_symbol", ""))
            candidates, missing, population = closure(target, frozenset())
            if ambiguous:
                missing.add("ambiguous_source_symbol_population")
            observation = {
                "authority": False,
                "source_class_resolved": target in classes,
                "class_candidates": sorted(population),
                "function_candidates": sorted(candidates),
                "unresolved": sorted(missing),
                "qualification": "SOURCE_OBLIGATIONS_ONLY_RUNTIME_PROVENANCE_REQUIRED",
            }
            constructor["construction_effect_observation"] = observation
            sites = call_sites.get((constructor.get("line"), constructor.get("column"), constructor.get("end_line"), constructor.get("end_column")), [])
            if len(sites) == 1 and sites[0].get("called_symbol") == constructor.get("called_symbol"):
                sites[0]["construction_effect_observation"] = observation
            elif sites:
                for call in sites:
                    call["construction_effect_observation"] = {
                        **observation,
                        "unresolved": sorted(missing | {"contradictory_constructor_site"}),
                    }

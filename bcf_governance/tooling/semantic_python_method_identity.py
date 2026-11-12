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
        descriptor_bindings: set[str] = set()
        for member in node.body:
            if isinstance(member, (ast.Assign, ast.AnnAssign)):
                targets = member.targets if isinstance(member, ast.Assign) else [member.target]
                class_rebindings.update(
                    target.id for target in targets if isinstance(target, ast.Name)
                )
                value = member.value
                if value is not None and not isinstance(value, ast.Constant):
                    descriptor_bindings.update(
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


def resolve_typed_receiver_candidates(inventory: dict[str, Any]) -> None:
    """Derive neutral type candidates; preserve every existing dispatch decision.

    An annotation, lexical import or protocol return is not runtime provenance.
    These rows cannot be consumed as read-port/effect authority.
    """
    function_rows, class_rows = inventory.get("functions", []), inventory.get("classes", [])
    functions = {str(row["symbol"]): row for row in function_rows}
    classes = {str(row["symbol"]): row for row in class_rows}
    if len(functions) != len(function_rows) or len(classes) != len(class_rows):
        inventory["typed_receiver_observation_errors"] = ["ambiguous source symbols"]
        return
    fields: dict[tuple[str, str], set[str]] = {}

    def method_targets(model: str, name: str, seen: frozenset[str] = frozenset()) -> set[str]:
        if model in seen or model.startswith("<"):
            return set()
        target = model + "." + name
        row = classes.get(model)
        if row is None:
            return {target}
        targets = {target} if target in functions else set()
        for base in row.get("bases", []):
            identity = base.get("called_symbol")
            if isinstance(identity, str):
                targets.update(method_targets(identity, name, seen | {model}))
        return targets

    def initial_types(function: dict[str, Any]) -> dict[str, set[str]]:
        result = {
            str(name): set(identities) or {"<unknown>"}
            for name, identities in function.get("parameter_annotation_symbols", {}).items()
        }
        owner, receiver = function.get("class_symbol"), function.get("receiver_parameter")
        if isinstance(owner, str) and isinstance(receiver, str) and function.get("method_binding") == "instance":
            result[receiver] = {"<instance:" + owner + ">"}
        return result

    def value_types(
        expression: dict[str, Any], environment: dict[str, set[str]],
        owner: str | None, calls: dict[tuple[int, int, int | None, int | None], list[dict[str, Any]]],
    ) -> set[str]:
        kind = expression.get("kind")
        if kind == "name":
            return environment.get(str(expression.get("name")), {"<unknown>"})
        if kind == "none":
            return {"<none>"}
        if kind == "await":
            return value_types(expression["value"], environment, owner, calls)
        if kind == "attribute":
            receiver = expression.get("receiver", {})
            if owner is not None and value_types(receiver, environment, owner, calls) == {"<instance:" + owner + ">"}:
                field = fields.get((owner, str(expression.get("name"))))
                if field is not None:
                    return field
            return {"<unknown>"}
        if kind == "call":
            rows = calls.get((expression.get("line"), expression.get("column"), expression.get("end_line"), expression.get("end_column")), [])
            if len(rows) != 1:
                return {"<unknown>"}
            call = rows[0]
            target = str(call.get("called_symbol", ""))
            if target in classes:
                return {target}
            candidates = {target} if target in functions else set()
            receiver = call.get("receiver_flow")
            if isinstance(receiver, dict):
                models = value_types(receiver, environment, owner, calls)
                for model in models:
                    candidates.update(method_targets(model, str(call.get("call_name", ""))))
            result: set[str] = set()
            for candidate in candidates:
                function = functions.get(candidate)
                if function is None:
                    result.add("<unknown>")
                else:
                    result.update(function.get("return_annotation_symbols", []) or ["<unknown>"])
            return result or {"<unknown>"}
        return {"<unknown>"}

    def call_index(function: dict[str, Any]) -> dict[tuple[int, int, int | None, int | None], list[dict[str, Any]]]:
        result: dict[tuple[int, int, int | None, int | None], list[dict[str, Any]]] = {}
        for call in function.get("calls", []):
            line, column = call.get("line"), call.get("column")
            if isinstance(line, int) and isinstance(column, int):
                result.setdefault((line, column, call.get("end_line"), call.get("end_column")), []).append(call)
        return result

    def bind_target(
        target: dict[str, Any], value: dict[str, Any], environment: dict[str, set[str]],
        owner: str | None, calls: dict[tuple[int, int, int | None, int | None], list[dict[str, Any]]],
        receiver: str | None,
    ) -> None:
        kind = target.get("kind")
        if kind == "sequence" and value.get("kind") == "sequence":
            targets, values = target.get("items", []), value.get("items", [])
            if len(targets) == len(values):
                for member, item in zip(targets, values, strict=True):
                    bind_target(member, item, environment, owner, calls, receiver)
                return
        types = value_types(value, environment, owner, calls)
        if kind == "name":
            name = str(target.get("name"))
            environment[name] = environment.get(name, set()) | types
        elif kind == "attribute" and owner is not None:
            root = target.get("receiver", {})
            if root.get("kind") == "name" and root.get("name") == receiver:
                key = owner, str(target.get("name"))
                fields[key] = fields.get(key, set()) | types

    # Constructor annotations are neutral candidates, never a concrete wiring proof.
    for symbol, function in functions.items():
        owner = function.get("class_symbol")
        if not symbol.endswith(".__init__") or not isinstance(owner, str) or function.get("method_binding") != "instance":
            continue
        environment = initial_types(function)
        parameters = list(function.get("parameters", {}))
        receiver = parameters[0] if parameters else None
        calls = call_index(function)
        for assignment in function.get("assignment_facts", []):
            value = assignment.get("value_flow", {"kind": "unknown"})
            for target in assignment.get("target_flows", []):
                bind_target(target, value, environment, owner, calls, receiver)

    for function in functions.values():
        environment = initial_types(function)
        owner = function.get("class_symbol")
        calls = call_index(function)
        assignments = sorted(function.get("assignment_facts", []), key=lambda row: (row["line"], row["column"]))
        for call in function.get("calls", []):
            receiver = call.get("receiver_flow")
            if not isinstance(receiver, dict):
                continue
            local = {name: set(identities) for name, identities in environment.items()}
            position = call.get("line", -1), call.get("column", -1)
            for assignment in assignments:
                if (assignment["line"], assignment["column"]) >= position:
                    break
                for target in assignment.get("target_flows", []):
                    # Method-local assignments never establish cross-method field authority.
                    if target.get("kind") in {"name", "sequence"}:
                        bind_target(target, assignment.get("value_flow", {"kind": "unknown"}), local, None, calls, None)
            models = value_types(receiver, local, owner, calls)
            targets: set[str] = set()
            for model in models:
                targets.update(method_targets(model, str(call.get("call_name", ""))))
            call["typed_receiver_observation"] = {
                "models": sorted(models), "method_candidates": sorted(targets),
                "authority": False,
                "qualification": "CONTROL_FLOW_RUNTIME_PROVENANCE_AND_OPERATION_WITNESS_REQUIRED",
            }


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
    lifecycle = {"__new__", "__init__", "__post_init__", "__setattr__"}
    interception = {"__getattribute__", "__getattr__", "__get__", "__set__", "__delete__"}

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
            if name not in lifecycle | interception and not decorators:
                continue
            target = str(method.get("symbol", ""))
            if target in functions:
                targets.add(target)
            else:
                missing.add(target + ":source_body_missing")
            if name in interception:
                missing.add(target + ":descriptor_runtime_provenance_required")
            if decorators - {"staticmethod", "classmethod"}:
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

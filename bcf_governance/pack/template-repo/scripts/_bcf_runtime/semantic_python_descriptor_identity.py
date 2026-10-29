"""Source-proven descriptor edges and bounded builtin exception constructors.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

import ast
from collections import Counter
from typing import Any
from .semantic_python_namespace_value_contracts import alias_discharged

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_EXCEPTIONS = {"Exception", "ValueError", "RuntimeError"}
_DYNAMIC_REBINDINGS = {
    "__getattribute__", "__getattr__", "__bases__", "__class__", "__build_class__",
    "__code__", "__dict__", "__builtins__", "__mro_entries__", "__get__",
    "classmethod", "staticmethod",
}


def _owned_nodes(node: ast.AST) -> list[ast.AST]:
    """Exclude deferred nested bodies from the containing execution owner."""
    result = [node]
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (*_FUNCTIONS, ast.ClassDef, ast.Lambda)):
            result.append(child)
        else:
            result.extend(_owned_nodes(child))
    return result


def _bindings(nodes: list[ast.AST]) -> Counter[str]:
    names: Counter[str] = Counter()
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names[node.id] += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names[node.name] += 1
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                names[alias.asname or alias.name.split(".", 1)[0]] += 1
        elif isinstance(node, ast.arg):
            names[node.arg] += 1
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names[node.name] += 1
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names.update(node.names)
        elif isinstance(node, ast.MatchAs) and node.name:
            names[node.name] += 1
        elif isinstance(node, ast.MatchStar) and node.name:
            names[node.name] += 1
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names[node.rest] += 1
    return names


def _unsafe_scope(nodes: list[ast.AST]) -> bool:
    return any(
        (isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names))
        or (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in {"exec", "eval", "globals", "locals", "vars", "setattr", "delattr"})
        or (isinstance(node, ast.Attribute) and node.attr == "__dict__")
        or (isinstance(node, ast.Name) and node.id == "__builtins__"
            and isinstance(node.ctx, (ast.Store, ast.Del)))
        for node in nodes
    )


def _method_facts(node: ast.FunctionDef | ast.AsyncFunctionDef, symbol: str) -> dict[str, Any]:
    # Defaults, decorators and annotations belong to definition-time analysis,
    # not this method's call-time body. Argument declarations still bind locals.
    arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    arguments.extend(value for value in (node.args.vararg, node.args.kwarg) if value is not None)
    nodes: list[ast.AST] = [*arguments]
    for statement in node.body:
        if isinstance(statement, (*_FUNCTIONS, ast.ClassDef)):
            nodes.append(statement)
        else:
            nodes.extend(_owned_nodes(statement))
    bindings = _bindings(nodes)
    positional = [*node.args.posonlyargs, *node.args.args]
    receiver = positional[0].arg if positional else None
    decorators = [ast.unparse(value) for value in node.decorator_list]
    # This feature does not establish binding/effect ownership for eager nested
    # definition headers. Keep those cases unresolved until the separate
    # definition-time feature proves them. Deferred nested bodies stay excluded.
    eager_header_unresolved = False
    for value in nodes:
        if isinstance(value, ast.ClassDef):
            eager_header_unresolved = True
        elif isinstance(value, (*_FUNCTIONS, ast.Lambda)):
            if (value.args.defaults or any(item is not None for item in value.args.kw_defaults)
                    or (not isinstance(value, ast.Lambda)
                        and (value.decorator_list or value.returns is not None))
                    or any(argument.annotation is not None for argument in
                           [*value.args.posonlyargs, *value.args.args, *value.args.kwonlyargs,
                            *(item for item in (value.args.vararg, value.args.kwarg) if item is not None)])
                    or getattr(value, "type_params", [])):
                eager_header_unresolved = True
    reads = [
        {"attribute": value.attr, "receiver": ast.unparse(value.value),
         "direct_receiver": isinstance(value.value, ast.Name) and value.value.id == receiver,
         "line": value.lineno, "column": value.col_offset}
        for value in nodes if isinstance(value, ast.Attribute) and isinstance(value.ctx, ast.Load)
    ]
    super_calls = [
        {"line": value.lineno, "column": value.col_offset,
         "zero_arguments": not value.func.value.args and not value.func.value.keywords}
        for value in nodes
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
        and value.func.attr == "__init__" and isinstance(value.func.value, ast.Call)
        and isinstance(value.func.value.func, ast.Name)
        and value.func.value.func.id == "super"
    ]
    return {"name": node.name, "symbol": symbol, "line": node.lineno,
            "decorators": decorators, "sync": isinstance(node, ast.FunctionDef),
            "receiver": receiver, "receiver_stable": receiver is not None and bindings[receiver] == 1,
            "local_bindings": dict(bindings), "unsafe_scope": _unsafe_scope(nodes),
            "eager_header_unresolved": eager_header_unresolved,
            "attribute_reads": reads, "super_calls": super_calls,
            "attribute_writes": [
                {"target": ast.unparse(value), "line": value.lineno}
                for value in nodes if isinstance(value, (ast.Attribute, ast.Subscript))
                and isinstance(value.ctx, (ast.Store, ast.Del))],
            "getter_signature": len(positional) == 1 and not node.args.kwonlyargs
            and node.args.vararg is None and node.args.kwarg is None
            and not node.args.defaults and not node.args.kw_defaults}


def _namespace_mutations(tree: ast.Module) -> list[dict[str, Any]]:
    """Conservative whole-source facts, including potentially deferred owners."""
    nodes = list(ast.walk(tree))
    parents = {child: parent for parent in nodes for child in ast.iter_child_nodes(parent)}
    mutators = {"exec", "eval", "globals", "locals", "vars", "setattr", "delattr"}
    bindings = _bindings(nodes)
    constants: dict[str, str] = {}
    for statement in tree.body:
        if (isinstance(statement, ast.Assign) and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str)
                and bindings[statement.targets[0].id] == 1):
            constants[statement.targets[0].id] = statement.value.value
    mutations = []
    for node in nodes:
        alias_name = (node.id if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
                      else node.attr if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load)
                      else None)
        parent = parents.get(node)
        if (isinstance(node, (ast.Name, ast.Attribute)) and alias_name in mutators
                and not (isinstance(parent, ast.Call) and parent.func is node)):
            mutations.append({"attribute": None, "line": node.lineno, "kind": "mutator_value_alias"})
        if isinstance(node, ast.ImportFrom) and any(alias.name in mutators for alias in node.names):
            mutations.append({"attribute": None, "line": node.lineno, "kind": "mutator_import_alias"})
        if isinstance(node, ast.Name) and node.id == "__builtins__":
            mutations.append({"attribute": None, "line": node.lineno, "kind": "dynamic_namespace"})
        if isinstance(node, ast.Attribute) and node.attr == "__dict__":
            mutations.append({"attribute": None, "line": node.lineno, "kind": "dynamic_namespace"})
        if not isinstance(node, ast.Call):
            continue
        name = (node.func.id if isinstance(node.func, ast.Name)
                else node.func.attr if isinstance(node.func, ast.Attribute) else "")
        if name in {"exec", "eval", "globals", "locals", "vars"}:
            mutations.append({"attribute": None, "line": node.lineno, "kind": "dynamic_namespace"})
        elif name in {"__setattr__", "__delattr__"}:
            mutations.append({"attribute": None, "line": node.lineno, "kind": name})
        elif name in {"setattr", "delattr"}:
            attribute = None
            if len(node.args) >= 2:
                value = node.args[1]
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    attribute = value.value
                elif isinstance(value, ast.Name):
                    attribute = constants.get(value.id)
            mutations.append({"attribute": attribute, "line": node.lineno, "kind": name})
    return mutations


def descriptor_source_facts(tree: ast.Module, *, path: str) -> dict[str, Any]:
    """Collect syntax only; actual import-root identity is checked later."""
    module_nodes = _owned_nodes(tree)
    module_bindings = _bindings(module_nodes)
    direct_dataclass_imports = {
        alias.asname or alias.name
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module == "dataclasses" and not node.level
        for alias in node.names if alias.name == "dataclass"
    }
    classes = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        class_nodes = _owned_nodes(node)[1:]
        bindings = _bindings(class_nodes)
        decorators = [ast.unparse(value) for value in node.decorator_list]
        dataclass_local = None
        if len(node.decorator_list) == 1:
            decorator = node.decorator_list[0]
            if (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name)
                    and decorator.func.id in direct_dataclass_imports and not decorator.args
                    and len(decorator.keywords) == 1 and decorator.keywords[0].arg == "frozen"
                    and isinstance(decorator.keywords[0].value, ast.Constant)
                    and decorator.keywords[0].value.value is True):
                dataclass_local = decorator.func.id
        symbol = f"{path}::{node.name}"
        methods = [_method_facts(member, f"{symbol}.{member.name}")
                   for member in node.body if isinstance(member, _FUNCTIONS)]
        classes.append({"symbol": symbol, "name": node.name, "line": node.lineno,
                        "bases": [ast.unparse(base) for base in node.bases],
                        "decorators": decorators, "keywords": bool(node.keywords),
                        "bindings": dict(bindings), "unsafe_scope": _unsafe_scope(class_nodes),
                        "dataclass_local": dataclass_local, "methods": methods})
    # Attribute assignments anywhere are conservative rebinding evidence. This
    # includes mutations in deferred owners without charging their reads here.
    attribute_writes = sorted({node.attr for node in ast.walk(tree)
                              if isinstance(node, ast.Attribute)
                              and isinstance(node.ctx, (ast.Store, ast.Del))})
    aliases = [(node.targets[0].id, node.value.id) for node in tree.body
               if isinstance(node, ast.Assign) and len(node.targets) == 1
               and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Name)]
    return {"path": path, "bindings": dict(module_bindings), "aliases": aliases,
            "namespace_mutations": _namespace_mutations(tree),
            "unsafe_scope": _unsafe_scope(module_nodes), "classes": classes,
            "attribute_writes": attribute_writes,
            "functions": [_method_facts(node, f"{path}::{node.name}")
                          for node in tree.body if isinstance(node, _FUNCTIONS)]}


def _class_safe(row: dict[str, Any], source: dict[str, Any], *,
                module_index: dict[str, str], inherited: set[str]) -> bool:
    if (row["symbol"] in inherited or row["bases"] or row["keywords"]
            or row["unsafe_scope"] or source["unsafe_scope"]
            or set(source["attribute_writes"]) & {"property", "__builtins__", "__dict__"}
            or source["bindings"].get(row["name"]) != 1
            or any(method["name"] in {"__getattribute__", "__getattr__"}
                   for method in row["methods"])):
        return False
    if not row["decorators"]:
        return True
    local = row["dataclass_local"]
    return (local is not None and source["bindings"].get(local) == 1
            and not row["bindings"].get(local)
            and not any(name == "dataclasses" or name.startswith("dataclasses.")
                        for name in module_index))


def _inherited_classes(sources: list[dict[str, Any]], inventory: dict[str, Any]) -> set[str]:
    classes = [row for source in sources for row in source["classes"]]
    symbols = {row["symbol"] for row in classes}
    by_name: dict[str, set[str]] = {}
    for row in classes:
        by_name.setdefault(row["name"], set()).add(row["symbol"])
    # Alias names remain conservative: a source alias can create a subclass
    # just as the original class spelling can. Iterate to a finite fixed point.
    aliases = [pair for source in sources for pair in source.get("aliases", [])]
    for _ in range(len(aliases)):
        for alias, original in aliases:
            if original in by_name:
                by_name.setdefault(alias, set()).update(by_name[original])
    inherited: set[str] = set()
    for row in classes:
        for base in row["bases"]:
            inherited.update(by_name.get(base.rsplit(".", 1)[-1], set()))
    for row in inventory.get("classes", []):
        for base in row.get("bases", []):
            target = base.get("called_symbol")
            if target in symbols:
                inherited.add(target)
    return inherited


def _failure(function: dict[str, Any], read: dict[str, Any]) -> dict[str, Any]:
    return {"kind": "ambiguous_property_access", "symbol": function["symbol"],
            "line": read["line"], "receiver": read["receiver"],
            "candidate_getters": read["candidate_getters"], "port_eligible": False}


def resolve_descriptor_dispatch(inventory: dict[str, Any], *,
                                module_index: dict[str, str]) -> None:
    """Add source edges; unresolved receiver identities never become permissions."""
    sources = inventory.get("descriptor_syntax", [])
    inherited = _inherited_classes(sources, inventory)
    functions = {row["symbol"]: row for row in inventory.get("functions", [])}
    candidates: dict[str, list[str]] = {}
    property_names: set[str] = set()
    accepted: set[str] = set()
    writes = {name for source in sources for name in source["attribute_writes"]}
    critical_names = _DYNAMIC_REBINDINGS | _EXCEPTIONS | {"property", "super", "dataclass", "__init__"}
    for source in sources:
        critical_names.update(source["bindings"])
        for row in source["classes"]:
            for method in row["methods"]:
                critical_names.add(method["name"])
                critical_names.update(read["attribute"] for read in method["attribute_reads"])
    cohort_uncertain = any(
        (mutation["attribute"] is None or mutation["attribute"] in critical_names)
        and not alias_discharged(inventory, str(source['path']), mutation)
        for source in sources for mutation in source["namespace_mutations"]
    )
    inventory["descriptor_binding_uncertainty"] = [
        {"path": source["path"], **mutation}
        for source in sources for mutation in source["namespace_mutations"]
        if (mutation["attribute"] is None or mutation["attribute"] in critical_names)
        and not alias_discharged(inventory, str(source['path']), mutation)
    ]
    owners: dict[str, tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = {}
    for source in sources:
        for row in source["classes"]:
            safe = _class_safe(row, source, module_index=module_index, inherited=inherited)
            if cohort_uncertain or writes & (_DYNAMIC_REBINDINGS | {"property"}):
                safe = False
            if row["decorators"] and "dataclass" in writes:
                safe = False
            for method in row["methods"]:
                owners[method["symbol"]] = (source, row, method)
                decorators = method["decorators"]
                if not decorators:
                    continue
                if "property" in decorators:
                    property_names.add(method["name"])
                known_method_binding = (
                    safe and len(decorators) == 1
                    and decorators[0] in {"classmethod", "staticmethod"}
                    and not cohort_uncertain and decorators[0] not in writes
                    and not source["bindings"].get(decorators[0])
                    and not row["bindings"].get(decorators[0])
                    and row["bindings"].get(method["name"]) == 1
                    and method["name"] not in writes
                )
                if known_method_binding:
                    continue
                # An unsupported decorator may produce a descriptor. Keep its
                # read unresolved rather than treating the attribute as inert.
                candidates.setdefault(method["name"], []).append(method["symbol"])
                if (safe and method["decorators"] == ["property"] and method["sync"]
                        and method["getter_signature"] and method["receiver_stable"]
                        and not method["unsafe_scope"] and not method["eager_header_unresolved"]
                        and not source["bindings"].get("property")
                        and not row["bindings"].get("property")
                        and row["bindings"].get(method["name"]) == 1 and method["name"] not in writes):
                    accepted.add(method["symbol"])
        for method in source["functions"]:
            owners[method["symbol"]] = (source, {}, method)
    for symbol, (source, row, method) in owners.items():
        function = functions.get(symbol)
        if function is None:
            continue
        if symbol in accepted:
            function["descriptor_identity"] = "builtin_property_getter"
            function["effect_unresolved"] = [failure for failure in function.get("effect_unresolved", [])
                                              if failure.get("dispatch_kind") != "decorated_method"]
            for write in method["attribute_writes"]:
                function.setdefault("calls", []).append({
                    "caller": symbol, "called_symbol": f"{symbol}:attribute_write:{write['target']}",
                    "call_name": "<descriptor-body-write>", "line": write["line"],
                    "effect": "write", "argument_origins": []})
        reads = []
        for syntax in method["attribute_reads"]:
            targets = sorted(set(candidates.get(syntax["attribute"], [])))
            if not targets:
                continue
            read = {**syntax, "candidate_getters": targets, "caller": symbol}
            own_target = f"{row.get('symbol', '')}.{syntax['attribute']}"
            if (syntax["direct_receiver"] and method["receiver_stable"]
                    and not method["unsafe_scope"] and not method["eager_header_unresolved"]
                    and (not method["decorators"] or symbol in accepted)
                    and own_target in accepted):
                read["resolved_getter"] = own_target
                function.setdefault("calls", []).append({
                    "caller": symbol, "called_symbol": own_target,
                    "call_name": syntax["attribute"], "line": syntax["line"],
                    "dispatch_resolution": "exact_property_getter", "argument_origins": [],
                    "descriptor_access": True})
            else:
                function.setdefault("effect_unresolved", []).append(_failure(function, read))
            reads.append(read)
        function["descriptor_reads"] = reads
        function["property_reads"] = [read for read in reads if read["attribute"] in property_names]
        if row:
            _resolve_builtin_super(function, source, row, method,
                                   inherited=inherited, writes=writes,
                                   cohort_uncertain=cohort_uncertain)


def _resolve_builtin_super(function: dict[str, Any], source: dict[str, Any],
                           row: dict[str, Any], method: dict[str, Any], *,
                           inherited: set[str], writes: set[str], cohort_uncertain: bool) -> None:
    bases = row["bases"]
    if (cohort_uncertain or len(bases) != 1 or bases[0] not in _EXCEPTIONS or row["symbol"] in inherited
            or row["decorators"] or row["keywords"] or row["unsafe_scope"]
            or source["unsafe_scope"] or method["unsafe_scope"]
            or method["eager_header_unresolved"]
            or writes & (_DYNAMIC_REBINDINGS | {"super", bases[0]})
            or method["name"] != "__init__" or method["decorators"]
            or not method["sync"] or not method["receiver_stable"]
            or source["bindings"].get(row["name"]) != 1
            or any(m["name"] in {"__getattribute__", "__getattr__"} for m in row["methods"])
            or any(scope.get(name) for scope in (source["bindings"], row["bindings"])
                   for name in (bases[0], "super"))
            or method["local_bindings"].get("super")
            or method["local_bindings"].get("__class__")
            or "__init__" in writes
            or row["bindings"].get("__init__") != 1):
        return
    line_counts = Counter(site["line"] for site in method["super_calls"])
    allowed = {site["line"] for site in method["super_calls"]
               if site["zero_arguments"] and line_counts[site["line"]] == 1}
    target = f"builtin:{bases[0]}.__init__"
    function["builtin_super_constructors"] = [{"target": target, "line": line}
                                                for line in sorted(allowed)]
    resolved_calls: set[tuple[Any, Any]] = set()
    for call in function.get("calls", []):
        reference = call.get("method_dispatch", {})
        if (reference.get("kind") == "super" and reference.get("method") == "__init__"
                and call.get("line") in allowed):
            resolved_calls.add((call.get("line"), call.get("called_symbol")))
            call["called_symbol"] = target
            call["dispatch_resolution"] = "exact_builtin_exception_constructor"
            call.pop("dispatch_port_eligible", None)
    function["effect_unresolved"] = [
        failure for failure in function.get("effect_unresolved", [])
        if not (failure.get("dispatch_kind") == "super"
                and (failure.get("line"), failure.get("called_symbol")) in resolved_calls)
    ]

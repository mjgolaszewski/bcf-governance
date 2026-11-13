"""Neutral retained-write and implicit-execution facts for Python scopes.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""
from __future__ import annotations

import ast
import hashlib
from typing import Any

from .semantic_python_constructor_callbacks import (
    constructor_callback_closures,
    resolve_exception_callbacks,
)

_MUTATORS = {
    "add", "append", "clear", "difference_update", "discard", "extend",
    "insert", "intersection_update", "pop", "popitem", "remove", "reverse",
    "setdefault", "sort", "symmetric_difference_update", "update",
    "__delitem__", "__setitem__",
}


def _scope_nodes(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.AST]:
    """Do not attribute an uninvoked nested definition's body to its parent."""
    result: list[ast.AST] = []
    pending: list[ast.AST] = list(function.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        result.append(node)
        pending.extend(ast.iter_child_nodes(node))
    return result


def _trivial_finalizer(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Only a plain no-op closes the interpreter's unraisable-hook boundary."""
    body = list(function.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    return (isinstance(function, ast.FunctionDef)
        and len([*function.args.posonlyargs, *function.args.args]) == 1
        and not function.args.kwonlyargs and not function.args.vararg and not function.args.kwarg
        and function.name == "__del__" and not function.decorator_list and all(
        isinstance(node, ast.Pass) or isinstance(node, ast.Return) and (
            node.value is None or isinstance(node.value, ast.Constant) and node.value.value is None
        ) for node in body
    ))


def container_builtin_names(tree: ast.Module) -> list[str]:
    """Derive stable builtin lexical identities once per source module."""
    bindings = {
        node.id for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
    }
    bindings.update(node.name for node in ast.walk(tree)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    bindings.update(node.arg for node in ast.walk(tree) if isinstance(node, ast.arg))
    bindings.update(node.asname or node.name.split(".")[0]
                    for node in ast.walk(tree) if isinstance(node, ast.alias))
    bindings.update(node.name for node in ast.walk(tree)
                    if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar))
                    and node.name)
    reflective = any(
        isinstance(node, ast.Name) and node.id in {
            "globals", "locals", "vars", "setattr", "delattr", "exec",
            "eval", "__import__", "__builtins__",
        }
        or isinstance(node, ast.Import) and any(alias.name == "builtins" for alias in node.names)
        or isinstance(node, ast.ImportFrom) and node.module == "builtins"
        for node in ast.walk(tree)
    )
    return sorted(
        {"len", "list", "tuple", "dict", "set", "bool", "super",
         "BaseException", "Exception", "ValueError", "RuntimeError", "type", "str", "int", "float", "complex", "bytes"} - bindings
    ) if "*" not in bindings and not reflective else []


def extend_python_effect_facts(
    tree: ast.Module, function: ast.FunctionDef | ast.AsyncFunctionDef,
    fact: dict[str, Any], path: str, *, builtin_names: list[str],
) -> None:
    """Record effects and callback obligations without granting runtime authority.

    A callback edge is an obligation to inspect its body, never evidence that
    the constructed object is detached or that a third-party decorator is pure.
    """
    nodes = _scope_nodes(function)
    fact['legacy_effect_sites'] = [[item.get('kind'), item.get('line'), item.get('target')]
                                   for item in fact.get('effects', [])]
    fact['lexically_allocated_containers'] = sorted({
        target.id for statement in _scope_nodes(function) if isinstance(statement, (ast.Assign, ast.AnnAssign))
        and isinstance(statement.value, (ast.List, ast.Dict, ast.Set, ast.Tuple, ast.ListComp, ast.DictComp, ast.SetComp))
        for target in (statement.targets if isinstance(statement, ast.Assign) else [statement.target])
        if isinstance(target, ast.Name)})
    fact["trivial_finalizer"] = _trivial_finalizer(function)
    fact["python_value_source"] = ast.unparse(function)
    fact["python_value_shape_sha256"] = hashlib.sha256(
        ast.dump(function, include_attributes=False).encode()
    ).hexdigest()
    fact["unshadowed_container_builtins"] = list(builtin_names)
    fact["python_value_sites"] = [
        [getattr(node, "lineno", 0), getattr(node, "col_offset", 0)]
        for node in ast.walk(function)
    ]
    parameters = {
        argument.arg for argument in [*function.args.posonlyargs, *function.args.args,
                                     *function.args.kwonlyargs]
    }
    retained = {name for node in nodes if isinstance(node, (ast.Global, ast.Nonlocal))
                for name in node.names}
    stores: dict[str, int] = {}
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            stores[node.id] = stores.get(node.id, 0) + 1
    fact['external_write_roots'] = sorted(retained | {
        node.id for node in nodes if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        and node.id not in parameters and node.id not in stores})
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    instances: dict[str, str] = {}
    scope_parents = {id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)}
    fact['caught_protocol_reads'] = []
    for call in nodes:
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                and call.func.id in {'str', 'repr'} and len(call.args) == 1
                and isinstance(call.args[0], ast.Name)):
            continue
        current: ast.AST | None = call
        while current is not None:
            if isinstance(current, ast.ExceptHandler) and current.name == call.args[0].id and current.type is not None:
                types = current.type.elts if isinstance(current.type, ast.Tuple) else [current.type]
                fact['caught_protocol_reads'].append({'call_name': call.func.id,
                    'line': call.lineno, 'column': call.col_offset,
                    'caught_type_expressions': [ast.unparse(value) for value in types]})
                break
            current = scope_parents.get(id(current))
    effects: list[dict[str, Any]] = []
    obligations: list[dict[str, Any]] = []
    for node in nodes:
        if isinstance(node, ast.FormattedValue):
            obligations.append({'kind': 'unqualified_format_callback',
                                'line': node.value.lineno, 'column': node.value.col_offset})


    def write(node: ast.AST, target: str) -> None:
        row = {"kind": "write", "line": getattr(node, "lineno", 0), "target": target}
        if row not in effects:
            effects.append(row)

    def class_of(value: ast.AST) -> str | None:
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            return value.func.id if value.func.id in classes else None
        if isinstance(value, ast.Name):
            current: ast.AST | None = value
            while current is not None:
                if (isinstance(current, ast.ExceptHandler) and current.name == value.id
                        and isinstance(current.type, ast.Name) and current.type.id in classes
                        and not stores.get(value.id)):
                    return current.type.id
                current = scope_parents.get(id(current))
            return instances.get(value.id)
        return None

    def callback(node: ast.AST, owner: str, name: str, seen: frozenset[str] = frozenset()) -> None:
        if owner in seen:
            obligations.append({"kind": "unqualified_protocol_inheritance_cycle", "line": getattr(node, "lineno", 0)})
            return
        cls = classes[owner]
        methods = [member for member in cls.body
                   if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                   and member.name == name]
        if not methods:
            if name in {'__str__', '__repr__', '__bool__', '__len__'}:
                for base in cls.bases:
                    if isinstance(base, ast.Name) and base.id in classes:
                        callback(node, base.id, name, seen | {owner})
            return
        edge = {"caller": fact["symbol"],
            "called_symbol": f"{path}::{owner}.{name}", "call_name": name,
            "line": getattr(node, "lineno", 0), "column": getattr(node, "col_offset", 0),
            "implicit_callback": True}
        if name == "__del__":
            edge["callback_phase"] = "possible_finalization"
            if not _trivial_finalizer(methods[0]):
                obligations.append({"kind": "unqualified_finalizer_exception_boundary",
                    "line": getattr(node, "lineno", 0), "class_symbol": f"{path}::{owner}"})
        fact["calls"].append(edge)

    for node in nodes:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            owner = class_of(node.value)
            if owner:
                for target in targets:
                    if isinstance(target, ast.Name) and stores.get(target.id) == 1:
                        instances[target.id] = owner
    for node in nodes:
        if isinstance(node, ast.FormattedValue):
            owner = class_of(node.value)
            if owner:
                callback(node.value, owner, '__str__' if node.conversion == ord('s') else '__repr__' if node.conversion == ord('r') else '__format__')
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if node.id in retained:
                write(node, node.id)
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            write(node, ast.unparse(node))
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in _MUTATORS:
                write(node, ast.unparse(node.func))
            owner = class_of(node)
            if owner:
                callback(node, owner, "__new__")
                callback(node, owner, "__init__")
                callback(node, owner, "__del__")
                cls = classes[owner]
                # A generated initializer can invoke __post_init__. Until its
                # decorator/binding is qualified, this remains an obligation.
                if cls.decorator_list:
                    callback(node, owner, "__post_init__")
            if isinstance(node.func, ast.Name) and node.func.id in {"str", "repr", "bool", "len"} and node.args:
                owner = class_of(node.args[0])
                if owner:
                    callback(node, owner, {"str": "__str__", "repr": "__repr__",
                        "bool": "__bool__", "len": "__len__"}[node.func.id])
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            owner = class_of(node.value)
            if owner and any(isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                             and member.name == node.attr and any(
                                 isinstance(decorator, ast.Name) and decorator.id == "property"
                                 for decorator in member.decorator_list)
                             for member in classes[owner].body):
                callback(node, owner, node.attr)
        if isinstance(node, ast.comprehension):
            for condition in node.ifs:
                owner = class_of(condition)
                if owner:
                    names = {member.name for member in classes[owner].body
                             if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))}
                    callback(condition, owner, "__bool__" if "__bool__" in names else "__len__")
    fact["effects"] = effects
    fact["implicit_effect_obligations"] = obligations
    fact["call_result_attribute_reads"] = [
        {"attribute": node.attr, "line": node.value.lineno,
         "column": node.value.col_offset}
        for node in nodes if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load)
        and isinstance(node.value, ast.Call)
    ]
    body = list(function.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    if (len(body) == 1 and isinstance(body[0], ast.Return)
            and isinstance(body[0].value, ast.Call) and isinstance(body[0].value.func, ast.Name)
            and body[0].value.func.id in classes):
        fact["direct_fresh_return"] = f"{path}::{body[0].value.func.id}"
    returns = [node for node in nodes if isinstance(node, ast.Return)]
    if (returns and function.args.args and fact.get('decorators') == ['classmethod']
            and all(isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == function.args.args[0].arg for node in returns)
            and not any(isinstance(node, ast.Name) and node.id == function.args.args[0].arg
                        and isinstance(node.ctx, (ast.Store, ast.Del)) for node in nodes)):
        fact['direct_class_receiver_return'] = True
    parents = {id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)}
    escaped = set()
    for node in nodes:
        if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
            continue
        parent = parents.get(id(node))
        grandparent = parents.get(id(parent))
        if not (isinstance(parent, ast.Attribute) and parent.value is node
                and isinstance(parent.ctx, ast.Load) and isinstance(grandparent, ast.Call)
                and grandparent.func is parent):
            escaped.add(node.id)
    fact["call_result_bindings"] = [
        {"local": target.id, "line": node.value.lineno}
        for node in nodes if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
        for target in node.targets if isinstance(target, ast.Name) and stores.get(target.id) == 1
        and target.id not in retained and target.id not in parameters
        and target.id not in escaped
    ]


def resolve_python_implicit_effects(inventory: dict[str, Any]) -> None:
    """Bind constructor obligations after neutral imports have exact identities.

    This deliberately uses the existing closed-binding proof. A spelling,
    annotation or classmethod's return type cannot qualify a dynamic model.
    """
    classes = {str(row["symbol"]): row for row in inventory.get("classes", [])}
    functions = {str(row["symbol"]): row for row in inventory.get("functions", [])}
    constructor_closures = constructor_callback_closures(classes)
    resolve_exception_callbacks(inventory, constructor_closures)
    for function in inventory.get("functions", []):
        for call in function.get("calls", []):
            reference = call.get("method_dispatch", {})
            if reference.get("kind") != "receiver_alias":
                continue
            bindings = [binding for binding in function.get("call_result_bindings", [])
                        if binding["local"] == reference.get("receiver_root")]
            if len(bindings) != 1:
                continue
            if bindings[0]["line"] >= call.get("line", 0):
                continue
            producers = [producer for producer in function["calls"]
                         if producer.get("line") == bindings[0]["line"]
                         and producer.get("dispatch_resolution") == "exact_same_instance"]
            if len(producers) != 1:
                continue
            producer = functions.get(str(producers[0]["called_symbol"]), {})
            subject = str(producer.get("direct_fresh_return", ""))
            cls = classes.get(subject, {})
            if not cls.get("closed_class_binding") or producer.get("effect_unresolved") or producer.get("unresolved"):
                continue
            if cls.get("library_model_binding"):
                continue
            if any(method["name"] == "__post_init__" or method.get("decorators") == ["property"]
                   for method in cls.get("methods", [])):
                continue
            targets = [method for method in cls.get("methods", [])
                       if method["name"] == reference.get("method")
                       and method["binding"] == "instance" and not method.get("decorators")]
            if len(targets) != 1:
                continue
            if any(str(scope.get("class_symbol", "")) == subject and
                   (reference.get("method") in scope.get("receiver_attribute_mutations", [])
                    or "*" in scope.get("receiver_attribute_mutations", []))
                   for scope in functions.values()):
                continue
            previous_symbol = call.get("called_symbol")
            call["called_symbol"] = targets[0]["symbol"]
            call["dispatch_resolution"] = "exact_fresh_source_record"
            function["effect_unresolved"] = [failure for failure in function.get("effect_unresolved", [])
                if not (failure.get("line") == call.get("line")
                        and failure.get("called_symbol") == previous_symbol
                        and failure.get("dispatch_kind") == "receiver_alias")]
        callbacks: list[dict[str, Any]] = []
        for read in function.get("call_result_attribute_reads", []):
            producers = [(index, call) for index, call in enumerate(function["calls"])
                         if call.get("line") == read["line"] and call.get("column") == read["column"]]
            if len(producers) != 1:
                continue
            occurrence, producer_call = producers[0]
            subjects = {str(producer_call.get("called_symbol", ""))} & classes.keys()
            producer = functions.get(str(producer_call.get("called_symbol", "")), {})
            bound_subjects = {str(binding["constructed_symbol"])
                for call in producer.get("calls", [])
                for binding in call.get("class_constructor_bindings", [])
                if binding.get("binding_caller") == function["symbol"]
                and binding.get("binding_occurrence") == occurrence}
            if bound_subjects and not producer.get("direct_class_receiver_return"):
                function.setdefault("implicit_effect_obligations", []).append({
                    "kind": "unqualified_constructor_return_binding", "line": read["line"]})
                continue
            subjects.update(bound_subjects)
            if len(subjects) != 1:
                continue
            subject = next(iter(subjects))
            for method in classes.get(subject, {}).get("methods", []):
                if method["name"] == read["attribute"] and method.get("decorators") == ["property"]:
                    callbacks.append({"caller": function["symbol"],
                        "called_symbol": method["symbol"], "call_name": method["name"],
                        "line": read["line"], "implicit_callback": True})
        for call in function.get("calls", []):
            subjects = {str(call.get("called_symbol", ""))}
            subjects.update(str(binding["constructed_symbol"])
                for binding in call.get("class_constructor_bindings", []))
            for subject in call.get('generated_copy_candidates', []):
                function.setdefault('implicit_effect_obligations', []).append({
                    'kind': 'unqualified_generated_copy_binding', 'line': call.get('line'),
                    'column': call.get('column'), 'class_symbol': subject})
            subjects.update(call.get('generated_copy_candidates', []))
            for subject in subjects & classes.keys():
                cls = classes[subject]
                closure = constructor_closures.get(subject)
                if closure and call.get("called_symbol") == subject:
                    initializer = closure.get("initializer")
                    call["source_constructor_frame"] = {
                        "subject": subject, "initializer": initializer["symbol"] if initializer else None,
                        "initializer_owner": closure["initializer_owner"],
                        "super_initializer": closure["super_initializer"],
                        "native_exception_initializer": initializer is None and 'builtins::BaseException' in closure['mro'],
                    }
                if (cls.get("closed_class_binding") and cls.get("standard_dataclass_declaration")
                        and cls.get("generated_record_fields") is not None
                        and call.get("called_symbol") == subject):
                    call["source_record_fields"] = {"subject": subject,
                                                    "fields": cls["generated_record_fields"]}
                if cls.get("library_model_binding"):
                    function.setdefault("implicit_effect_obligations", []).append({
                        "kind": "unqualified_library_model_effects", "line": call.get("line"),
                        "class_symbol": subject})
                if not cls.get("closed_class_binding") and not closure:
                    obligation = {"kind": "unqualified_constructor_callbacks",
                                  "line": call.get("line"), "class_symbol": subject}
                    if obligation not in function.setdefault("implicit_effect_obligations", []):
                        function["implicit_effect_obligations"].append(obligation)
                effective = closure["methods"].values() if closure else cls.get("methods", [])
                names = {str(method["name"]): str(method["symbol"]) for method in effective}
                if closure and not cls.get("closed_class_binding") and not call.get("literal_arguments"):
                    function.setdefault("implicit_effect_obligations", []).append({
                        "kind": "unqualified_constructor_input_binding", "line": call.get("line"),
                        "column": call.get("column"), "class_symbol": subject,
                        "binding_source": "constructor_initializer_frame"})
                # An unrelated property does not execute during construction.
                # Getter reads keep their independent callback edges above.
                has_hooks = "__post_init__" in names and cls.get("standard_dataclass_declaration")
                if has_hooks and (not call.get("literal_arguments") or cls.get("dataclass_default_factories")):
                    function.setdefault("implicit_effect_obligations", []).append({
                        "kind": "unqualified_constructor_input_binding", "line": call.get("line"),
                        "class_symbol": subject})
                if cls.get("closed_class_binding"):
                    for field, factory in (cls.get("dataclass_default_factories") or {}).items():
                        callbacks.append({"caller": function["symbol"],
                            "called_symbol": factory, "call_name": factory.rsplit("::", 1)[-1],
                            "line": call.get("line"), "implicit_callback": True,
                            "dataclass_field": field})
                for name in ("__new__", "__init__", "__post_init__", "__del__"):
                    if name == "__post_init__" and not cls.get("standard_dataclass_declaration"):
                        continue
                    if name in names:
                        edge = {"caller": function["symbol"],
                            "called_symbol": names[name], "call_name": name,
                            "line": call.get("line"), "column": call.get("column"),
                            "implicit_callback": True}
                        if name == "__init__" and call.get("source_constructor_frame"):
                            edge["constructor_frame_origin"] = {
                                "line": call.get("line"), "column": call.get("column"),
                                "subject": subject, "target": names[name]}
                            for existing in function["calls"]:
                                if (existing.get("implicit_callback") and existing.get("called_symbol") == names[name]
                                        and existing.get("line") == call.get("line")
                                        and existing.get("column") == call.get("column")):
                                    existing.update(edge)
                        if name == "__del__":
                            # This is a lifetime obligation, not a claim that
                            # finalization runs during the constructor itself.
                            edge["callback_phase"] = "possible_finalization"
                            if not functions.get(names[name], {}).get("trivial_finalizer"):
                                obligation = {"kind": "unqualified_finalizer_exception_boundary",
                                    "line": call.get("line"), "class_symbol": subject}
                                if obligation not in function.setdefault("implicit_effect_obligations", []):
                                    function["implicit_effect_obligations"].append(obligation)
                        callbacks.append(edge)
        for callback in callbacks:
            if callback not in function["calls"]:
                function["calls"].append(callback)

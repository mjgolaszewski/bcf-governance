"""Python AST function and call facts for the shared source inventory.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import ast
import hashlib
from typing import Any

from .semantic_python_annotation_identity import annotation_text as _annotation
from .semantic_python_method_identity import (
    bound_method_origins,
    call_name as _call_name,
    call_reference as _call_reference,
    method_binding,
    method_dispatch_reference,
    root_name as _root_name,
    source_symbol,
)


from .semantic_python_protocols import (
    _native_literal_value, IMPLICIT_PROTOCOL_KIND_VERSIONS, implicit_runtime_protocols,
)


NORMALIZERS = {
    "casefold",
    "decode",
    "filter",
    "get",
    "join",
    "lower",
    "lstrip",
    "parse",
    "replace",
    "rstrip",
    "split",
    "strip",
    "upper",
}
DYNAMIC_CALLS = {"__import__", "eval", "exec"}
PRIMITIVES = {"bool", "bytes", "float", "int", "None", "str"}


def _normalized_return_fingerprint(
    expression: ast.expr, parameters: set[str]
) -> str:
    class Normalize(ast.NodeTransformer):
        def visit_Name(self, node: ast.Name) -> ast.AST:  # noqa: N802
            if node.id in parameters:
                return ast.copy_location(ast.Name(id="$parameter", ctx=node.ctx), node)
            return node

    reparsed = ast.parse(ast.unparse(expression), mode="eval").body
    normalized = Normalize().visit(ast.fix_missing_locations(reparsed))
    return hashlib.sha256(
        ast.dump(normalized, annotate_fields=False, include_attributes=False).encode()
    ).hexdigest()


def _closed_native_region(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str] | None:
    """A linear, call-free literal region has no external container references."""
    args = function.args
    parameters = {arg.arg for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs,
                                      *([args.vararg] if args.vararg else []),
                                      *([args.kwarg] if args.kwarg else [])]}
    names: set[str] = set()
    observed: set[str] = set()
    def target(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            if node.id in parameters:
                return False
            names.add(node.id)
            observed.add(node.id)
            return True
        return isinstance(node, ast.Subscript) and _native_literal_value(node, names)
    for statement in function.body:
        if isinstance(statement, ast.Assign):
            if not _native_literal_value(statement.value, names) or not all(target(value) for value in statement.targets):
                return None
        elif isinstance(statement, ast.AugAssign):
            if not _native_literal_value(statement.target, names) or not _native_literal_value(statement.value, names):
                return None
        elif isinstance(statement, ast.Delete):
            for value in statement.targets:
                if not _native_literal_value(value, names):
                    return None
                if isinstance(value, ast.Name):
                    names.remove(value.id)
        elif isinstance(statement, ast.Return):
            if statement.value is not None and not _native_literal_value(statement.value, names):
                return None
        elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
            continue
        elif not isinstance(statement, ast.Pass):
            return None
    return observed


def _closed_owned_scalar_cells(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str] | None:
    """Recognize only a whole closed, synchronous literal-int cell region."""
    args = function.args
    if (not isinstance(function, ast.FunctionDef) or function.decorator_list or function.returns
            or args.posonlyargs or args.args or args.kwonlyargs or args.vararg or args.kwarg
            or args.defaults or args.kw_defaults or getattr(function, "type_params", [])):
        return None
    cells: set[str] = set()
    children: set[str] = set()
    shared: set[str] = set()

    def integer(node: ast.AST | None) -> bool:
        return isinstance(node, ast.Constant) and type(node.value) is int

    for statement in function.body:
        if isinstance(statement, ast.Assign):
            if (len(statement.targets) != 1 or not isinstance(statement.targets[0], ast.Name)
                    or not integer(statement.value) or statement.targets[0].id in cells | children):
                return None
            cells.add(statement.targets[0].id)
        elif isinstance(statement, ast.FunctionDef):
            child_args = statement.args
            if (statement.name in cells | children or statement.decorator_list or statement.returns
                    or child_args.posonlyargs or child_args.args or child_args.kwonlyargs
                    or child_args.vararg or child_args.kwarg or child_args.defaults
                    or child_args.kw_defaults or getattr(statement, "type_params", [])):
                return None
            nonlocals = {name for node in statement.body if isinstance(node, ast.Nonlocal) for name in node.names}
            if not nonlocals <= cells:
                return None
            for node in statement.body:
                if isinstance(node, ast.Nonlocal):
                    continue
                if (isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name)
                        and node.target.id in nonlocals and isinstance(node.op, (ast.Add, ast.Sub))
                        and integer(node.value)):
                    continue
                if (isinstance(node, ast.Assign) and len(node.targets) == 1
                        and isinstance(node.targets[0], ast.Name) and node.targets[0].id in nonlocals
                        and integer(node.value)):
                    continue
                if isinstance(node, ast.Return) and (node.value is None or integer(node.value)):
                    continue
                if isinstance(node, ast.Pass):
                    continue
                return None
            shared.update(nonlocals)
            children.add(statement.name)
        elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
            call = statement.value
            if not isinstance(call.func, ast.Name) or call.func.id not in children or call.args or call.keywords:
                return None
        elif isinstance(statement, ast.Return):
            if not integer(statement.value) and not (isinstance(statement.value, ast.Name) and statement.value.id in cells):
                return None
        else:
            return None
    return sorted(shared) if shared else None


class _FunctionVisitor(ast.NodeVisitor):
    def __init__(
        self,
        *,
        path: str,
        imports: dict[str, str],
        import_bindings: dict[str, dict[str, Any]],
        local_types: set[str],
        class_name: str | None,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        call_contracts: bool = False,
        lexical_context: dict[str, Any] | None = None,
        postponed_annotations: bool = False,
        lexical_parent_function: ast.FunctionDef | ast.AsyncFunctionDef | None = None,
    ) -> None:
        self.call_contracts = call_contracts
        context = lexical_context or {}
        self.lexical_parent = context.get('lexical_parent')
        self._lexical_bindings = context.get('bindings', {})
        self._closure_parameters = context.get('closure_parameters', {})
        self._ambiguous_imports = set(context.get('ambiguous_imports', []))
        self._postponed_annotations = postponed_annotations
        self._call_target_attributes = {id(node.func) for node in ast.walk(function) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self._owned_scalar_cells = _closed_owned_scalar_cells(function) if self.lexical_parent is None else None
        self._root_function = function
        self._track_global_stores = False
        self._track_operation_stores = False
        self._native_region = _closed_native_region(function)
        self._parent_scalar_cells = set(_closed_owned_scalar_cells(lexical_parent_function) or ()) if (
            lexical_parent_function is not None and any(child is function for child in lexical_parent_function.body)
        ) else set()
        self._source_stores: list[dict[str, Any]] = []
        self._store_occurrences: dict[str, int] = {}
        self._global_store_effects: list[dict[str, Any]] = []
        self._global_names: set[str] = set()
        self._nonlocal_names: set[str] = set()
        pending = list(function.body)
        while pending:
            node = pending.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(node, ast.Global):
                self._global_names.update(node.names)
            if isinstance(node, ast.Nonlocal):
                self._nonlocal_names.update(node.names)
            pending.extend(ast.iter_child_nodes(node))
        self.call_occurrences: dict[str, int] = {}
        self.path = path
        self.imports = imports
        self.import_bindings = import_bindings
        self.local_types = local_types
        self.class_symbol = f"{path}::{class_name}" if class_name else None
        self.method_binding_kind, self.receiver = method_binding(function)
        self.decorators = sorted(ast.unparse(value) for value in function.decorator_list)
        suffix = f"{class_name}.{function.name}" if class_name else function.name
        self.symbol = path + "::" + context.get("qualified_name", suffix)
        arguments = [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
            *([function.args.vararg] if function.args.vararg else []),
            *([function.args.kwarg] if function.args.kwarg else []),
        ]
        self.parameters = {
            argument.arg: _annotation(argument.annotation) for argument in arguments
        }
        self.assignments = {
            name: {f"parameter:{name}"} for name in {**self._closure_parameters, **self.parameters}
        }
        for name, binding in self._lexical_bindings.items():
            self.assignments.setdefault(name, {'lexical_function:' + binding['symbol']})
        self.calls: list[dict[str, Any]] = []
        self.constructors: list[dict[str, Any]] = []
        self.normalizations: list[dict[str, Any]] = []
        self.unresolved: list[dict[str, Any]] = []
        self.return_fingerprints: list[str] = []
        self.return_annotation = _annotation(function.returns)
        self.receiver_attribute_mutations: set[str] = set()

    def _record_global_binding(self, name: str, node: ast.stmt | ast.expr) -> None:
        if self._track_global_stores and name in self._global_names | self._nonlocal_names:
            self._global_store_effects.append({
                "kind": "write", "target": name, "scope": "global" if name in self._global_names else "nonlocal",
                "line": node.lineno, "column": node.col_offset,
            })

    def _visit_scoped_fields(self, node: ast.AST, active_fields: set[str], operation_fields: set[str]) -> None:
        previous = self._track_global_stores
        operation_previous = self._track_operation_stores
        try:
            for field, value in ast.iter_fields(node):
                if field == 'body' and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and node is not self._root_function:
                    continue
                if self._postponed_annotations and field == 'returns' and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                self._track_global_stores = field in active_fields
                self._track_operation_stores = field in operation_fields
                for child in value if isinstance(value, list) else [value]:
                    if isinstance(child, ast.AST):
                        self.visit(child)
        finally:
            self._track_global_stores = previous
            self._track_operation_stores = operation_previous

    def visit(self, node: ast.AST) -> Any:
        if self._track_operation_stores:
            native = self._native_region or set()
            if isinstance(node, ast.AugAssign):
                native = native | self._parent_scalar_cells
            for kind in implicit_runtime_protocols(node, native, self._call_target_attributes):
                self._record_implicit_protocol(node.iter if isinstance(node, ast.comprehension) else node, kind)
        return super().visit(node)

    def _record_implicit_protocol(self, node: ast.AST, kind: str) -> None:
        contract = self._source_call_contract(node)
        contract['arguments'] = []
        fact = {
            "caller": self.symbol, "called_symbol": "python-implicit::" + kind,
            "call_name": "<implicit>", "line": node.lineno, "column": node.col_offset,
            "end_line": node.end_lineno, "end_column": node.end_col_offset,
            "argument_origins": sorted(self._origins(node)),
            "dispatch_resolution": "unresolved", "dispatch_port_eligible": False,
            "implicit_protocol": {
                "version": IMPLICIT_PROTOCOL_KIND_VERSIONS.get(kind, "1.0"), "authority": False, "execution_qualified": False,
                "kind": kind, "expression_sha256": contract["expression_sha256"],
                "occurrence": contract["occurrence"],
            },
        }
        if self.call_contracts:
            fact["call_contract"] = contract
        self.calls.append(fact)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        if node is self._root_function:
            active = {"body"}
        else:
            self._record_global_binding(node.name, node)
        if node is not self._root_function:
            annotations = [arg.annotation for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs, *([node.args.vararg] if node.args.vararg else []), *([node.args.kwarg] if node.args.kwarg else [])]]
            if (node.decorator_list or getattr(node, "type_params", [])
                    or (not self._postponed_annotations and any(value is not None for value in [*annotations, node.returns]))
                    or any(value is not None and not _native_literal_value(value, set()) for value in [*node.args.defaults, *node.args.kw_defaults])):
                self._global_store_effects.append({"kind": "unresolved", "target": "definition_evaluation",
                                                  "scope": "definition_eager", "line": node.lineno, "column": node.col_offset})
            active = {field for field, _ in ast.iter_fields(node) if field != "body"} if self._track_global_stores else set()
        operation = {"body"} if node is self._root_function else ({field for field, _ in ast.iter_fields(node) if field != "body"} if self._track_operation_stores else set())
        self._visit_scoped_fields(node, active, operation)

    def visit_arg(self, node: ast.arg) -> None:
        if node.annotation is not None and not self._postponed_annotations:
            self.visit(node.annotation)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self.visit_FunctionDef(node)  # type: ignore[arg-type]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        if self._track_operation_stores:
            self._global_store_effects.append({"kind": "unresolved", "target": "local_class_construction",
                                              "scope": "definition_eager", "line": node.lineno, "column": node.col_offset})
        self._record_global_binding(node.name, node)
        active = {field for field, _ in ast.iter_fields(node) if field != "body"} if self._track_global_stores else set()
        operation = {field for field, _ in ast.iter_fields(node)} if self._track_operation_stores else set()
        self._visit_scoped_fields(node, active, operation)

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        active = {field for field, _ in ast.iter_fields(node) if field != "body"} if self._track_global_stores else set()
        operation = {field for field, _ in ast.iter_fields(node) if field != "body"} if self._track_operation_stores else set()
        self._visit_scoped_fields(node, active, operation)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        active = {field for field, _ in ast.iter_fields(node) if field != "target"} if self._track_global_stores else set()
        operation = {field for field, _ in ast.iter_fields(node)} if self._track_operation_stores else set()
        self._visit_scoped_fields(node, active, operation)

    def _record_object_store(self, node: ast.Subscript | ast.Attribute, *, local: bool) -> None:
        if self._track_operation_stores and isinstance(node.ctx, (ast.Store, ast.Del)):
            digest = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
            occurrence = self._store_occurrences.get(digest, 0)
            self._store_occurrences[digest] = occurrence + 1
            observation = {
                "authority": False, "execution_qualified": False, "caller": self.symbol,
                "kind": ("subscript" if isinstance(node, ast.Subscript) else "attribute") + ("_delete" if isinstance(node.ctx, ast.Del) else "_store"),
                "phase": "operation_eager", "expression_sha256": digest, "occurrence": occurrence,
                "line": node.lineno, "column": node.col_offset,
                "end_line": node.end_lineno, "end_column": node.end_col_offset,
                "disposition": "closed_native_literal_region" if local else "unresolved_object_binding",
            }
            self._source_stores.append(observation)
            if not local:
                self._global_store_effects.append({
                    "kind": "unresolved", "target": "subscript" if isinstance(node, ast.Subscript) else "attribute", "scope": "object_binding",
                    "line": node.lineno, "column": node.col_offset,
                    "source_store_key": digest + ":" + str(occurrence),
                })
    def visit_Subscript(self, node: ast.Subscript) -> None:  # noqa: N802
        local = self._native_region is not None and _native_literal_value(node, self._native_region)
        self._record_object_store(node, local=local)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
        self._record_object_store(node, local=False)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._record_global_binding(node.id, node)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            self._record_global_binding(alias.asname or alias.name.split(".")[0], node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        for alias in node.names:
            self._record_global_binding(alias.asname or alias.name, node)
        self.generic_visit(node)

    def _record_receiver_attribute_target(self, target: ast.AST) -> None:
        if (
            self.receiver is not None
            and isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == self.receiver
        ):
            self.receiver_attribute_mutations.add(target.attr)

    def _resolved_symbol(self, call: ast.Call) -> str:
        if isinstance(call.func, ast.Name):
            binding = self._lexical_bindings.get(call.func.id)
            if binding is not None:
                return str(binding["symbol"])
            origins = self.assignments.get(call.func.id, set())
            targets = {value[len("lexical_function:"):] for value in origins if value.startswith("lexical_function:")}
            if len(targets) == 1 and len(origins) == 1:
                return next(iter(targets))
        return source_symbol(call.func, self.path, self.imports)

    def _origins(self, node: ast.AST) -> set[str]:
        origins: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                origins.update(self.assignments.get(child.id, {f"local:{child.id}"}))
        return origins

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        origins = bound_method_origins(
            node.value,
            class_symbol=self.class_symbol,
            receiver=self.receiver,
            assignments=self.assignments,
        ) or self._origins(node.value)
        for target in node.targets:
            self._record_receiver_attribute_target(target)
            if isinstance(target, ast.Name):
                self.assignments[target.id] = self.assignments.get(target.id, set()) | origins
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        self._record_receiver_attribute_target(node.target)
        if isinstance(node.target, ast.Name) and node.value is not None:
            origins = bound_method_origins(
                node.value,
                class_symbol=self.class_symbol,
                receiver=self.receiver,
                assignments=self.assignments,
            ) or self._origins(node.value)
            self.assignments[node.target.id] = (
                self.assignments.get(node.target.id, set()) | origins
            )
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:  # noqa: N802
        self._record_receiver_attribute_target(node.target)
        self.generic_visit(node)

    def visit_Delete(self, node: ast.Delete) -> None:  # noqa: N802
        for target in node.targets:
            self._record_receiver_attribute_target(target)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:  # noqa: N802
        if node.value is not None:
            self.return_fingerprints.append(
                _normalized_return_fingerprint(node.value, set(self.parameters))
            )
        self.generic_visit(node)

    def _source_call_contract(self, node: ast.AST) -> dict[str, Any]:
        """Observe syntax only; hashes are identities, not secret redaction proofs."""
        def digest(expression: ast.AST) -> str:
            return hashlib.sha256(
                ast.dump(expression, include_attributes=False).encode()
            ).hexdigest()

        expression_sha256 = digest(node)
        occurrence = self.call_occurrences.get(expression_sha256, 0)
        self.call_occurrences[expression_sha256] = occurrence + 1
        arguments: list[dict[str, Any]] = []
        for slot, argument in enumerate(getattr(node, 'args', [])):
            arguments.append({
                "kind": "starred" if isinstance(argument, ast.Starred) else "positional",
                "slot": slot,
                "expression_sha256": digest(argument),
            })
        for slot, keyword in enumerate(getattr(node, 'keywords', [])):
            arguments.append({
                "kind": "keyword" if keyword.arg is not None else "double_starred",
                "slot": keyword.arg if keyword.arg is not None else slot,
                "expression_sha256": digest(keyword.value),
            })
        return {
            "authority": False,
            "expression_sha256": expression_sha256,
            "occurrence": occurrence,
            "arguments": arguments,
        }

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        name = _call_name(node)
        if (
            name in {"delattr", "setattr"}
            and self.receiver is not None
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == self.receiver
        ):
            attribute = node.args[1] if len(node.args) > 1 else None
            self.receiver_attribute_mutations.add(
                attribute.value
                if isinstance(attribute, ast.Constant)
                and isinstance(attribute.value, str)
                else "*"
            )
        symbol = self._resolved_symbol(node)
        fact = {
            "caller": self.symbol,
            "called_symbol": symbol,
            "call_name": name,
            "line": node.lineno,
            "column": node.col_offset,
            "end_line": node.end_lineno,
            "end_column": node.end_col_offset,
            "argument_origins": sorted(self._origins(node)),
        }
        if self.call_contracts:
            fact["call_contract"] = self._source_call_contract(node)
        reference = _call_reference(node.func, self.import_bindings)
        if reference is not None:
            fact["import_reference"] = reference
        dispatch = method_dispatch_reference(
            node.func,
            class_symbol=self.class_symbol,
            method_binding_kind=self.method_binding_kind,
            receiver=self.receiver,
            assignments=self.assignments,
        )
        if dispatch is not None:
            fact["method_dispatch"] = dispatch
        target_origins = sorted(origin for origin in self._origins(node.func) if origin.startswith("parameter:"))
        if target_origins and dispatch is None:
            fact["runtime_target_origins"] = target_origins
        if isinstance(node.func, ast.Name):
            binding = self._lexical_bindings.get(node.func.id)
            origins = self.assignments.get(node.func.id, set())
            targets = {value[len("lexical_function:"):] for value in origins if value.startswith("lexical_function:")}
            if binding is not None or targets:
                fact.pop("import_reference", None)
                if (binding is not None and binding["ambiguous"]) or len(targets) != 1 or len(origins) != 1:
                    fact.update(dispatch_resolution="unresolved", dispatch_port_eligible=False)
                else:
                    fact.update(called_symbol=next(iter(targets)), dispatch_resolution="source_lexical")
        if (isinstance(node.func, ast.Name) and node.func.id in self.assignments
                and not any(value.startswith("lexical_function:") for value in self.assignments[node.func.id])
                and dispatch is None):
            fact.update(dispatch_resolution="unresolved", dispatch_port_eligible=False)
        if not isinstance(node.func, (ast.Name, ast.Attribute)):
            fact.update(dispatch_resolution="unresolved", dispatch_port_eligible=False)
        if reference is not None:
            import_line = reference.get("binding", {}).get("line")
            future_local = (type(import_line) is int and getattr(self._root_function, 'lineno', 0) <= node.lineno < import_line
                            <= (getattr(self._root_function, 'end_lineno', 0) or 0))
            if reference.get("local") in self._ambiguous_imports or future_local:
                fact.pop("import_reference", None)
                fact.update(dispatch_resolution="unresolved", dispatch_port_eligible=False)
        escaped = set().union(*(self._origins(value) for value in [*node.args, *[keyword.value for keyword in node.keywords]]))
        if any(value.startswith("lexical_function:") for value in escaped):
            self._global_store_effects.append({"kind": "unresolved", "target": "lexical_callable_escape",
                                              "scope": "operation_eager", "line": node.lineno, "column": node.col_offset})
        self.calls.append(fact)
        if name in self.local_types or (name[:1].isupper() and name not in PRIMITIVES):
            constructed = (
                f"{self.path}::{name}" if name in self.local_types else symbol
            )
            self.constructors.append({**fact, "constructed_symbol": constructed})
        if isinstance(node.func, ast.Attribute) and name in NORMALIZERS:
            root = _root_name(node.func.value)
            origins = self._origins(node.func.value)
            parameter_origins = sorted(
                origin for origin in origins if origin.startswith("parameter:")
            )
            self.normalizations.append(
                {
                    **fact,
                    "receiver_root": root,
                    "receiver_annotation": self.parameters.get(root or ""),
                    "parameter_origins": parameter_origins,
                }
            )
        if name in DYNAMIC_CALLS:
            self.unresolved.append(
                {
                    "kind": "dynamic_call",
                    "symbol": self.symbol,
                    "called_symbol": symbol,
                    "line": node.lineno,
                }
            )
        self.generic_visit(node)

    def facts(self) -> dict[str, Any]:
        result = {
            "symbol": self.symbol,
            "parameters": self.parameters,
            "return_annotation": self.return_annotation,
            "return_fingerprints": sorted(set(self.return_fingerprints)),
            "calls": self.calls,
            "constructors": self.constructors,
            "normalizations": self.normalizations,
            "unresolved": self.unresolved,
            "class_symbol": self.class_symbol,
            "decorators": self.decorators,
            "receiver_attribute_mutations": sorted(self.receiver_attribute_mutations),
        }
        if self.lexical_parent is not None:
            result["lexical_parent"] = self.lexical_parent
            result["closure_parameters"] = dict(self._closure_parameters)
        if self._owned_scalar_cells:
            result["lexical_scalar_region"] = {
                "authority": False, "execution_qualified": False, "owner": self.symbol,
                "expression_sha256": hashlib.sha256(ast.dump(self._root_function, include_attributes=False).encode()).hexdigest(),
                "cells": self._owned_scalar_cells,
            }
        if self._source_stores:
            result["source_store_observations"] = self._source_stores
        if self._global_store_effects:
            result["effects"] = self._global_store_effects
        return result


class _InitializationVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.sites: list[dict[str, Any]] = []
        self.unresolved: list[dict[str, Any]] = []
        self.occurrences: dict[tuple[str, str], int] = {}

    def site(self, node: ast.AST, kind: str, **fields: Any) -> None:
        digest = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
        key = (kind, digest)
        occurrence = self.occurrences.get(key, 0)
        self.occurrences[key] = occurrence + 1
        self.sites.append(dict(kind=kind, expression_sha256=digest,
                               occurrence=occurrence, line=getattr(node, 'lineno', 0),
                               **fields))

    def unknown(self, node: ast.AST, reason: str) -> None:
        self.unresolved.append(dict(reason=reason, line=getattr(node, 'lineno', 0)))

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        self.site(node, 'call', call_name=_call_name(node))
        self.unknown(node, 'call_execution_and_dispatch')
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        self.site(node, 'import')
        self.unknown(node, 'import_execution')

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        self.visit_Import(node)  # type: ignore[arg-type]

    def decorators(self, nodes: list[ast.expr]) -> None:
        for node in nodes:
            self.visit(node)
            self.site(node, 'decorator_application')
            self.unknown(node, 'implicit_decorator_execution')

    def annotation(self, node: ast.expr | None) -> None:
        if node is not None:
            self.site(node, 'annotation')
            self.unknown(node, 'annotation_evaluation')

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self.decorators(node.decorator_list)
        for value in [*node.args.defaults, *node.args.kw_defaults]:
            if value is not None:
                self.visit(value)
        for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
                    *([node.args.vararg] if node.args.vararg else []),
                    *([node.args.kwarg] if node.args.kwarg else [])]:
            self.annotation(arg.annotation)
        self.annotation(node.returns)
        if getattr(node, 'type_params', []):
            self.unknown(node, 'type_parameter_evaluation')
        # The function body is deferred, including nested definitions and imports.

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self.visit_FunctionDef(node)  # type: ignore[arg-type]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self.decorators(node.decorator_list)
        for value in [*node.bases, *[keyword.value for keyword in node.keywords]]:
            self.visit(value)
        for statement in node.body:
            self.visit(statement)
        self.site(node, 'class_construction')
        self.unknown(node, 'metaclass_and_implicit_class_hooks')
        if getattr(node, 'type_params', []):
            self.unknown(node, 'type_parameter_evaluation')

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        for value in [*node.args.defaults, *node.args.kw_defaults]:
            if value is not None:
                self.visit(value)
        self.unknown(node, 'deferred_expression')

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:  # noqa: N802
        # Only the outermost iterable expression is evaluated at creation.
        self.visit(node.generators[0].iter)
        self.unknown(node, 'deferred_expression')

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        self.visit(node.target)
        if node.value is not None:
            self.visit(node.value)
        self.annotation(node.annotation)


def initialization_facts(tree: ast.Module, *, path: str) -> dict[str, Any]:
    """Retain possible sites; unknown dispatch prevents any completeness claim."""
    visitor = _InitializationVisitor()
    visitor.visit(tree)
    return dict(path=path, authority=False, execution_qualified=False,
                completeness_qualified=False,
                limitations=['implicit_protocol_effects_not_enumerated',
                             'external_native_dynamic_execution_not_resolved'],
                scope='possible_python_initialization_syntax',
                sites=visitor.sites, unresolved=visitor.unresolved)

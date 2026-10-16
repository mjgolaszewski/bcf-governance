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
    ) -> None:
        self.call_contracts = call_contracts
        self.call_occurrences: dict[str, int] = {}
        self.path = path
        self.imports = imports
        self.import_bindings = import_bindings
        self.local_types = local_types
        self.class_symbol = f"{path}::{class_name}" if class_name else None
        self.method_binding_kind, self.receiver = method_binding(function)
        self.decorators = sorted(ast.unparse(value) for value in function.decorator_list)
        suffix = f"{class_name}.{function.name}" if class_name else function.name
        self.symbol = f"{path}::{suffix}"
        arguments = [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        ]
        self.parameters = {
            argument.arg: _annotation(argument.annotation) for argument in arguments
        }
        self.assignments = {
            name: {f"parameter:{name}"} for name in self.parameters
        }
        self.calls: list[dict[str, Any]] = []
        self.constructors: list[dict[str, Any]] = []
        self.normalizations: list[dict[str, Any]] = []
        self.unresolved: list[dict[str, Any]] = []
        self.return_fingerprints: list[str] = []
        self.return_annotation = _annotation(function.returns)
        self.receiver_attribute_mutations: set[str] = set()

    def _record_receiver_attribute_target(self, target: ast.AST) -> None:
        if (
            self.receiver is not None
            and isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == self.receiver
        ):
            self.receiver_attribute_mutations.add(target.attr)

    def _resolved_symbol(self, call: ast.Call) -> str:
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

    def _source_call_contract(self, node: ast.Call) -> dict[str, Any]:
        """Observe syntax only; hashes are identities, not secret redaction proofs."""
        def digest(expression: ast.AST) -> str:
            return hashlib.sha256(
                ast.dump(expression, include_attributes=False).encode()
            ).hexdigest()

        expression_sha256 = digest(node)
        occurrence = self.call_occurrences.get(expression_sha256, 0)
        self.call_occurrences[expression_sha256] = occurrence + 1
        arguments: list[dict[str, Any]] = []
        for slot, argument in enumerate(node.args):
            arguments.append({
                "kind": "starred" if isinstance(argument, ast.Starred) else "positional",
                "slot": slot,
                "expression_sha256": digest(argument),
            })
        for slot, keyword in enumerate(node.keywords):
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
        return {
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

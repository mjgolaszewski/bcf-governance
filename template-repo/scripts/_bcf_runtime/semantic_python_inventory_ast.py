"""Neutral syntax facts for semantic ownership inventory.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""
from __future__ import annotations

import ast
import hashlib
from typing import Any

from . import semantic_python_method_identity as _method_identity
from .semantic_python_method_identity import (
    bound_method_origins,
    method_binding,
    method_dispatch_reference,
    source_symbol,
)

_call_name = _method_identity.call_name
_call_reference = _method_identity.call_reference
_root_name = _method_identity.root_name

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

def _annotation(node: ast.expr | None) -> str:
    if node is None:
        return "untyped"
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return "unresolved"

def _imports(
    tree: ast.Module, module_index: dict[str, str], current_module: str
) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                resolved[local] = f"{module_index.get(alias.name, alias.name)}::module"
        elif isinstance(node, ast.ImportFrom) and node.module:
            import_module = node.module
            if node.level:
                package = current_module.split(".")[:-1]
                retained = len(package) - node.level + 1
                import_module = ".".join(
                    [*package[:retained], *node.module.split(".")]
                )
            module = module_index.get(import_module, import_module)
            for alias in node.names:
                resolved[alias.asname or alias.name] = f"{module}::{alias.name}"
    return resolved

def _import_bindings(
    tree: ast.Module | ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    recursive: bool = False,
) -> list[dict[str, Any]]:
    """Retain neutral import syntax for source-root resolution after discovery."""
    bindings: list[dict[str, Any]] = []
    nodes = ast.walk(tree) if recursive else tree.body
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bindings.append(
                    {
                        "kind": "import",
                        "local": alias.asname or alias.name.split(".", 1)[0],
                        "module": (
                            alias.name
                            if alias.asname is not None
                            else alias.name.split(".", 1)[0]
                        ),
                        "aliased": alias.asname is not None,
                        "line": node.lineno,
                    }
                )
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    continue
                bindings.append(
                    {
                        "kind": "from",
                        "local": alias.asname or alias.name,
                        "module": node.module or "",
                        "member": alias.name,
                        "level": node.level,
                        "line": node.lineno,
                    }
                )
    return bindings

def _router_prefixes(tree: ast.Module) -> dict[str, list[tuple[int, str]]]:
    prefixes: dict[str, list[tuple[int, str]]] = {}
    for member in ast.walk(tree):
        if not isinstance(member, (ast.Assign, ast.AnnAssign)):
            continue
        value = member.value
        if not isinstance(value, ast.Call) or _call_name(value) != "APIRouter":
            continue
        targets = member.targets if isinstance(member, ast.Assign) else [member.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            continue
        prefix = next(
            (
                keyword.value.value
                for keyword in value.keywords
                if keyword.arg == "prefix"
                and isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
            ),
            "",
        )
        prefixes.setdefault(targets[0].id, []).append((member.lineno, prefix))
    return prefixes

def _endpoint_facts(tree: ast.Module, path: str) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    prefixes = _router_prefixes(tree)
    for member in ast.walk(tree):
        if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in member.decorator_list:
            if not isinstance(decorator, ast.Call) or not decorator.args:
                continue
            method = _call_name(decorator).lower()
            route = decorator.args[0]
            if (
                method not in {"delete", "get", "patch", "post", "put"}
                or not isinstance(route, ast.Constant)
                or not isinstance(route.value, str)
            ):
                continue
            response_model = next(
                (
                    ast.unparse(keyword.value)
                    for keyword in decorator.keywords
                    if keyword.arg == "response_model"
                ),
                _annotation(member.returns),
            )
            router_name = _root_name(decorator.func)
            candidates = [
                value
                for value in prefixes.get(router_name or "", [])
                if value[0] < member.lineno
            ]
            prefix = max(candidates, default=(0, ""))[1]
            full_path = route.value
            if prefix and not full_path.startswith(prefix):
                full_path = f"{prefix.rstrip('/')}/{full_path.lstrip('/')}"
            endpoints.append(
                {
                    "path": full_path,
                    "method": method.upper(),
                    "response_model": response_model,
                    "symbol": f"{path}::{member.name}",
                    "line": member.lineno,
                }
            )
    return endpoints

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
    ) -> None:
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
            "argument_origins": sorted(self._origins(node)),
        }
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
                    "column": node.col_offset,
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

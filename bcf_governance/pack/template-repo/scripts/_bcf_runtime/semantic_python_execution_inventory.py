"""Static executable-scope call facts for Python semantic inventory.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""
from __future__ import annotations

import ast
import hashlib
from collections import Counter
from collections.abc import Sequence
from typing import Any

from .semantic_python_method_identity import (
    bound_method_origins,
    method_binding,
    method_dispatch_reference,
    receiver_attribute_targets,
    source_symbol,
)
from .semantic_python_method_identity import call_name as _call_name
from .semantic_python_method_identity import call_reference as _call_reference
from .semantic_python_method_identity import root_name as _root_name

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
        function: ast.FunctionDef | ast.AsyncFunctionDef | None,
        initializer_symbol: str | None = None,
    ) -> None:
        self.path = path
        self.imports = imports
        self.import_bindings = import_bindings
        self.local_types = local_types
        self.class_symbol = f"{path}::{class_name}" if class_name else None
        self.method_binding_kind, self.receiver = method_binding(function) if function else ("static", None)
        self.decorators = sorted(ast.unparse(value) for value in function.decorator_list) if function else []
        suffix = f"{class_name}.{function.name}" if class_name and function else function.name if function else ""
        self.symbol = initializer_symbol or f"{path}::{suffix}"
        arguments = [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        ] if function else []
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
        self.return_annotation = _annotation(function.returns) if function else "untyped"
        self.receiver_attribute_mutations: set[str] = set()

    def _record_receiver_attribute_target(self, target: ast.AST) -> None:
        self.receiver_attribute_mutations.update(
            receiver_attribute_targets(target, self.receiver)
        )

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




class _InitializerVisitor(_FunctionVisitor):
    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        self.unresolved.append({"kind": "unsupported_initializer_lambda",
                                "symbol": self.symbol, "line": node.lineno})


def discover_initializers(
    tree: ast.Module, *, path: str, imports: dict[str, str],
    import_bindings: dict[str, dict[str, Any]], local_types: set[str],
) -> list[dict[str, Any]]:
    """Inventory import-time execution separately from callable bodies.

    Assignment targets identify narrow construction sites. Definition defaults,
    annotations and decorators execute in the enclosing scope, not on invocation.
    No source is imported or evaluated. Unsupported computed dispatch is explicit.
    """
    rows: list[dict[str, Any]] = []
    local_functions = {node.name for node in tree.body
                       if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    builtin_calls = frozenset({"object", "str", "bytes", "int", "float", "bool", "list", "dict",
                               "set", "frozenset", "tuple", "range", "len", "sorted", "enumerate",
                               "zip", "map", "filter", "iter", "next", "min", "max", "sum", "any",
                               "all", "isinstance", "issubclass", "type", "property", "classmethod",
                               "staticmethod", "super", "print", "open", "getattr", "setattr",
                               "hasattr", "globals", "locals", "vars", "repr", "Exception",
                               "ValueError", "RuntimeError", "TypeError", "KeyError", "OSError"})
    deferred_annotations = any(
        isinstance(node, ast.ImportFrom) and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    )

    def record(symbol: str, nodes: Sequence[ast.AST], bindings: dict[str, dict[str, Any]]) -> None:
        visitor = _InitializerVisitor(path=path, imports=imports, import_bindings=bindings,
                                   local_types=local_types, class_name=None, function=None,
                                   initializer_symbol=f"{path}::{symbol}")
        for node in nodes:
            visitor.visit(node)
        row = visitor.facts()
        for call in row["calls"]:
            if call["call_name"] == "<dynamic>":
                row["unresolved"].append({"kind": "unsupported_initializer_dispatch",
                                          "symbol": row["symbol"], "line": call["line"]})
            if (call["called_symbol"] == f"{path}::{call['call_name']}"
                    and not call.get("import_reference")
                    and call["call_name"] not in local_types | local_functions | builtin_calls):
                row["unresolved"].append({"kind": "unsupported_initializer_callee",
                                          "symbol": row["symbol"], "line": call["line"]})
        if row["calls"] or row["unresolved"]:
            rows.append({**row, "scope_kind": "initializer",
                         "line": min(getattr(node, "lineno", 0) for node in nodes),
                         "column": min(getattr(node, "col_offset", 0) for node in nodes)})

    def walk(body: list[ast.stmt], scope: str,
             bindings: dict[str, dict[str, Any]]) -> None:
        local = dict(bindings)
        for node in body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local[alias.asname or alias.name.split(".")[0]] = {
                        "kind": "import", "local": alias.asname or alias.name.split(".")[0],
                        "module": alias.name if alias.asname else alias.name.split(".")[0],
                        "aliased": alias.asname is not None, "line": node.lineno,
                    }
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        rows.append({"symbol": f"{path}::{scope}", "calls": [], "constructors": [],
                                     "normalizations": [], "parameters": {},
                                     "unresolved": [{"kind": "unsupported_initializer_star_import",
                                                     "symbol": f"{path}::{scope}", "line": node.lineno}]})
                    else:
                        local[alias.asname or alias.name] = {
                            "kind": "from", "local": alias.asname or alias.name,
                            "module": node.module or "", "member": alias.name,
                            "level": node.level, "line": node.lineno,
                        }
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                values: list[ast.AST] = [*node.decorator_list, *node.args.defaults,
                                        *(value for value in node.args.kw_defaults if value is not None)]
                if not deferred_annotations:
                    values.extend(argument.annotation for argument in
                                  [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                                  if argument.annotation is not None)
                    if node.returns is not None:
                        values.append(node.returns)
                record(f"{scope}.{node.name}", values, local)
            elif isinstance(node, ast.ClassDef):
                record(f"{scope}.{node.name}", [*node.decorator_list, *node.bases,
                                               *(value.value for value in node.keywords)], local)
                qualified = node.name if scope == "<module>" else scope.removesuffix(".<class>") + "." + node.name
                walk(node.body, f"{qualified}.<class>", local)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = sorted({child.id for target in targets for child in ast.walk(target)
                                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)})
                record(f"{scope}.{','.join(names) or '@' + str(node.lineno)}", [node], local)
                if node.value is not None:
                    reference = _call_reference(node.value, local)
                    for name in names:
                        if reference is not None:
                            local[name] = {"kind": "alias", "source_binding": dict(reference["binding"]),
                                           "source_attributes": reference["attributes"]}
                        elif isinstance(node.value, ast.Name) and node.value.id in local_types:
                            local[name] = {"kind": "local", "symbol": f"{path}::{node.value.id}"}
                        elif name in local or name in local_types:
                            # A rebound import is no longer evidence for the original callee.
                            local[name] = {"kind": "unresolved", "local": name, "line": node.lineno}
            elif isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With,
                                   ast.AsyncWith, ast.Try, ast.TryStar, ast.Match)):
                # Split suites rather than visiting nested definitions as executable bodies.
                expressions: list[ast.expr] = []
                def heads(current: ast.AST, found: list[ast.expr]) -> None:
                    for child in ast.iter_child_nodes(current):
                        if isinstance(child, ast.stmt):
                            continue
                        if isinstance(child, ast.expr):
                            found.append(child)
                        else:
                            heads(child, found)
                heads(node, expressions)
                record(f"{scope}.@{node.lineno}", expressions, local)
                suites: list[list[ast.stmt]] = []
                for _, value in ast.iter_fields(node):
                    if isinstance(value, list) and value and all(isinstance(item, ast.stmt) for item in value):
                        suites.append(value)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, (ast.ExceptHandler, ast.match_case)):
                                suites.append(item.body)
                for suite in suites:
                    walk(suite, scope, local)
            else:
                record(f"{scope}.@{node.lineno}", [node], local)

    walk(tree.body, "<module>", import_bindings)
    counts = Counter(row["symbol"] for row in rows)
    for row in rows:
        previous = row["symbol"]
        if counts[previous] < 2:
            continue
        row["symbol"] = f"{previous}@{row.get('line', 0)}.{row.get('column', 0)}"
        for collection in ("calls", "constructors", "normalizations"):
            for fact in row.get(collection, []):
                fact["caller"] = row["symbol"]
        for fact in row.get("unresolved", []):
            if fact.get("symbol") == previous:
                fact["symbol"] = row["symbol"]
    return rows

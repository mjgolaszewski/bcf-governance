"""Source-first Python inventory for semantic ownership enforcement.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import ast
import hashlib
import subprocess
from pathlib import Path
from typing import Any


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


class SemanticInventoryError(ValueError):
    """Raised when the exact tracked Python population cannot be inventoried."""


def _relative(repo_root: Path, path: Path) -> str:
    return path.resolve().relative_to(repo_root.resolve()).as_posix()


def tracked_python_files(repo_root: Path) -> list[Path]:
    """Return every tracked Python source before any registry is available."""
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.py"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise SemanticInventoryError("tracked Python discovery requires a Git worktree")
    files: list[Path] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            relative = Path(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise SemanticInventoryError("tracked Python path is not UTF-8") from exc
        path = repo_root / relative
        if relative.is_absolute() or ".." in relative.parts:
            raise SemanticInventoryError("tracked Python path escapes the repository")
        if path.is_symlink() or not path.is_file():
            raise SemanticInventoryError(
                f"tracked Python source must be a regular file: {relative.as_posix()}"
            )
        files.append(path)
    if not files:
        raise SemanticInventoryError("tracked Python discovery returned zero files")
    return sorted(files)


def _annotation(node: ast.expr | None) -> str:
    if node is None:
        return "untyped"
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return "unresolved"


def _root_name(node: ast.AST) -> str | None:
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


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return "<dynamic>"


def _imports(tree: ast.Module, module_index: dict[str, str]) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                resolved[local] = f"{module_index.get(alias.name, alias.name)}::module"
        elif isinstance(node, ast.ImportFrom) and node.module:
            module = module_index.get(node.module, node.module)
            for alias in node.names:
                resolved[alias.asname or alias.name] = f"{module}::{alias.name}"
    return resolved


def _module_name(repo_root: Path, path: Path) -> str:
    return _relative(repo_root, path).removesuffix("/__init__.py").removesuffix(
        ".py"
    ).replace("/", ".")


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
        local_types: set[str],
        class_name: str | None,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        self.path = path
        self.imports = imports
        self.local_types = local_types
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

    def _resolved_symbol(self, call: ast.Call) -> str:
        if isinstance(call.func, ast.Name):
            return self.imports.get(call.func.id, f"{self.path}::{call.func.id}")
        if isinstance(call.func, ast.Attribute):
            root = _root_name(call.func)
            imported = self.imports.get(root or "")
            if imported:
                return f"{imported}.{call.func.attr}"
            return f"{self.path}::{ast.unparse(call.func)}"
        return f"{self.path}::<dynamic>"

    def _origins(self, node: ast.AST) -> set[str]:
        origins: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                origins.update(self.assignments.get(child.id, {f"local:{child.id}"}))
        return origins

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        origins = self._origins(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.assignments[target.id] = origins
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.assignments[node.target.id] = self._origins(node.value)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:  # noqa: N802
        if node.value is not None:
            self.return_fingerprints.append(
                _normalized_return_fingerprint(node.value, set(self.parameters))
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        name = _call_name(node)
        symbol = self._resolved_symbol(node)
        fact = {
            "caller": self.symbol,
            "called_symbol": symbol,
            "call_name": name,
            "line": node.lineno,
            "argument_origins": sorted(self._origins(node)),
        }
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
        }


def discover_python_source(
    repo_root: Path, files: list[Path] | None = None
) -> dict[str, Any]:
    """Parse the tracked population without consulting semantic declarations."""
    repo_root = repo_root.resolve()
    paths = files if files is not None else tracked_python_files(repo_root)
    module_index = {_module_name(repo_root, path): _relative(repo_root, path) for path in paths}
    file_rows: list[dict[str, str]] = []
    functions: list[dict[str, Any]] = []
    types: list[str] = []
    for path in paths:
        relative = _relative(repo_root, path)
        raw = path.read_bytes()
        try:
            tree = ast.parse(raw.decode("utf-8"), filename=relative)
        except (UnicodeDecodeError, SyntaxError) as exc:
            raise SemanticInventoryError(
                f"tracked Python source cannot be parsed: {relative}: {exc}"
            ) from exc
        file_rows.append({"path": relative, "sha256": hashlib.sha256(raw).hexdigest()})
        local_types = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
        types.extend(f"{relative}::{name}" for name in sorted(local_types))
        imports = _imports(tree, module_index)
        for node in tree.body:
            members = node.body if isinstance(node, ast.ClassDef) else [node]
            class_name = node.name if isinstance(node, ast.ClassDef) else None
            for member in members:
                if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                visitor = _FunctionVisitor(
                    path=relative,
                    imports=imports,
                    local_types=local_types,
                    class_name=class_name,
                    function=member,
                )
                visitor.visit(member)
                functions.append(visitor.facts())
    return {
        "language": "python",
        "files": file_rows,
        "types": sorted(types),
        "functions": functions,
        "constructors": [
            fact for function in functions for fact in function["constructors"]
        ],
        "normalizations": [
            fact for function in functions for fact in function["normalizations"]
        ],
        "unresolved": [fact for function in functions for fact in function["unresolved"]],
    }

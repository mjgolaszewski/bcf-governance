"""Source-first Python inventory for semantic ownership enforcement.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import subprocess
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from .semantic_python_method_identity import (
    bound_method_origins,
    call_name as _call_name,
    call_reference as _call_reference,
    discover_class_facts,
    method_binding,
    method_dispatch_reference,
    resolve_method_dispatch,
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


def _module_name(repo_root: Path, path: Path) -> str:
    return _relative(repo_root, path).removesuffix("/__init__.py").removesuffix(
        ".py"
    ).replace("/", ".")


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
    endpoints: list[dict[str, Any]] = []
    import_rows: list[dict[str, Any]] = []
    class_rows: list[dict[str, Any]] = []
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
        endpoints.extend(_endpoint_facts(tree, relative))
        imports = _imports(tree, module_index, _module_name(repo_root, path))
        bindings = _import_bindings(tree)
        import_rows.append({"path": relative, "bindings": bindings})
        bindings_by_local = {str(value["local"]): value for value in bindings}
        class_rows.extend(
            discover_class_facts(
                tree,
                path=relative,
                imports=imports,
                import_bindings=bindings_by_local,
            )
        )
        for node in tree.body:
            members = node.body if isinstance(node, ast.ClassDef) else [node]
            class_name = node.name if isinstance(node, ast.ClassDef) else None
            for member in members:
                if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                local_bindings = {
                    str(value["local"]): value
                    for value in _import_bindings(member, recursive=True)
                }
                visitor = _FunctionVisitor(
                    path=relative,
                    imports=imports,
                    import_bindings={**bindings_by_local, **local_bindings},
                    local_types=local_types,
                    class_name=class_name,
                    function=member,
                )
                visitor.visit(member)
                functions.append(visitor.facts())
    return {
        "language": "python",
        "files": file_rows,
        "imports": import_rows,
        "classes": class_rows,
        "types": sorted(types),
        "functions": functions,
        "constructors": [
            fact for function in functions for fact in function["constructors"]
        ],
        "normalizations": [
            fact for function in functions for fact in function["normalizations"]
        ],
        "unresolved": [fact for function in functions for fact in function["unresolved"]],
        "endpoints": sorted(
            endpoints,
            key=lambda value: (value["path"], value["method"], value["symbol"]),
        ),
    }


def _root_contains(root: str, path: str) -> str | None:
    if root == ".":
        return path
    prefix = root + "/"
    return path[len(prefix) :] if path.startswith(prefix) else None


def _validate_import_roots(
    repo_root: Path, inventory: dict[str, Any], import_roots: tuple[str, ...]
) -> tuple[dict[str, str], dict[str, str]]:
    if not import_roots:
        raise SemanticInventoryError("Python import roots must not be empty")
    normalized = tuple(sorted(set(import_roots)))
    if len(normalized) != len(import_roots):
        raise SemanticInventoryError("Python import roots must be unique")
    for index, root in enumerate(normalized):
        relative = PurePosixPath(root)
        if root != relative.as_posix() or relative.is_absolute() or ".." in relative.parts:
            raise SemanticInventoryError(f"unsafe Python import root: {root}")
        for other in normalized[index + 1 :]:
            if root == "." or other.startswith(root + "/"):
                raise SemanticInventoryError(
                    f"Python import roots overlap: {root} and {other}"
                )
        directory = repo_root if root == "." else repo_root / root
        components = [] if root == "." else list(relative.parts)
        cursor = repo_root
        unsafe_link = False
        for component in components:
            cursor /= component
            if cursor.is_symlink():
                unsafe_link = True
                break
        try:
            resolved_directory = directory.resolve(strict=True)
            resolved_directory.relative_to(repo_root)
        except (FileNotFoundError, RuntimeError, ValueError):
            resolved_directory = None
        if unsafe_link or resolved_directory is None or not directory.is_dir():
            raise SemanticInventoryError(
                f"Python import root must be an existing regular directory: {root}"
            )

    module_index: dict[str, str] = {}
    module_by_path: dict[str, str] = {}
    paths = [str(value["path"]) for value in inventory.get("files", [])]
    for root in normalized:
        discovered = 0
        for path in paths:
            suffix = _root_contains(root, path)
            if suffix is None or not suffix.endswith(".py"):
                continue
            parts = list(PurePosixPath(suffix).parts)
            if parts[-1] == "__init__.py":
                parts = parts[:-1]
            else:
                parts[-1] = parts[-1][:-3]
            if not parts or not all(part.isidentifier() for part in parts):
                continue
            discovered += 1
            module = ".".join(parts)
            previous = module_index.get(module)
            if previous is not None and previous != path:
                raise SemanticInventoryError(
                    f"Python import module {module} is ambiguous between {previous} and {path}"
                )
            previous_module = module_by_path.get(path)
            if previous_module is not None and previous_module != module:
                raise SemanticInventoryError(
                    f"Python source {path} has conflicting import identities"
                )
            module_index[module] = path
            module_by_path[path] = module
        if discovered == 0:
            raise SemanticInventoryError(
                f"Python import root contains no discovered importable source: {root}"
            )
    return module_index, module_by_path


def _absolute_module(
    binding: dict[str, Any], current_module: str, *, is_package: bool
) -> str | None:
    module = str(binding.get("module", ""))
    level = int(binding.get("level", 0))
    if not level:
        return module
    package = current_module if is_package else current_module.rpartition(".")[0]
    parts = package.split(".") if package else []
    ascend = level - 1
    if ascend > len(parts):
        return None
    retained = parts[: len(parts) - ascend] if ascend else parts
    return ".".join([*retained, *([module] if module else [])])


def _binding_map(
    inventory: dict[str, Any], admitted_paths: set[str]
) -> dict[str, dict[str, dict[str, Any]]]:
    result: dict[str, dict[str, dict[str, Any]]] = {}
    for row in inventory.get("imports", []):
        path = str(row.get("path", ""))
        if path not in admitted_paths:
            continue
        by_local: dict[str, dict[str, Any]] = {}
        for binding in row.get("bindings", []):
            local = str(binding.get("local", ""))
            previous = by_local.get(local)
            identity = {key: value for key, value in binding.items() if key != "line"}
            previous_identity = (
                {key: value for key, value in previous.items() if key != "line"}
                if previous is not None
                else None
            )
            if previous_identity is not None and previous_identity != identity:
                raise SemanticInventoryError(
                    f"Python import binding {path}::{local} is ambiguous"
                )
            by_local[local] = binding
        result[path] = by_local
    return result


def resolve_python_imports(
    repo_root: Path,
    inventory: dict[str, Any],
    import_roots: tuple[str, ...] = (".",),
) -> dict[str, Any]:
    """Resolve neutral import facts against exact, declared source roots.

    Discovery is completed before this function receives any declaration. The
    roots can qualify discovered identities, but cannot hide source files or
    introduce a suffix/name guess.
    """
    repo_root = repo_root.resolve()
    resolved = copy.deepcopy(inventory)
    module_index, module_by_path = _validate_import_roots(
        repo_root, resolved, import_roots
    )
    bindings_by_path = _binding_map(resolved, set(module_by_path))
    known_symbols = {
        *[str(value) for value in resolved.get("types", [])],
        *[str(value["symbol"]) for value in resolved.get("functions", [])],
    }

    def exported_symbol(
        module: str, members: list[str], seen: frozenset[tuple[str, str]]
    ) -> str | None:
        path = module_index.get(module)
        if path is None or not members:
            return None
        direct = f"{path}::{'.'.join(members)}"
        if direct in known_symbols:
            return direct
        local = members[0]
        marker = (path, local)
        if marker in seen:
            raise SemanticInventoryError(
                f"cyclic Python package export while resolving {module}::{local}"
            )
        binding = bindings_by_path.get(path, {}).get(local)
        if binding is None:
            return None
        target = binding_target(
            path, binding, members[1:], seen | {marker}
        )
        return target

    def module_member(
        module: str,
        parts: list[str],
        seen: frozenset[tuple[str, str]],
    ) -> str | None:
        for retained in range(len(parts), -1, -1):
            candidate = (
                ".".join([module, *parts[:retained]])
                if module
                else ".".join(parts[:retained])
            )
            if candidate not in module_index:
                continue
            remaining = parts[retained:]
            if not remaining:
                return f"{module_index[candidate]}::module"
            exported = exported_symbol(candidate, remaining, seen)
            return exported or f"{module_index[candidate]}::{'.'.join(remaining)}"
        return None

    def binding_target(
        path: str,
        binding: dict[str, Any],
        attributes: list[str],
        seen: frozenset[tuple[str, str]] = frozenset(),
    ) -> str | None:
        current_module = module_by_path.get(path)
        if current_module is None:
            return None
        is_package = path.endswith("/__init__.py") or path == "__init__.py"
        module = _absolute_module(binding, current_module, is_package=is_package)
        if module is None:
            raise SemanticInventoryError(
                f"Python relative import escapes its declared root: {path}"
            )
        if binding["kind"] == "from":
            member = str(binding["member"])
            exported = exported_symbol(module, [member, *attributes], seen)
            if exported is not None:
                return exported
            submodule = ".".join(filter(None, (module, member)))
            if submodule in module_index:
                return module_member(submodule, attributes, seen)
            return module_member(module, [member, *attributes], seen)

        imported = str(binding["module"])
        if bool(binding.get("aliased")):
            return module_member(imported, attributes, seen)
        imported_parts = imported.split(".")
        remainder = imported_parts[1:]
        if attributes[: len(remainder)] == remainder:
            return module_member(imported, attributes[len(remainder) :], seen)
        return module_member(imported_parts[0], attributes, seen)

    for function in resolved.get("functions", []):
        path = str(function["symbol"]).split("::", 1)[0]
        for collection in ("calls", "constructors"):
            for fact in function.get(collection, []):
                reference = fact.get("import_reference")
                if not isinstance(reference, dict):
                    continue
                binding = reference.get("binding")
                if not isinstance(binding, dict):
                    binding = bindings_by_path.get(path, {}).get(
                        str(reference.get("local", ""))
                    )
                attributes = reference.get("attributes", [])
                if binding is None or not isinstance(attributes, list):
                    continue
                target = binding_target(path, binding, [str(value) for value in attributes])
                if target is None:
                    continue
                fact["called_symbol"] = target
                if "constructed_symbol" in fact:
                    fact["constructed_symbol"] = target
    for class_row in resolved.get("classes", []):
        path = str(class_row["symbol"]).split("::", 1)[0]
        for fact in class_row.get("bases", []):
            reference = fact.get("import_reference")
            if not isinstance(reference, dict):
                continue
            binding = reference.get("binding")
            attributes = reference.get("attributes", [])
            if not isinstance(binding, dict) or not isinstance(attributes, list):
                continue
            target = binding_target(path, binding, [str(value) for value in attributes])
            if target is not None:
                fact["called_symbol"] = target
    resolve_method_dispatch(resolved)
    resolved["constructors"] = [
        fact
        for function in resolved.get("functions", [])
        for fact in function.get("constructors", [])
    ]
    return resolved

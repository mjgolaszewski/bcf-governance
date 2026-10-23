"""Python-only declaration and import identities for operation populations."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

def _operation_source_text(repo_root: Path, source: Path, source_subject=None) -> str:
    """Read exact source when bound; this does not authenticate its repository."""
    if source_subject is None:
        return source.read_text(encoding="utf-8")
    from .semantic_source_paths import committed_regular_blob_capture

    _, raw = committed_regular_blob_capture(
        repo_root, path=source.relative_to(repo_root).as_posix(), **source_subject,
    )
    return raw.decode("utf-8")


def _inventory_source_subject(inventory):
    """Retain the source subject separately from the protected policy subject."""
    if "source_population" not in inventory:
        return None
    from .semantic_source_paths import _exact_subject

    population = inventory["source_population"]
    if not isinstance(population, dict) or not isinstance(population.get("subject"), dict):
        raise ValueError("operation source population requires an exact subject")
    subject = dict(population["subject"])
    _exact_subject(subject)
    return subject


def _module_aliases(repo_root: Path, tree: ast.Module, source: Path, *, source_subject=None) -> dict[str, str]:
    source_paths = None
    if source_subject is not None:
        from .semantic_source_paths import committed_python_source_population

        population = committed_python_source_population(repo_root, **source_subject)
        if population["unresolved_entries"]:
            raise ValueError("operation import population contains unresolved source entries")
        source_paths = {row[0] for row in population["python_blobs"]}

    def present(path):
        return path.is_file() if source_paths is None else path.relative_to(repo_root).as_posix() in source_paths

    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                candidate = repo_root / (alias.name.replace(".", "/") + ".py")
                aliases[alias.asname or alias.name.split(".", 1)[0]] = (
                    candidate.relative_to(repo_root).as_posix() if present(candidate) else alias.name
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                candidate = repo_root / node.module.replace(".", "/") / f"{alias.name}.py"
                if present(candidate):
                    aliases[alias.asname or alias.name] = candidate.relative_to(repo_root).as_posix()
                else:
                    aliases[alias.asname or alias.name] = f"{node.module.replace('.', '/')}.py::{alias.name}"
    aliases.setdefault("__module__", source.relative_to(repo_root).as_posix())
    return aliases


def _expression_symbol(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        target = aliases.get(node.id)
        return target if target and "::" in target else f"{aliases['__module__']}::{node.id}"
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        target = aliases.get(node.value.id, aliases["__module__"])
        if "::" in target:
            target = target.split("::", 1)[0]
        return f"{target}::{node.attr}"
    return "<dynamic>"


def _function_for_entrypoint(
    repo_root: Path, symbol: str, functions: dict[str, dict[str, Any]], *, source_subject=None,
) -> dict[str, Any] | None:
    direct = functions.get(symbol)
    if direct is not None:
        return direct
    raw_path, separator, name = symbol.partition("::")
    if not separator:
        return None
    path = repo_root / raw_path
    if path.suffix != ".py" or (source_subject is None and (not path.is_file() or path.is_symlink())):
        return None
    try:
        tree = ast.parse(_operation_source_text(repo_root, path, source_subject), filename=raw_path)
    except (OSError, UnicodeError, SyntaxError, ValueError):
        return None

    def shadows(node):
        if isinstance(node, ast.Name):
            return node.id == name and isinstance(node.ctx, (ast.Store, ast.Del))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return node.name == name
        if isinstance(node, ast.Lambda):
            return False
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            return any((alias.asname or alias.name.split(".", 1)[0]) == name for alias in node.names)
        return any(shadows(child) for child in ast.iter_child_nodes(node))

    targets = set()
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom) or node.module is None:
            if shadows(node):
                return None
            continue
        for alias in node.names:
            if (alias.asname or alias.name) != name:
                continue
            module = node.module
            if node.level:
                package = raw_path.removesuffix(".py").split("/")[:-1]
                package = package[: len(package) - node.level + 1]
                resolved = "/".join([*package, *module.split(".")]) + ".py"
            else:
                resolved = module.replace(".", "/") + ".py"
            targets.add(f"{resolved}::{alias.name}")
    return functions.get(next(iter(targets))) if len(targets) == 1 else None

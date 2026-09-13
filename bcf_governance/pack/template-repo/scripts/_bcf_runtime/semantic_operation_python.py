"""Python-only declaration and import identities for operation populations."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

def _module_aliases(repo_root: Path, tree: ast.Module, source: Path) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                candidate = repo_root / (alias.name.replace(".", "/") + ".py")
                aliases[alias.asname or alias.name.split(".", 1)[0]] = (
                    candidate.relative_to(repo_root).as_posix() if candidate.is_file() else alias.name
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                candidate = repo_root / node.module.replace(".", "/") / f"{alias.name}.py"
                if candidate.is_file():
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
    repo_root: Path, symbol: str, functions: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    direct = functions.get(symbol)
    if direct is not None:
        return direct
    raw_path, separator, name = symbol.partition("::")
    if not separator:
        return None
    path = repo_root / raw_path
    if path.suffix != ".py" or not path.is_file() or path.is_symlink():
        return None
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=raw_path)
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom) or node.module is None:
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
            return functions.get(f"{resolved}::{alias.name}")
    return None

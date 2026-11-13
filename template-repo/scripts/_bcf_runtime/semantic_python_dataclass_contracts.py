"""Source-bound default-factory obligations for standard dataclasses.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""
from __future__ import annotations

import ast


def dataclass_default_factories(
    node: ast.ClassDef, tree: ast.Module, path: str, imports: dict[str, str],
) -> dict[str, str] | None:
    """Accept only literal field options and stable, local function callbacks.

    The returned identities must still be traversed by effect validation.
    This contract grants neither purity nor returned-instance alias freedom.
    """
    result: dict[str, str] = {}
    for member in node.body:
        if not isinstance(member, ast.AnnAssign) or not isinstance(member.value, ast.Call):
            continue
        value = member.value
        if isinstance(value.func, ast.Name):
            identity = imports.get(value.func.id)
        elif isinstance(value.func, ast.Attribute) and isinstance(value.func.value, ast.Name):
            identity = imports.get(value.func.value.id, "") + "." + value.func.attr
        else:
            return None
        if identity not in {"dataclasses::field", "dataclasses::module.field"} or value.args:
            return None
        if not isinstance(member.target, ast.Name):
            return None
        for keyword in value.keywords:
            if keyword.arg == "default_factory":
                if not isinstance(keyword.value, ast.Name):
                    return None
                name = keyword.value.id
                definitions = [candidate for candidate in tree.body
                               if isinstance(candidate, ast.FunctionDef) and candidate.name == name]
                if len(definitions) != 1 or definitions[0].decorator_list or definitions[0].lineno >= node.lineno:
                    return None
                for candidate in ast.walk(tree):
                    if isinstance(candidate, ast.Name) and candidate.id == name and isinstance(candidate.ctx, (ast.Store, ast.Del)):
                        return None
                    if isinstance(candidate, (ast.ClassDef, ast.AsyncFunctionDef)) and candidate.name == name:
                        return None
                    if isinstance(candidate, ast.FunctionDef) and candidate.name == name and candidate is not definitions[0]:
                        return None
                    if isinstance(candidate, ast.Attribute) and isinstance(candidate.value, ast.Name) and candidate.value.id == name:
                        return None
                    if isinstance(candidate, ast.Call) and isinstance(candidate.func, ast.Name) and candidate.func.id in {"setattr", "delattr"} and candidate.args and isinstance(candidate.args[0], ast.Name) and candidate.args[0].id == name:
                        return None
                result[member.target.id] = f"{path}::{name}"
            elif keyword.arg in {"init", "repr", "compare", "hash", "kw_only"}:
                if not isinstance(keyword.value, ast.Constant) or keyword.value.value not in (True, False, None):
                    return None
            elif keyword.arg == "default":
                if not isinstance(keyword.value, ast.Constant):
                    return None
            else:
                return None
        if {keyword.arg for keyword in value.keywords} >= {"default", "default_factory"}:
            return None
    return result

"""Source-bound default-factory obligations for standard dataclasses.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""
from __future__ import annotations

import ast
import sys


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


def generated_record_fields(node: ast.ClassDef, tree: ast.Module,
                            imports: dict[str, str]) -> list[dict[str, object]] | None:
    """Describe generated init storage, without using field types as value facts.

    This bounded slice excludes inheritance, factories, post-init and custom
    initializers. Annotation identity is examined only to distinguish ordinary
    fields from ClassVar/InitVar; it never grants purity or a scalar value kind.
    """
    if sys.implementation.name != 'cpython' or not (3, 11) <= sys.version_info[:2] <= (3, 14):
        return None
    if node.bases or node.keywords:
        return None
    if any(not isinstance(member, (ast.AnnAssign, ast.Assign, ast.FunctionDef, ast.AsyncFunctionDef, ast.Pass))
           and not (isinstance(member, ast.Expr) and isinstance(member.value, ast.Constant)
                    and isinstance(member.value.value, str)) for member in node.body):
        return None
    if any(isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
           and member.name in {'__init__', '__post_init__'} for member in node.body):
        return None
    options: dict[str, bool] = {}
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call):
            for keyword in decorator.keywords:
                if keyword.arg is None or not isinstance(keyword.value, ast.Constant) or type(keyword.value.value) is not bool:
                    return None
                options[keyword.arg] = keyword.value.value
    if options.get('init') is False:
        return None
    if any(isinstance(part, ast.Name) and part.id in {
        'globals', 'locals', 'vars', 'exec', 'eval', 'setattr', 'delattr', '__import__', '__builtins__', '__build_class__'
    } or isinstance(part, ast.ImportFrom) and (part.module == 'builtins' or any(alias.name == '*' for alias in part.names))
       or isinstance(part, ast.Import) and any(alias.name == 'builtins' for alias in part.names)
       for part in ast.walk(tree)):
        return None
    rebound = {part.id for part in ast.walk(tree) if isinstance(part, ast.Name)
               and isinstance(part.ctx, (ast.Store, ast.Del))}
    decorated_functions = {part.name for part in ast.walk(tree)
                           if isinstance(part, (ast.FunctionDef, ast.AsyncFunctionDef)) and part.decorator_list}
    own_classes = {member.name: member for member in tree.body if isinstance(member, ast.ClassDef)}
    fields = []
    for member in node.body:
        if not isinstance(member, ast.AnnAssign) or not isinstance(member.target, ast.Name):
            continue
        annotation = member.annotation
        if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
            try:
                annotation = ast.parse(annotation.value, mode='eval').body
            except SyntaxError:
                return None
        # Unknown annotation aliases could denote ClassVar/InitVar and change
        # positional binding. Fail closed instead of guessing a signature.
        for part in ast.walk(annotation):
            if isinstance(part, ast.Name):
                if part.id in rebound:
                    return None
                identity = imports.get(part.id)
                if identity is not None:
                    return None
                if part.id in decorated_functions:
                    return None
                declaration = own_classes.get(part.id)
                if declaration is None:
                    # With no source binding this is a builtin or an unresolved
                    # forward name, neither a ClassVar/InitVar module alias.
                    continue
                if declaration.decorator_list or declaration.keywords:
                    return None
                if any(not isinstance(base, ast.Name) or imports.get(base.id) not in {
                    'enum::Enum', 'enum::StrEnum', 'enum::IntEnum', 'enum::IntFlag', 'enum::Flag'
                } for base in declaration.bases):
                    return None
            elif not isinstance(part, (ast.BinOp, ast.BitOr, ast.Subscript, ast.Tuple, ast.Load, ast.Constant)):
                return None
        if member.value is not None and not isinstance(member.value, ast.Constant):
            return None
        fields.append({'name': member.target.id, 'kw_only': options.get('kw_only', False),
                       'has_default': member.value is not None,
                       'default_scalar': isinstance(member.value, ast.Constant)})
    return fields

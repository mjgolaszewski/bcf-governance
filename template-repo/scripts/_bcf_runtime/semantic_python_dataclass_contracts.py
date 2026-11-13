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
                    if identity.startswith('typing::') and identity not in {'typing::ClassVar', 'typing::module.ClassVar'}:
                        continue
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


def discover_generated_copies(inventory: dict[str, object]) -> None:
    """Inventory possible generated allocations, never annotation-based purity.

    A nominal target is a candidate for ownership checking. Runtime invocation
    and constructor effects still require an independently qualified frame.
    """
    from typing import Any, cast
    classes = {str(row['symbol']): row for row in cast(list[dict[str, Any]], inventory.get('classes', []))}
    functions = {str(row['symbol']): row for row in cast(list[dict[str, Any]], inventory.get('functions', []))}
    library_rebound = any(str(mutation.get('called_symbol', '')) in {
        'dataclasses::module', 'dataclasses::replace', 'dataclasses::module.replace'
    } and mutation.get('escaped_member') in {None, '*', 'replace'}
        for mutation in cast(list[dict[str, Any]], inventory.get('class_binding_mutations', [])))
    for row in functions.values():
        source = row.get('python_value_source')
        if not source:
            continue
        function = ast.parse(source).body[0]
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        nodes = list(ast.walk(function))
        sites = row.get('python_value_sites', [])
        if len(nodes) != len(sites):
            continue
        positions = {id(node): tuple(site) for node, site in zip(nodes, sites, strict=True)}
        calls = { (call.get('line'), call.get('column')): call
                  for call in row.get('calls', []) if not call.get('implicit_callback') }
        bindings = {name: set(symbols) for name, symbols in row.get('parameter_annotation_symbols', {}).items()}

        def subjects(value: ast.AST | None, bindings: dict[str, set[str]] = bindings,
                     calls: dict[tuple[Any, ...], dict[str, Any]] = calls,
                     positions: dict[int, tuple[Any, ...]] = positions) -> set[str]:
            if isinstance(value, ast.Name):
                return set(bindings.get(value.id, set()))
            if isinstance(value, ast.Call):
                target = calls.get(positions[id(value)], {}).get('called_symbol')
                if target in classes:
                    return {str(target)}
                if target in {'dataclasses::replace', 'dataclasses::module.replace'} and value.args:
                    return subjects(value.args[0])
                return set(functions.get(str(target), {}).get('return_annotation_symbols', []))
            return set()

        for statement in function.body:
            # Direct local bindings enrich only the neutral candidate inventory.
            # Reassignment or unsupported control flow confers no effect facts.
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        bindings[target.id] = subjects(statement.value)
            for node in ast.walk(statement):
                if not isinstance(node, ast.Call):
                    continue
                call = calls.get(positions[id(node)])
                if not call or call.get('called_symbol') not in {'dataclasses::replace', 'dataclasses::module.replace'} or not node.args:
                    continue
                candidates = sorted(subject for subject in subjects(node.args[0])
                                    if classes.get(subject, {}).get('standard_dataclass_declaration'))
                if not candidates:
                    continue
                call['generated_copy_candidates'] = candidates
                call['generated_copy_profiles'] = {
                    subject: {'subject': subject, 'fields': classes[subject]['generated_record_fields']}
                    for subject in candidates
                    if not library_rebound and classes[subject].get('closed_class_binding') and classes[subject].get('generated_record_fields') is not None
                    and not any(method['name'] in {'__class__', '__dataclass_fields__', '__replace__'}
                                for method in classes[subject].get('methods', []))}
                call['generated_copy_fields'] = [keyword.arg for keyword in node.keywords]
                for subject in candidates:
                    row.setdefault('constructors', []).append({**call, 'constructed_symbol': subject,
                        'construction_kind': 'generated_copy_candidate',
                        'binding_source': 'nominal_source_candidate_not_runtime_proof'})

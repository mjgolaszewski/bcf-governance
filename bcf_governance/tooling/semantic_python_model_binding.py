"""Bounded Pydantic classmethod selection; model effects remain obligations.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import sys
import tomllib
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet

_BUILTINS = {"str", "int", "float", "bool", "bytes", "list", "dict", "tuple", "set", "frozenset", "object"}
_HOOKS = {"__get_pydantic_core_schema__", "__get_pydantic_json_schema__", "__pydantic_init_subclass__", "__pydantic_on_complete__", "__init_subclass__", "__class_getitem__"}
_ROOTS = {"pydantic::BaseModel", "pydantic::module.BaseModel", "pydantic.main::BaseModel"}


def literal_type_aliases(tree: ast.Module, path: str, imports: dict[str, str]) -> list[str]:
    """Retain closed PEP 695 literal aliases without evaluating arbitrary aliases."""
    result = []
    for node in tree.body:
        if not isinstance(node, ast.TypeAlias) or not isinstance(node.name, ast.Name) or node.type_params:
            continue
        value = node.value
        if not isinstance(value, ast.Subscript) or _identity(value.value, imports).replace("::module.", "::") != "typing::Literal":
            continue
        values = value.slice.elts if isinstance(value.slice, ast.Tuple) else [value.slice]
        if not all(isinstance(item, ast.Constant) for item in values):
            continue
        if any(isinstance(item, ast.Name) and item is not node.name and item.id == node.name.id
               and isinstance(item.ctx, (ast.Store, ast.Del)) for item in ast.walk(tree)):
            continue
        result.append(f"{path}::{node.name.id}")
    return result


def _identity(node: ast.AST, imports: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return imports.get(node.id, "")
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return imports.get(node.value.id, "") + "." + node.attr
    return ""


def model_default_shape(value: ast.AST, imports: dict[str, str]) -> bool:
    """Recognize declaration syntax, never certify its constructor effects."""
    if not isinstance(value, ast.Call):
        return False
    identity = _identity(value.func, imports)
    field = identity in {"pydantic::Field", "pydantic::module.Field"}
    if not field and identity not in {"pydantic::ConfigDict", "pydantic::module.ConfigDict"}:
        return False
    if not field and value.args:
        return False
    literal = (ast.Constant, ast.Tuple, ast.List, ast.Dict, ast.Set, ast.Load, ast.UnaryOp, ast.UAdd, ast.USub)
    if any(not all(isinstance(part, literal) for part in ast.walk(argument)) for argument in value.args):
        return False
    for keyword in value.keywords:
        if keyword.arg is None:
            return False
        if field and keyword.arg == "default_factory" and isinstance(keyword.value, ast.Name):
            continue
        if not all(isinstance(part, literal) for part in ast.walk(keyword.value)):
            return False
    return True


def model_declaration_shape(node: ast.ClassDef, imports: dict[str, str], tree: ast.Module) -> bool:
    """Exclude class-creation hooks and executable or opaque schema metadata."""
    names = {member.name for member in node.body if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))}
    if names & _HOOKS or node.keywords or node.decorator_list:
        return False
    for member in node.body:
        if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in member.decorator_list:
                if isinstance(decorator, ast.Name) and decorator.id in {"classmethod", "staticmethod", "property"}:
                    continue
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                identity = _identity(target, imports).replace("::module.", "::")
                if identity not in {"pydantic::field_validator", "pydantic::model_validator", "pydantic::field_serializer", "pydantic::model_serializer"}:
                    return False
                if isinstance(decorator, ast.Call) and any(
                    not isinstance(value, ast.Constant) for value in
                    [*decorator.args, *(keyword.value for keyword in decorator.keywords)]
                ):
                    return False
            continue
        if isinstance(member, ast.Expr) and isinstance(member.value, ast.Constant) and isinstance(member.value.value, str):
            continue
        if isinstance(member, ast.Pass):
            continue
        if not isinstance(member, (ast.Assign, ast.AnnAssign)):
            return False
        targets = member.targets if isinstance(member, ast.Assign) else [member.target]
        if any(not isinstance(target, ast.Name) or target.id.startswith("__") or target.id in names for target in targets):
            return False
        if isinstance(member, ast.Assign) and any(target.id != "model_config" for target in targets if isinstance(target, ast.Name)):
            return False
        if member.value is not None and isinstance(member.value, ast.Call) and not model_default_shape(member.value, imports):
            return False
        if isinstance(member.value, ast.Call):
            for keyword in member.value.keywords:
                if keyword.arg == "default_factory" and isinstance(keyword.value, ast.Name):
                    name = keyword.value.id
                    definitions = [value for value in tree.body if isinstance(value, ast.FunctionDef) and value.name == name and not value.decorator_list]
                    if name not in {"list", "dict", "tuple", "set"} and len(definitions) != 1:
                        return False
                    if any(isinstance(value, ast.Name) and value.id == name and isinstance(value.ctx, (ast.Store, ast.Del))
                           or isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name) and value.value.id == name
                           for value in ast.walk(tree)):
                        return False
        if isinstance(member, ast.AnnAssign):
            if any(isinstance(part, (ast.Call, ast.Lambda)) for part in ast.walk(member.annotation)):
                return False
            if isinstance(member.annotation, ast.Constant):
                return False
            parents = {id(child): parent for parent in ast.walk(member.annotation) for child in ast.iter_child_nodes(parent)}
            for value in ast.walk(member.annotation):
                if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                    continue
                parent = parents.get(id(value))
                if isinstance(parent, ast.Tuple):
                    parent = parents.get(id(parent))
                if not isinstance(parent, ast.Subscript) or _identity(parent.value, imports).replace("::module.", "::") != "typing::Literal":
                    return False
    return True


def literal_enum_shape(node: ast.ClassDef, imports: dict[str, str]) -> bool:
    """Only closed, literal enum declarations can be schema leaves here."""
    if node.keywords or node.decorator_list or not any(
        _identity(base, imports) in {"enum::Enum", "enum::module.Enum", "enum::StrEnum"}
        for base in node.bases
    ):
        return False
    for member in node.body:
        if isinstance(member, ast.Expr) and isinstance(member.value, ast.Constant) and isinstance(member.value.value, str):
            continue
        if not isinstance(member, ast.Assign) or not isinstance(member.value, ast.Constant):
            return False
        if any(not isinstance(target, ast.Name) or target.id.startswith("_") for target in member.targets):
            return False
    return True


def runtime_model_binding(root: Path) -> dict[str, Any] | None:
    """Observe dependency mechanics in a declared product dependency universe.

    This is deliberately not a parser, invocation, alias or effect capability.
    No project modules are imported and no dependency is installed or fetched.
    """
    try:
        project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
        requirements = [Requirement(value) for value in project["dependencies"]]
        selected = [value for value in requirements if value.marker is None or value.marker.evaluate({"extra": ""})]
        if not any(value.name.lower().replace("_", "-") == "pydantic" for value in selected):
            return None
        if not SpecifierSet(project["requires-python"]).contains(".".join(map(str, sys.version_info[:3]))):
            return None
        for requirement in selected:
            if requirement.url or not requirement.specifier.contains(importlib.metadata.version(requirement.name)):
                return None
        distribution = importlib.metadata.distribution("pydantic")
        if distribution.version != "2.13.4" or importlib.metadata.version("pydantic-core") != "2.46.4":
            return None
        if importlib.metadata.entry_points(group="pydantic"):
            return None
        expected = Path(str(distribution.locate_file("pydantic/__init__.py"))).resolve(strict=True)
        spec = importlib.util.find_spec("pydantic")
        if spec is None or spec.origin is None or Path(spec.origin).resolve(strict=True) != expected:
            return None
        from pydantic import BaseModel, Field

        meta: Any = type(BaseModel)
        if meta.__getattribute__ is not type.__getattribute__ or meta.__call__ is not type.__call__:
            return None
        events: list[str] = []

        def factory() -> int:
            events.append("factory")
            return 7

        def make(cls: Any) -> Any:
            return cls()

        probe = meta("BCFClassmethodBindingProbe", (BaseModel,), {
            "__module__": __name__, "__annotations__": {"value": int},
            "value": Field(default_factory=factory), "make": classmethod(make),
        })
        if events or type(probe.__dict__["make"]) is not classmethod or probe.__dict__["make"].__func__ is not make:
            return None
        instance = probe.make()
        if type(instance) is not probe or events != ["factory"]:
            return None
        files = [expected, expected.parent / "main.py", expected.parent / "_internal/_model_construction.py"]
        return {"contract": "pydantic-2.13.4-source-classmethod-selection.v1",
                "version": distribution.version, "core_version": "2.46.4",
                "source_sha256": {path.relative_to(expected.parent).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in files},
                "declaration_sha256": hashlib.sha256((root / "pyproject.toml").read_bytes()).hexdigest(),
                "execution_qualified": False, "effects_qualified": False}
    except (OSError, ValueError, KeyError, TypeError, ImportError, InvalidRequirement, InvalidSpecifier):
        return None


def qualify_model_bindings(root: Path, inventory: dict[str, Any]) -> None:
    """Qualify only a closed schema ancestry under observed library mechanics."""
    classes = {str(row["symbol"]): row for row in inventory.get("classes", [])}
    if not any(base.get("called_symbol") in _ROOTS for row in classes.values() for base in row.get("bases", [])):
        return
    binding = runtime_model_binding(root)
    if binding is None:
        return
    mutations = inventory.get("class_binding_mutations", [])
    invalid = {str(row.get("called_symbol", "")) for row in mutations
               if row.get("escaped_member") is None or row.get("escaped_member") == "*"}
    accepted: set[str] = set()
    aliases = set(inventory.get("literal_type_aliases", []))
    pending: set[str] = set()

    def valid(symbol: str) -> bool:
        if symbol in aliases and symbol not in invalid:
            return True
        if symbol in accepted:
            return True
        if symbol in pending or symbol in invalid:
            return False
        row = classes.get(symbol, {})
        if row.get("literal_enum_shape"):
            return True
        if not row.get("model_local_binding"):
            return False
        bases = row.get("bases", [])
        if len(bases) != 1:
            return False
        pending.add(symbol)
        base = str(bases[0]["called_symbol"])
        if base not in _ROOTS and not valid(base):
            pending.remove(symbol)
            return False
        for reference in row.get("model_schema_references", []):
            target = str(reference["called_symbol"])
            target = target.replace("::module.", "::")
            if target.startswith("builtin:") and target[8:] in _BUILTINS:
                continue
            if target in {"typing::Any", "typing::Literal", "typing::Optional", "typing::Union", "datetime::datetime", "datetime::date"}:
                continue
            if not valid(target):
                pending.remove(symbol)
                return False
        pending.remove(symbol)
        accepted.add(symbol)
        return True

    for symbol, row in classes.items():
        if valid(symbol) and not row.get("literal_enum_shape"):
            row["closed_class_binding"] = True
            row["local_class_binding"] = True
            row["library_model_binding"] = json.loads(json.dumps(binding))
            callbacks: list[dict[str, Any]] = []
            current = symbol
            visited = set()
            while current in classes and current not in visited:
                visited.add(current)
                parent = classes[current]
                callbacks.extend({"declaring_class": current, "symbol": method["symbol"],
                                  "decorators": method.get("decorators", [])}
                    for method in parent.get("methods", [])
                    if method["name"] == "model_post_init" or
                    set(method.get("decorators", [])) - {"classmethod", "staticmethod"})
                bases = parent.get("bases", [])
                current = str(bases[0]["called_symbol"]) if len(bases) == 1 else ""
            row["model_effect_obligations"] = {"declared_callbacks": callbacks,
                "effective_configuration": "unqualified", "input_binding": "unqualified",
                "returned_aliases": "unqualified"}

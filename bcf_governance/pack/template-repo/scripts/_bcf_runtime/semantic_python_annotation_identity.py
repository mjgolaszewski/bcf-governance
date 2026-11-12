"""Resolve Python annotation references to exact semantic identities."""

from __future__ import annotations

import ast
from collections.abc import Callable, Mapping
from typing import Any

BindingTarget = Callable[[Mapping[str, Any], list[str]], str | None]


def external_import_identity(
    path: str,
    binding: Mapping[str, Any],
    attributes: list[str],
    *,
    module_by_path: Mapping[str, str],
    absolute_module: Callable[[Mapping[str, Any], str, bool], str | None],
    error: Callable[[str], Exception],
) -> str | None:
    """Represent an imported non-project annotation without project authority."""
    current_module = module_by_path.get(path)
    if current_module is None:
        return None
    module = absolute_module(
        binding, current_module, path.endswith("/__init__.py") or path == "__init__.py"
    )
    if module is None:
        raise error(f"Python relative import escapes its declared root: {path}")
    if binding["kind"] == "from":
        members = [str(binding["member"]), *attributes]
        return f"external:{module}::{'.'.join(members)}"
    imported = str(binding["module"])
    if bool(binding.get("aliased")):
        members = attributes
    else:
        remainder = imported.split(".")[1:]
        members = (
            attributes[len(remainder) :]
            if attributes[: len(remainder)] == remainder
            else attributes
        )
    return f"external:{imported}::{'.'.join(members) or 'module'}"


def resolve_annotation_identities(
    annotation: object,
    *,
    local_symbol: Callable[[str, list[str]], str | None],
    binding_for: Callable[[str], Mapping[str, Any] | None],
    binding_target: BindingTarget,
    external_binding_target: BindingTarget,
) -> list[str]:
    """Return qualified project/external identities named by one annotation."""
    if not isinstance(annotation, str) or annotation in {"untyped", "unresolved"}:
        return []
    try:
        expression = ast.parse(annotation, mode="eval").body
    except SyntaxError:
        return []
    identities: set[str] = set()

    def reference(node: ast.AST) -> tuple[str, list[str]] | None:
        attributes: list[str] = []
        cursor = node
        while isinstance(cursor, ast.Attribute):
            attributes.append(cursor.attr)
            cursor = cursor.value
        if not isinstance(cursor, ast.Name):
            return None
        return cursor.id, list(reversed(attributes))

    class AnnotationVisitor(ast.NodeVisitor):
        def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
            self._record(node)

        def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
            self._record(node)

        def visit_Constant(self, node: ast.Constant) -> None:  # noqa: N802
            if isinstance(node.value, str):
                identities.update(
                    resolve_annotation_identities(
                        node.value,
                        local_symbol=local_symbol,
                        binding_for=binding_for,
                        binding_target=binding_target,
                        external_binding_target=external_binding_target,
                    )
                )

        def _record(self, node: ast.AST) -> None:
            parsed = reference(node)
            if parsed is None:
                return
            local, attributes = parsed
            binding = binding_for(local)
            if binding is not None:
                target = binding_target(binding, attributes)
                external = external_binding_target(binding, attributes)
                if target or external:
                    identities.add(target or external or "")
                return
            target = local_symbol(local, attributes)
            if target is not None:
                identities.add(target)

    AnnotationVisitor().visit(expression)
    identities.discard("")
    return sorted(identities)


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


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

"""Source entrypoint import discovery."""

from __future__ import annotations

import ast


def _module_time_bcf_imports(tree: ast.Module) -> list[ast.Import | ast.ImportFrom]:
    """Return package imports that execute while a source entrypoint starts."""

    imports: list[ast.Import | ast.ImportFrom] = []

    def visit(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return
        if isinstance(node, ast.Import):
            if any(alias.name == "bcf_governance" or alias.name.startswith("bcf_governance.") for alias in node.names):
                imports.append(node)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "bcf_governance" or (node.module or "").startswith("bcf_governance."):
                imports.append(node)
        for child in ast.iter_child_nodes(node):
            visit(child)

    for statement in tree.body:
        visit(statement)
    return imports


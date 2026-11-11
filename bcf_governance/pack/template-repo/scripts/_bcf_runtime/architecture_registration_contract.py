"""Reuse the maintained frozen-registration owner for transport delegation facts.

This derives identities from exact source, not authored operation labels. It
confers no mutation/read port exemption and does not certify an operation registry.
Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

import ast
import hashlib
from collections.abc import Mapping
from pathlib import Path

from .semantic_operation_registrations import TypedRegistrationError, discover_typed_registrations
from .semantic_ownership_inventory import discover_python_source


def registration_factories(
    root: Path | None, sources: Mapping[str, ast.Module],
) -> tuple[dict[str, set[str]], list[tuple[str, int, str]]]:
    """Admit only source tables proven by the existing closed native profile."""
    candidates: list[tuple[str, str, int]] = []
    for path, tree in sources.items():
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if (len(targets) != 1 or not isinstance(targets[0], ast.Name)
                    or not isinstance(value, (ast.Tuple, ast.List)) or not value.elts):
                continue
            if all(isinstance(item, ast.Call) and any(
                keyword.arg in {"query_factory", "command_factory"} for keyword in item.keywords
            ) for item in value.elts):
                candidates.append((path, targets[0].id, node.lineno))
    if not candidates:
        return {}, []
    if root is None:
        return {}, []
    inventory = discover_python_source(root, [root / path for path in sorted(sources)])
    for row in inventory["files"]:
        raw = (root / row["path"]).read_bytes()
        if (hashlib.sha256(raw).hexdigest() != row["sha256"]
                or ast.dump(ast.parse(raw), include_attributes=True)
                != ast.dump(sources[row["path"]], include_attributes=True)):
            raise ValueError("native registration source differs from supplied AST population")
    bindings: dict[str, set[str]] = {}
    failures: list[tuple[str, int, str]] = []
    for path, table, _line in candidates:
        try:
            _, bound = discover_typed_registrations(root, {"source": path, "symbol": table}, inventory)
        except TypedRegistrationError:
            # A shape resemblance grants nothing. Existing mandatory registration
            # validation owns opt-in profile diagnostics; this gate needs proof.
            continue
        for fact in bound:
            binding = fact["registration_binding"]
            bindings.setdefault(binding["lexical_handler"], set()).add(binding["factory"])
    return bindings, failures

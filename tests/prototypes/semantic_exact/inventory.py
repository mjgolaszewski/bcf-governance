"""Immutable source inputs for a prototype using the existing shared inventory.

No function/call graph or acceptance result is fabricated. The optional neutral
metadata integration draft is retained beside this development-only adapter.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import Any

from bcf_governance.tooling.semantic_python_effect_obligations import (
    container_builtin_names,
    python_binding_names,
)


def native_builtin_names(tree: ast.Module) -> list[str]:
    existing = container_builtin_names(tree)
    if not existing:
        return []
    nodes = tuple(ast.walk(tree))
    bound = python_binding_names(nodes)
    bound.update(node.asname or node.name.split('.')[0] for node in nodes if isinstance(node, ast.alias))
    return sorted(set(existing) | ({'any', 'all', 'ord', 'frozenset', 'object'} - bound))


def module_inputs(inventory: dict[str, Any], root: Path) -> dict[str, Any]:
    modules = []
    builtins = {}
    for row in inventory['files']:
        raw = (root / row['path']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == row['sha256']
        tree = ast.parse(raw.decode())
        modules.append({'path': row['path'], 'source': ast.unparse(tree),
                        'shape_sha256': hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest()})
        builtins[row['path']] = native_builtin_names(tree)
    result = {**inventory, 'python_modules': modules, 'prototype_only': True}
    for key in ('functions', 'source_callable_frames'):
        result[key] = [{**row, 'unshadowed_container_builtins': builtins[str(row['symbol']).partition('::')[0]]}
                       for row in inventory.get(key, [])]
    return result

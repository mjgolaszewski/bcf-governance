"""Join bounded constructor contexts to exact maintained source inventories.

Context facts never grant dispatch, port eligibility, purity or runtime identity.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from collections.abc import Callable
from typing import Any

from .semantic_python_constructor_context_facts import discover_constructor_contexts
from .semantic_python_fresh_local_context import resolve_fresh_local_contexts
from .semantic_python_literal_default_context import retain_literal_default_contexts


class ConstructorContextSourceError(ValueError):
    """The discovery snapshot cannot be joined to unchanged declared bytes."""


def retain_constructor_contexts(
    repo_root: Path, inventory: dict[str, Any], *,
    reference: Callable[[str, str], str | None],
) -> None:
    """Attach conservative obligations; never rewrite existing resolver facts."""
    trees: dict[str, ast.Module] = {}
    classes: dict[str, ast.ClassDef] = {}
    root = repo_root.resolve()
    for row in inventory.get('files', []):
        relative = str(row['path'])
        path = root / relative
        if not path.resolve().is_relative_to(root) or path.is_symlink():
            raise ConstructorContextSourceError('unsafe constructor source: ' + relative)
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise ConstructorContextSourceError('constructor source changed after discovery: ' + relative)
        tree = ast.parse(raw.decode('utf-8'), filename=relative)
        trees[relative] = tree
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                classes[relative + '::' + node.name] = node
    contexts = []
    by_symbol: dict[str, list[dict[str, Any]]] = {}
    for function in inventory.get('functions', []):
        by_symbol.setdefault(str(function['symbol']), []).append(function)
    for source_path, tree in trees.items():
        facts = discover_constructor_contexts(tree, path=source_path,
                                              class_definitions=classes, reference=reference)
        contexts.append(facts)
        if facts['population_budget_exhausted']:
            for symbol, functions in by_symbol.items():
                if symbol.startswith(source_path + '::'):
                    for function in functions:
                        function['constructor_context_budget_unresolved'] = True
        for context in facts['functions']:
            matches = by_symbol.get(str(context['symbol']), [])
            if len(matches) != 1:
                continue  # Ambiguous runtime definitions cannot receive a guessed context.
            function = matches[0]
            function['constructor_context'] = context
            obligations = []
            for event in context['events']:
                if event['kind'] != 'method_context':
                    continue
                # Even a narrow body summary does not prove fresh ownership,
                # runtime receiver identity, or external-effect confinement.
                obligations.append({
                    'line': event['line'], 'source_target': event['source_target'],
                    'status': event['status'], 'guards': event['guards'],
                    'body_effects': event['body_effects'],
                    'initializer': event['context']['initializer'],
                    'runtime_identity': event['runtime_identity'],
                    'permits_acceptance': False,
                })
            function['constructor_context_obligations'] = obligations
            if context['budget_exhausted'] or facts['population_budget_exhausted']:
                function['constructor_context_budget_unresolved'] = True
    inventory['constructor_contexts'] = contexts
    resolve_fresh_local_contexts(inventory, trees, reference=reference)
    retain_literal_default_contexts(inventory, trees, reference=reference)

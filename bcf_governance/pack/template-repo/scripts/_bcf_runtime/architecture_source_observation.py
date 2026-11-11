"""Whole-population architecture observations over exact governed source.

The native caller binds Policy and the complete current source inventory.
Implementation duplication is measured within lexical bodies; metadata does
not count as repeated executable logic. No application imports or effects occur.
"""
from __future__ import annotations

import ast
import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .architecture_transport_contract import transport_violations


def duplication_lines(source: str) -> list[tuple[int, str]]:
    """Count executable source, preserving body windows and original locations.

    Shared signatures, imports and documentation are interface metadata rather
    than repeated implementation. Runtime values, expressions and control flow
    retain the existing normalized-line threshold and context scoping.
    """
    ignored: set[int] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            ignored.update(range(node.lineno, node.body[0].lineno))
            for decorator in node.decorator_list:
                ignored.update(range(decorator.lineno, (decorator.end_lineno or decorator.lineno) + 1))
        elif isinstance(node, (ast.Import, ast.ImportFrom)) or (
            isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ) or (isinstance(node, ast.AnnAssign) and node.value is None):
            ignored.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return [(number, re.sub(r"\s+", " ", line.strip()))
            for number, line in enumerate(source.splitlines(), 1)
            if number not in ignored and line.strip() and not line.strip().startswith("#")]


def duplication_blocks(source: str, minimum: int) -> list[tuple[int, tuple[str, ...]]]:
    """Compare implementation windows within one lexical body, never signatures."""
    scopes = [node for node in ast.walk(ast.parse(source))
              if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    groups: list[list[tuple[int, str]]] = []
    previous: tuple[int, int] | None = None
    for number, line in duplication_lines(source):
        owners = [(node.lineno, node.end_lineno or node.lineno) for node in scopes
                  if node.body[0].lineno <= number <= (node.end_lineno or node.lineno)]
        scope = min(owners, key=lambda row: row[1] - row[0]) if owners else (0, 0)
        if scope != previous:
            groups.append([])
            previous = scope
        groups[-1].append((number, line))
    return [(rows[index][0], tuple(line for _, line in rows[index:index + minimum]))
            for rows in groups for index in range(max(len(rows) - minimum + 1, 0))]


@dataclass(frozen=True)
class Policy:
    source_roots: tuple[str, ...]
    excluded_path_tokens: tuple[str, ...]
    excluded_suffixes: tuple[str, ...]
    layer_tokens: tuple[tuple[str, tuple[str, ...]], ...]
    context_root_tokens: tuple[str, ...]
    shared_context_tokens: tuple[str, ...]
    router_max_branch_nodes: int
    router_max_loop_nodes: int
    delegate_call_tokens: tuple[str, ...]
    duplication_min_lines: int
    metadata_ownership: tuple[tuple[str, str, str, tuple[str, ...]], ...] = ()


@dataclass(frozen=True, order=True)
class Violation:
    rule: str
    path: str
    line: int
    detail: str


@dataclass(frozen=True)
class Observation:
    source_sha256: tuple[tuple[str, str], ...]
    router_modules: tuple[str, ...]
    violations: tuple[Violation, ...]
    metadata_modules: tuple[str, ...] = ()
    scope: str = "Source policy observation only; not semantic, Standard, or release acceptance."


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _contexts(relative: Path, policy: Policy) -> set[str]:
    parts = relative.parent.parts
    if set(parts).intersection(policy.shared_context_tokens):
        return {"shared_kernel"}
    layers = {token for _, tokens in policy.layer_tokens for token in tokens}
    reserved = layers | set(policy.context_root_tokens) | set(policy.shared_context_tokens)
    return {
        parts[index + 1]
        for index, token in enumerate(parts[:-1])
        if token in policy.context_root_tokens and parts[index + 1] not in reserved
    }


def _production_files(root: Path, policy: Policy) -> list[Path]:
    assert policy.source_roots and len(set(policy.source_roots)) == len(policy.source_roots)
    files: set[Path] = set()
    for relative in policy.source_roots:
        source = Path(relative)
        assert not source.is_absolute() and ".." not in source.parts
        directory = root / source
        assert directory.is_dir() and directory.resolve(strict=True) == directory
        for path in directory.rglob("*.py"):
            relative_path = path.relative_to(root)
            if set(relative_path.parts).intersection(policy.excluded_path_tokens):
                continue
            if policy.excluded_suffixes and path.name.endswith(policy.excluded_suffixes):
                continue
            assert not path.is_symlink() and path.is_file()
            assert path.resolve(strict=True) == path
            assert path not in files, "overlapping configured source roots"
            files.add(path)
    assert files, "empty production population cannot qualify"
    return sorted(files)


def observe(root: Path, policy: Policy) -> Observation:
    """Observe every configured production file without importing project code."""
    assert root.is_absolute() and root.resolve(strict=True) == root
    assert policy.router_max_branch_nodes >= 0 and policy.router_max_loop_nodes >= 0
    assert policy.duplication_min_lines > 0 and policy.delegate_call_tokens
    assert len({name for name, _ in policy.layer_tokens}) == len(policy.layer_tokens)
    assert "routers" in {name for name, _ in policy.layer_tokens}
    population = _production_files(root, policy)
    population_names = {path.relative_to(root).as_posix() for path in population}
    metadata: dict[str, tuple[str, str, tuple[str, ...]]] = {}
    for name, layer, context, exports in policy.metadata_ownership:
        path = Path(name)
        assert path.as_posix() == name and not path.is_absolute() and ".." not in path.parts
        assert path.name == "__init__.py" and name in population_names and name not in metadata
        assert layer in {name for name, _ in policy.layer_tokens} and context
        assert exports == ("__doc__",), "only the admitted docstring metadata shape is supported"
        metadata[name] = (layer, context, exports)
    metadata_modules: list[str] = []
    violations: list[Violation] = []
    source_pins: list[tuple[str, str]] = []
    router_modules: list[str] = []
    trees: dict[str, ast.Module] = {}
    source_layers: dict[str, set[str]] = {}
    blocks: dict[tuple[str, tuple[str, ...]], set[tuple[str, int]]] = defaultdict(set)
    for path in population:
        relative = path.relative_to(root)
        name = relative.as_posix()
        raw = path.read_bytes()
        source_pins.append((name, hashlib.sha256(raw).hexdigest()))
        text = raw.decode("utf-8")
        tree = ast.parse(text, filename=name)
        trees[name] = tree
        parent_parts = set(relative.parent.parts)
        layers = {layer for layer, tokens in policy.layer_tokens if parent_parts.intersection(tokens)}
        contexts = _contexts(relative, policy)
        if name in metadata:
            # Governed ownership is interpretation, not a population exclusion.
            assert len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr)
            assert isinstance(tree.body[0].value, ast.Constant) and isinstance(tree.body[0].value.value, str)
            layer, context, _ = metadata[name]
            assert not layers or layers == {layer}, "metadata owner conflicts with inferred layers"
            assert not contexts or contexts == {context}, "metadata owner conflicts with inferred contexts"
            layers, contexts = {layer}, {context}
            metadata_modules.append(name)
        # Unknown ownership is an explicit failing observation, never a skip.
        if len(layers) != 1:
            violations.append(Violation("layer_membership", name, 1, repr(sorted(layers))))
        if len(contexts) != 1:
            violations.append(Violation("context_membership", name, 1, repr(sorted(contexts))))
        source_layers[name] = layers
        if "routers" in layers:
            router_modules.append(name)
        if len(contexts) == 1:
            context = next(iter(contexts))
            for line, block in duplication_blocks(text, policy.duplication_min_lines):
                blocks[(context, block)].add((name, line))
    violations.extend(Violation(rule, path, line, detail)
                      for path, line, rule, detail in transport_violations(
                          trees, source_layers, max_branch_nodes=policy.router_max_branch_nodes,
                          max_loop_nodes=policy.router_max_loop_nodes,
                          source_roots=policy.source_roots, root=root))
    for (context, block), locations in blocks.items():
        if len({name for name, _ in locations}) > 1:
            identity = hashlib.sha256("\n".join(block).encode()).hexdigest()
            for name, line in sorted(locations):
                violations.append(Violation("bounded_context_duplication", name, line,
                                            f"context={context};block={identity}"))
    assert [path.relative_to(root).as_posix() for path in _production_files(root, policy)] == [
        name for name, _ in source_pins
    ], "production population changed during observation"
    for name, expected in source_pins:
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name
    return Observation(tuple(source_pins), tuple(router_modules), tuple(sorted(violations)),
                       metadata_modules=tuple(metadata_modules))

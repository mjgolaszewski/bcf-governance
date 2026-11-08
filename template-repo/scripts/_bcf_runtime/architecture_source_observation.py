"""Source draft of whole-population policy observations; not native acceptance.

The future caller must construct Policy from the exact governed configuration,
authenticate the complete source population, and qualify real negative controls.
Router and duplication rules retain the official 2.3.9 template semantics.
No project imports, application execution, writes, or external effects occur here.
"""
from __future__ import annotations

import ast
import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


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
    blocks: dict[tuple[str, tuple[str, ...]], set[tuple[str, int]]] = defaultdict(set)
    for path in population:
        relative = path.relative_to(root)
        name = relative.as_posix()
        raw = path.read_bytes()
        source_pins.append((name, hashlib.sha256(raw).hexdigest()))
        text = raw.decode("utf-8")
        tree = ast.parse(text, filename=name)
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
        if "routers" in layers:
            router_modules.append(name)
            branches = sum(isinstance(node, (ast.If, ast.Match, ast.Try)) for node in ast.walk(tree))
            loops = sum(isinstance(node, (ast.For, ast.AsyncFor, ast.While)) for node in ast.walk(tree))
            if branches > policy.router_max_branch_nodes:
                violations.append(Violation("router_branches", name, 1, str(branches)))
            if loops > policy.router_max_loop_nodes:
                violations.append(Violation("router_loops", name, 1, str(loops)))
            for function in ast.walk(tree):
                if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                calls = [_call_name(call.func).lower() for call in ast.walk(function)
                         if isinstance(call, ast.Call)]
                if calls and not any(token.lower() in call for call in calls
                                     for token in policy.delegate_call_tokens):
                    violations.append(Violation("router_delegation", name, function.lineno, function.name))
        if len(contexts) == 1:
            context = next(iter(contexts))
            lines = [(number, re.sub(r"\s+", " ", line.strip()))
                     for number, line in enumerate(text.splitlines(), 1)
                     if line.strip() and not line.strip().startswith("#")]
            for index in range(max(len(lines) - policy.duplication_min_lines + 1, 0)):
                block = tuple(line for _, line in lines[index:index + policy.duplication_min_lines])
                blocks[(context, block)].add((name, lines[index][0]))
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

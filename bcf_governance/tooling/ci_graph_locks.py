"""Mechanically maintain CI graph extension and value-source digests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ci_graph_contracts import GRAPH_PATH, CIGraphError
from .ci_graph_yaml import GraphYAMLError, load_yaml_path, render_yaml
from .governance_install.transaction import apply_transaction


@dataclass(frozen=True)
class CIGraphLockResult:
    status: str
    changed_inputs: tuple[str, ...]


def _safe_input(repo_root: Path, relative: str) -> Path:
    path = repo_root / relative
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(repo_root):
        raise CIGraphError(f"CI graph lock input is unsafe: {relative}")
    return path


def _locked_graph(repo_root: Path) -> tuple[dict[str, Any], tuple[str, ...]]:
    try:
        graph = load_yaml_path(repo_root / GRAPH_PATH)
    except GraphYAMLError as exc:
        raise CIGraphError(str(exc)) from exc
    changed: list[str] = []
    for reference in graph.get("extensions", []):
        relative = str(reference["path"])
        digest = hashlib.sha256(_safe_input(repo_root, relative).read_bytes()).hexdigest()
        if reference.get("sha256") != digest:
            reference["sha256"] = digest
            changed.append(relative)
    for source in graph.get("value_sources", {}).values():
        relative = str(source["path"])
        digest = hashlib.sha256(_safe_input(repo_root, relative).read_bytes()).hexdigest()
        if source.get("sha256") != digest:
            source["sha256"] = digest
            changed.append(relative)
    return graph, tuple(sorted(set(changed)))


def check_ci_graph_locks(repo_root: Path) -> CIGraphLockResult:
    _, changed = _locked_graph(repo_root.resolve())
    return CIGraphLockResult("clean" if not changed else "drift", changed)


def apply_ci_graph_locks(repo_root: Path) -> CIGraphLockResult:
    repo_root = repo_root.resolve()
    graph, changed = _locked_graph(repo_root)
    if not changed:
        return CIGraphLockResult("clean", ())
    desired = render_yaml(graph)

    def mutate(shadow: Path) -> None:
        (shadow / GRAPH_PATH).write_bytes(desired)

    apply_transaction(
        repo_root,
        managed_paths=(GRAPH_PATH.as_posix(),),
        mutate_shadow=mutate,
    )
    return CIGraphLockResult("applied", changed)

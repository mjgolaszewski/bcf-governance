"""Resolve hash-locked scalar graph values from canonical YAML owners."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import Any

from .ci_graph_yaml import GraphYAMLError, load_yaml_path


SOURCE_PATTERN = re.compile(
    r"\{source:([A-Za-z0-9][A-Za-z0-9._-]*):([A-Za-z0-9][A-Za-z0-9._-]*(?:\.[A-Za-z0-9][A-Za-z0-9._-]*)*)\}"
)


class CIGraphValueError(ValueError):
    """Raised when a graph value projection is stale or not a scalar."""


def declared_graph_value_source_paths(
    repo_root: Path, *, graph_path: Path = Path("governance/ci-graph.yml")
) -> tuple[str, ...]:
    """Return the exact safe source paths that graph projection depends upon."""

    try:
        graph = load_yaml_path(repo_root / graph_path)
    except GraphYAMLError as exc:
        raise CIGraphValueError(str(exc)) from exc
    sources = graph.get("value_sources")
    if not isinstance(sources, dict):
        raise CIGraphValueError("CI graph value_sources must be an object")
    paths: list[str] = []
    for source_id, contract in sources.items():
        if not isinstance(source_id, str) or not isinstance(contract, dict):
            raise CIGraphValueError("CI graph value source contract is malformed")
        relative = contract.get("path")
        if not isinstance(relative, str):
            raise CIGraphValueError(
                f"CI graph value source path is malformed: {source_id}"
            )
        candidate = PurePosixPath(relative)
        if candidate.is_absolute() or ".." in candidate.parts or relative != candidate.as_posix():
            raise CIGraphValueError(
                f"CI graph value source path is unsafe: {relative}"
            )
        paths.append(relative)
    if len(paths) != len(set(paths)):
        raise CIGraphValueError("CI graph value source paths must be unique")
    return tuple(sorted(paths))


def _lookup(payload: dict[str, Any], selector: str) -> str | int | bool:
    value: Any = payload
    for key in selector.split("."):
        if isinstance(value, dict) and key in value:
            value = value[key]
            continue
        if isinstance(value, list) and key.isdigit() and int(key) < len(value):
            value = value[int(key)]
            continue
        else:
            raise CIGraphValueError(f"CI graph value selector does not exist: {selector}")
    if not isinstance(value, (str, int, bool)):
        raise CIGraphValueError(f"CI graph value selector is not scalar: {selector}")
    return value


def resolve_graph_values(
    repo_root: Path, graph: dict[str, Any]
) -> tuple[dict[str, Any], tuple[tuple[str, str], ...]]:
    """Resolve every typed source placeholder and return authenticated inputs."""

    loaded: dict[str, dict[str, Any]] = {}
    inputs: list[tuple[str, str]] = []
    for source_id, contract in graph["value_sources"].items():
        relative = str(contract["path"])
        path = repo_root / relative
        if path.is_symlink() or not path.is_file():
            raise CIGraphValueError(f"CI graph value source is unsafe: {relative}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != contract["sha256"]:
            raise CIGraphValueError(f"CI graph value source digest mismatch: {relative}")
        try:
            loaded[source_id] = load_yaml_path(path)
        except GraphYAMLError as exc:
            raise CIGraphValueError(str(exc)) from exc
        inputs.append((relative, digest))

    def resolve(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: resolve(item) for key, item in value.items()}
        if isinstance(value, list):
            return [resolve(item) for item in value]
        if not isinstance(value, str):
            return value
        exact = SOURCE_PATTERN.fullmatch(value)
        if exact is not None:
            source_id, selector = exact.groups()
            if source_id not in loaded:
                raise CIGraphValueError(f"CI graph references unknown value source: {source_id}")
            return _lookup(loaded[source_id], selector)

        def replace(match: re.Match[str]) -> str:
            source_id, selector = match.groups()
            if source_id not in loaded:
                raise CIGraphValueError(f"CI graph references unknown value source: {source_id}")
            return str(_lookup(loaded[source_id], selector))

        rendered = SOURCE_PATTERN.sub(replace, value)
        if "{source:" in rendered:
            raise CIGraphValueError(f"CI graph contains malformed value source: {value}")
        return rendered

    return resolve(graph), tuple(sorted(inputs))

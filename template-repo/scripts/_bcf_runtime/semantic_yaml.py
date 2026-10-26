"""Duplicate-rejecting YAML decoding for semantic authority contracts."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml


class SemanticYAMLError(ValueError):
    """Raised when semantic YAML is malformed or ambiguous."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    construct: Callable[[yaml.Node, bool], object] = loader.construct_object
    for key_node, value_node in node.value:
        key = construct(key_node, deep)
        if key in result:
            raise SemanticYAMLError(f"duplicate YAML key: {key}")
        result[key] = construct(value_node, deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping
)


def load_unique_mapping(path: Path) -> dict[str, Any]:
    try:
        payload = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError, SemanticYAMLError) as exc:
        raise SemanticYAMLError(str(exc)) from exc
    if not isinstance(payload, dict):
        raise SemanticYAMLError("document must contain a mapping")
    return payload

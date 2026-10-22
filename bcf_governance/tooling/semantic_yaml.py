"""Duplicate-rejecting YAML decoding for semantic authority contracts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


class SemanticYAMLError(ValueError):
    """Raised when semantic YAML is malformed or ambiguous."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise SemanticYAMLError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
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

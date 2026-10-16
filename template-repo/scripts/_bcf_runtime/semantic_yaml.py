"""Duplicate-rejecting YAML decoding for semantic authority contracts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


class SemanticYAMLError(ValueError):
    """Raised when semantic YAML is malformed or ambiguous."""


class _UniqueKeyLoader(yaml.SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self._checked_mapping_nodes: set[int] = set()
        self._merge_key = object()

    def flatten_mapping(self, node):
        # Check authored keys once, before SafeLoader expands/reuses merge nodes.
        if id(node) not in self._checked_mapping_nodes:
            self._checked_mapping_nodes.add(id(node))
            seen = set()
            for key_node, _ in node.value:
                key = (
                    self._merge_key if key_node.tag == "tag:yaml.org,2002:merge"
                    else self.construct_object(key_node)
                )
                if key in seen:
                    raise SemanticYAMLError(f"duplicate YAML key: {key_node.value}")
                seen.add(key)
        super().flatten_mapping(node)


def _mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping
)


def load_unique_mapping_text(text: str) -> dict[str, Any]:
    """Decode one captured semantic document through the existing unique loader."""
    try:
        payload = yaml.load(text, Loader=_UniqueKeyLoader)
    except (UnicodeError, TypeError, yaml.YAMLError, SemanticYAMLError) as exc:
        raise SemanticYAMLError(str(exc)) from exc
    if not isinstance(payload, dict):
        raise SemanticYAMLError("document must contain a mapping")
    return payload


def load_unique_mapping(path: Path) -> dict[str, Any]:
    try:
        return load_unique_mapping_text(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise SemanticYAMLError(str(exc)) from exc

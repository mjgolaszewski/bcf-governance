"""Strict YAML decoding and deterministic rendering for CI graph contracts."""

from __future__ import annotations

import copy
from pathlib import Path
import re
from typing import Any

import yaml  # type: ignore[import-untyped]


class GraphYAMLError(ValueError):
    """Raised when a graph or workflow YAML document is ambiguous."""


class _UniqueYAML12Loader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise GraphYAMLError(f"duplicate YAML key {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueYAML12Loader.yaml_implicit_resolvers = copy.deepcopy(
    yaml.SafeLoader.yaml_implicit_resolvers
)
_UniqueYAML12Loader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)
for first_character, resolvers in list(_UniqueYAML12Loader.yaml_implicit_resolvers.items()):
    _UniqueYAML12Loader.yaml_implicit_resolvers[first_character] = [
        item for item in resolvers if item[0] != "tag:yaml.org,2002:bool"
    ]
_UniqueYAML12Loader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)


class _GraphDumper(yaml.SafeDumper):
    pass


def _represent_string(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_GraphDumper.add_representer(str, _represent_string)


def load_yaml_bytes(content: bytes, *, source: str) -> dict[str, Any]:
    try:
        payload = yaml.load(content, Loader=_UniqueYAML12Loader)
    except (yaml.YAMLError, GraphYAMLError) as exc:
        raise GraphYAMLError(f"{source}: {exc}") from exc
    if not isinstance(payload, dict):
        raise GraphYAMLError(f"{source}: document must be a mapping")
    return payload


def load_yaml_path(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise GraphYAMLError(f"{path}: expected a regular nonsymlink file")
    return load_yaml_bytes(path.read_bytes(), source=path.as_posix())


def render_yaml(payload: dict[str, Any]) -> bytes:
    return yaml.dump(
        payload,
        Dumper=_GraphDumper,
        sort_keys=False,
        width=1000,
        default_flow_style=None,
    ).encode("utf-8")

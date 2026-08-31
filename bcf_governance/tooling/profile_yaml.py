"""Bounded YAML rendering for generated profile contracts and policy."""

from __future__ import annotations

from typing import Any

import yaml  # type: ignore[import-untyped]


class _FlowMapping(dict[str, Any]):
    """Marker for one compact generated negative-control mapping."""


class _ProfileSurfaceDumper(yaml.SafeDumper):
    """Safe dumper with deterministic compact control rendering."""


def _represent_flow_mapping(
    dumper: yaml.SafeDumper, value: _FlowMapping
) -> yaml.nodes.MappingNode:
    node = dumper.represent_dict(value)
    node.flow_style = True
    return node


_ProfileSurfaceDumper.add_representer(_FlowMapping, _represent_flow_mapping)


def _compact_control_mappings(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                [_FlowMapping(control) for control in item]
                if key == "negative_controls" and isinstance(item, list)
                else _compact_control_mappings(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_compact_control_mappings(item) for item in value]
    return value


def render_profile_surface(payload: dict[str, Any], *, width: int) -> str:
    """Render controls compactly without changing their decoded semantics."""

    return yaml.dump(
        _compact_control_mappings(payload),
        Dumper=_ProfileSurfaceDumper,
        sort_keys=False,
        width=width,
        default_flow_style=None,
    )

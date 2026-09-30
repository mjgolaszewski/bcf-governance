"""Bounded YAML rendering for generated profile contracts and policy."""

from __future__ import annotations

from typing import Any

import yaml  # type: ignore[import-untyped]


class _FlowMapping(dict[str, Any]):
    """Marker for one compact generated negative-control mapping."""


class _SharedScalar(str):
    """Ordinary YAML string eligible for sharing within one rendered surface."""


class _ProfileSurfaceDumper(yaml.SafeDumper):
    """Safe dumper with deterministic compact control rendering."""

    def ignore_aliases(self, value: Any) -> bool:
        return False if isinstance(value, _SharedScalar) else super().ignore_aliases(value)


def _represent_flow_mapping(
    dumper: yaml.SafeDumper, value: _FlowMapping
) -> yaml.nodes.MappingNode:
    node = dumper.represent_dict(value)
    node.flow_style = True
    return node


_ProfileSurfaceDumper.add_representer(_FlowMapping, _represent_flow_mapping)
_ProfileSurfaceDumper.add_representer(_SharedScalar, yaml.SafeDumper.represent_str)


def _compact_control_mappings(value: Any, scalars: dict[str, _SharedScalar]) -> Any:
    if isinstance(value, str) and len(value) >= 8:
        return scalars.setdefault(value, _SharedScalar(value))
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            compact = _compact_control_mappings(item, scalars)
            if key == "negative_controls" and isinstance(compact, list):
                compact = [_FlowMapping(control) for control in compact]
            elif key == "invocation" and isinstance(compact, dict):
                compact = _FlowMapping(compact)
            result[key] = compact
        return result
    if isinstance(value, list):
        return [_compact_control_mappings(item, scalars) for item in value]
    return value


def render_profile_surface(payload: dict[str, Any], *, width: int) -> str:
    """Render controls compactly without changing their decoded semantics."""

    return yaml.dump(
        _compact_control_mappings(payload, {}),
        Dumper=_ProfileSurfaceDumper,
        sort_keys=False,
        width=width,
        default_flow_style=None,
    )


def render_governance_profile(payload: dict[str, Any]) -> str:
    """Render the profile with each typed gate as one lossless compact record."""

    profile = dict(payload)
    raw_release_profile = profile.get("release_gate_profile")
    if raw_release_profile is not None:
        if not isinstance(raw_release_profile, dict):
            raise ValueError("governance profile release gate profile must be a mapping")
        release_profile = dict(raw_release_profile)
        gates = release_profile.get("gates")
        if not isinstance(gates, dict) or any(
            not isinstance(gate_id, str) or not isinstance(gate, dict)
            for gate_id, gate in gates.items()
        ):
            raise ValueError("governance profile gate catalog must be a mapping of mappings")
        release_profile["gates"] = {
            gate_id: _FlowMapping(gate) for gate_id, gate in gates.items()
        }
        profile["release_gate_profile"] = release_profile
    return yaml.dump(
        profile,
        Dumper=_ProfileSurfaceDumper,
        sort_keys=False,
        width=4096,
        default_flow_style=None,
    )

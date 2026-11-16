"""Lossless promotion renderers preserve full indexed and multi-line gate inputs."""
from __future__ import annotations

from copy import deepcopy

import yaml

from bcf_governance.tooling.profile_yaml import render_profile_surface
from bcf_governance.tooling.semantic_locking import render_compact_semantic_yaml


def test_indexed_root_keeps_large_closed_index_inside_existing_line_and_byte_caps() -> None:
    payload = {
        "document": {"kind": "canonical_representation_registry"},
        "enforcement": {"blocking_semantic_ids": [f"binding.value-{i}.v1" for i in range(578)]},
        "source_authority": {"authoritative_python_roots": ["src", "tests"]},
        "representation_sources": [f"governance/canonical-representations/family-{i}.yml" for i in range(295)],
    }
    before = deepcopy(payload)
    rendered = render_compact_semantic_yaml(payload)
    assert yaml.safe_load(rendered) == payload == before
    assert len(rendered.splitlines()) <= 200
    assert len(rendered) <= 64 * 1024
    assert render_compact_semantic_yaml(yaml.safe_load(rendered)) == rendered


def test_flat_semantic_rendering_keeps_its_existing_bytes() -> None:
    payload = {"document": {"kind": "registry"}, "representations": [{"semantic_id": "one"}]}
    assert render_compact_semantic_yaml(payload) == (
        b"document:\n  kind: registry\nrepresentations:\n- {semantic_id: one}\n"
    )


def test_full_gate_commands_preserve_newlines_and_types_inside_existing_budgets() -> None:
    gates = {}
    for index in range(20):
        command = "\n".join(f"printf '%s\\n' 'gate {index}: line {line}'" for line in range(30)) + "\n"
        gates[f"gate-{index}"] = {
            "command": command, "required": index < 17,
            "negative_controls": [{"id": f"control-{index}", "command": command}],
        }
    payload = {
        "document": {"kind": "gate_contract_registry"},
        "gates": gates, "gate_catalog": {**gates, "deferred-extra": {"required": False}},
        "values": ["true", True, None, 7, "quote: \" and slash \\\nnext\n"],
    }
    before = deepcopy(payload)
    rendered = render_profile_surface(payload, width=4096)
    assert yaml.safe_load(rendered) == payload == before
    assert len(rendered.splitlines()) <= 800
    assert len(rendered.encode()) <= 96 * 1024
    assert render_profile_surface(yaml.safe_load(rendered), width=4096) == rendered

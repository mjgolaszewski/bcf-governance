"""Profile rendering preserves contracts inside their existing context budget."""

from __future__ import annotations

import copy
from pathlib import Path

import yaml

from bcf_governance.tooling.profile_yaml import render_profile_surface


def test_current_gate_contract_renders_inside_existing_context_budget() -> None:
    root = Path(__file__).resolve().parents[1]
    source = yaml.safe_load((root / "governance/gate-contracts.yml").read_text())
    before = copy.deepcopy(source)
    rendered = render_profile_surface(source, width=4096)

    assert yaml.safe_load(rendered) == source == before
    assert len(rendered.encode("utf-8")) <= 101 * 1024
    assert len(rendered.splitlines()) <= 800
    assert render_profile_surface(yaml.safe_load(rendered), width=4096) == rendered


def test_scalar_sharing_is_deterministic_local_and_preserves_yaml_types() -> None:
    kind = "test_node_failure"
    payload = {"negative_controls": [
        {"id": f"control-{index}", "oracle": {"kind": kind.encode().decode()},
         "values": ["01234567890123456789", "true", True, None, 7, "line one\nline two\n"]}
        for index in range(5)
    ]}
    ordinary = yaml.safe_dump(payload)
    first = render_profile_surface(payload, width=4096)
    render_profile_surface({"different": kind}, width=4096)

    assert yaml.safe_load(first) == payload
    assert render_profile_surface(copy.deepcopy(payload), width=4096) == first
    assert yaml.safe_dump(payload) == ordinary
    assert len(first) < len(ordinary)

"""Existing phase-input queries consume canonical values without becoming factories."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from bcf_governance.tooling import semantic_ownership_inventory, semantic_ownership_scan
from bcf_governance.tooling.semantic_ownership_registry import load_registry

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def phase_input_inventory():
    registry = load_registry(ROOT)
    files = [ROOT / "bcf_governance/tooling" / name for name in (
        "trusted_inputs.py", "ci_authority_certification.py", "ci_github_artifacts.py",
    )]
    discovered = semantic_ownership_inventory.discover_python_source(ROOT, files=files)
    return semantic_ownership_scan.resolve_python_imports(ROOT, discovered, registry.python_import_roots)


@pytest.mark.parametrize("semantic_id", [
    "governance.ci-certification-verification.v1", "governance.github-provider-artifact.v1",
])
@pytest.mark.parametrize("operation", ["verify_phase_closure_input", "verify_required_phase_closure_inputs"])
def test_phase_input_authorization_consumer_is_exact_and_causal(phase_input_inventory, semantic_id, operation):
    registry = load_registry(ROOT)
    entry = next(value for value in registry.entries if value.semantic_id == semantic_id)
    consumer = "bcf_governance/tooling/trusted_inputs.py::" + operation
    assert consumer in entry.raw["declared_consumer_layers_and_sinks"]["authorization"]
    assert consumer not in entry.authorized_constructors | entry.authorized_delegates
    assert entry.raw["narrow_suppressions"] == []
    assert any(value["symbol"] == consumer for value in phase_input_inventory["functions"])
    selected = replace(registry, entries=(entry,))
    before = semantic_ownership_scan.evaluate_discovery(phase_input_inventory, selected)
    assert not [value for value in before["violations"]
                if value["kind"] == "downstream_normalization" and value["symbol"] == consumer]
    removed = deepcopy(entry.raw)
    removed["declared_consumer_layers_and_sinks"]["authorization"].remove(consumer)
    without = replace(selected, entries=(replace(entry, raw=removed),))
    after = semantic_ownership_scan.evaluate_discovery(phase_input_inventory, without)
    assert any(value["kind"] == "downstream_normalization" and value["symbol"] == consumer
               for value in after["violations"])

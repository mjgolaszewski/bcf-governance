"""The actual standard SBOM CLI must admit input before allocating output."""
import importlib.util
import json
from pathlib import Path
import sys

import pytest
import yaml

from bcf_governance.tooling.dependency_assurance import DependencyAssuranceError, cyclonedx_sbom
from test_dependency_snapshot_consumption import changed, inventory

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / ".github/scripts/run_self_governance_gate.py"


def load_gate(tmp_path, monkeypatch, source=SOURCE):
    spec = importlib.util.spec_from_file_location("_sbom_gate_admission_fixture", source)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    root = tmp_path / "repo"
    root.mkdir()
    governance = root / "governance"
    governance.mkdir()
    policy = governance / "self-governance-policy.yml"
    registry = governance / "gate-contracts.yml"
    policy.write_text(yaml.safe_dump({"sbom_format": "CycloneDX"}))
    registry.write_text(yaml.safe_dump({"gates": {"security-sbom": {"evidence": {}}}}))
    monkeypatch.setattr(gate, "REPO_ROOT", root)
    monkeypatch.setattr(gate, "POLICY_PATH", policy)
    monkeypatch.setattr(gate, "GATE_CONTRACTS_PATH", registry)
    monkeypatch.setattr(sys, "argv", [str(source), "security-sbom"])
    return gate, root


def assert_refusal_without_allocation(gate, root):
    caught = None
    try:
        gate.main()
    except (DependencyAssuranceError, SystemExit, TypeError, ValueError) as error:
        caught = error
    assert not (root / ".artifacts").exists(), "security-sbom allocated before inventory admission"
    assert isinstance(caught, SystemExit) and caught.code == 1, "SBOM refusal bypassed controlled gate failure"


@pytest.mark.parametrize("kind", ["component", "roots", "edges", "digest"])
def test_actual_cli_refuses_stale_inventory_before_allocation(tmp_path, monkeypatch, capsys, kind):
    gate, root = load_gate(tmp_path, monkeypatch)
    subject = changed(inventory(), kind)
    monkeypatch.setattr(gate, "collect_installed_inventory", lambda _: subject)
    assert_refusal_without_allocation(gate, root)
    assert "security-sbom failed: dependency inventory" in capsys.readouterr().err


def test_actual_cli_serializes_before_allocation(tmp_path, monkeypatch):
    gate, root = load_gate(tmp_path, monkeypatch)
    subject = inventory()
    monkeypatch.setattr(gate, "collect_installed_inventory", lambda _: subject)
    original = json.dumps
    def serialize(value, *args, **kwargs):
        if isinstance(value, dict) and value.get("bomFormat") == "CycloneDX":
            raise TypeError("test serialization failure")
        return original(value, *args, **kwargs)
    monkeypatch.setattr(gate.json, "dumps", serialize)
    assert_refusal_without_allocation(gate, root)


def test_refusal_preserves_preexisting_evidence(tmp_path, monkeypatch):
    gate, root = load_gate(tmp_path, monkeypatch)
    path = root / ".artifacts/sbom.json"
    path.parent.mkdir()
    path.write_bytes(b"retained prior bytes\n")
    subject = changed(inventory(), "component")
    monkeypatch.setattr(gate, "collect_installed_inventory", lambda _: subject)
    caught = None
    try:
        gate.main()
    except (DependencyAssuranceError, SystemExit) as error:
        caught = error
    assert path.read_bytes() == b"retained prior bytes\n"
    assert isinstance(caught, SystemExit) and caught.code == 1


def test_valid_registered_cli_preserves_exact_document_bytes(tmp_path, monkeypatch):
    gate, root = load_gate(tmp_path, monkeypatch)
    subject = inventory()
    expected = json.dumps(cyclonedx_sbom(subject), indent=2, sort_keys=True) + "\n"
    monkeypatch.setattr(gate, "collect_installed_inventory", lambda _: subject)
    gate.main()
    assert (root / ".artifacts/sbom.json").read_text() == expected


def test_restoring_late_admission_fails_named_boundary_control(tmp_path, monkeypatch):
    source = SOURCE.read_text()
    render = '        rendered = json.dumps(cyclonedx_sbom(inventory), indent=2, sort_keys=True, allow_nan=False) + "\\n"\n'
    write = '    output.write_text(rendered, encoding="utf-8")'
    assert source.count(render) == source.count(write) == 1
    altered = source.replace(render, '        rendered = None\n').replace(write,
        '    output.write_text(json.dumps(cyclonedx_sbom(inventory), indent=2, sort_keys=True) + "\\n", encoding="utf-8")')
    path = tmp_path / "late-admission.py"
    path.write_text(altered)
    gate, root = load_gate(tmp_path, monkeypatch, source=path)
    subject = changed(inventory(), "component")
    monkeypatch.setattr(gate, "collect_installed_inventory", lambda _: subject)
    with pytest.raises(AssertionError, match="security-sbom allocated before inventory admission"):
        assert_refusal_without_allocation(gate, root)

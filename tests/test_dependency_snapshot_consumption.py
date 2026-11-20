"""Stored dependency digests must survive exact input capture at consumers."""
from dataclasses import replace
import hashlib
import json

import pytest

from bcf_governance.tooling import dependency_assurance as owner


def inventory():
    result = owner.InstalledDependencyInventory(
        roots=("example",), components=({"type": "library", "name": "example", "version": "1.0", "bom-ref": "pkg:pypi/example@1.0"},),
        dependencies=({"ref": "pkg:pypi/example@1.0", "dependsOn": []},), sha256="")
    return replace(result, sha256=hashlib.sha256(json.dumps(result.payload(), sort_keys=True, separators=(",", ":")).encode()).hexdigest())


def changed(subject, kind):
    if kind == "component":
        subject.components[0]["version"] = "2.0"
    elif kind == "roots":
        subject = replace(subject, roots=("unobserved",))
    elif kind == "edges":
        subject.dependencies[0]["dependsOn"].append("pkg:pypi/unobserved@1.0")
    else:
        subject = replace(subject, sha256="a" * 64)
    return subject


def audit(subject, raw=None, code=0):
    if raw is None:
        raw = {"dependencies": [{"name": "example", "version": subject.components[0]["version"], "vulns": []}]}
    return owner.audit_envelope(inventory=subject, scanner_version="2.10.1", service="pypi",
        returncode=code, raw=raw, diagnostic="")


@pytest.mark.parametrize("kind", ["component", "roots", "edges", "digest"])
def test_stale_inventory_cannot_gain_clean_subject(kind):
    result = audit(changed(inventory(), kind))
    assert result["status"] == "scanner_failure", "stale inventory was accepted under its old digest"
    assert "inventory" in result["diagnostic"]


@pytest.mark.parametrize("kind", ["component", "roots", "edges", "digest"])
@pytest.mark.parametrize("consumer", ["requirements", "sbom"])
def test_stale_export_rejects_before_output_allocation(tmp_path, kind, consumer):
    subject = changed(inventory(), kind)
    target = tmp_path / "not-allocated/input.txt"
    with pytest.raises(owner.DependencyAssuranceError, match="inventory"):
        if consumer == "requirements":
            owner.write_frozen_requirements(subject, target)
        else:
            owner.cyclonedx_sbom(subject)
    assert not target.parent.exists()


def test_payload_is_owned_including_nested_edge_lists():
    subject = inventory()
    captured = subject.payload()
    captured["components"][0]["version"] = "2.0"
    captured["dependencies"][0]["dependsOn"].append("other")
    assert subject.components[0]["version"] == "1.0"
    assert subject.dependencies[0]["dependsOn"] == []


def test_sbom_is_owned_including_nested_edge_lists():
    subject = inventory()
    captured = owner.cyclonedx_sbom(subject)
    captured["components"][0]["version"] = "2.0"
    captured["dependencies"][0]["dependsOn"].append("other")
    assert subject.components[0]["version"] == "1.0"
    assert subject.dependencies[0]["dependsOn"] == []


def test_scanner_input_cannot_rewrite_captured_result():
    raw = {"dependencies": [{"name": "example", "version": "1.0", "vulns": []}]}
    result = audit(inventory(), raw)
    raw["dependencies"][0]["vulns"].append({"id": "CVE-EXAMPLE"})
    assert result["raw_result"]["dependencies"][0]["vulns"] == []
    assert result["status"] == "clean"
    assert result["raw_result_sha256"] == hashlib.sha256(json.dumps(result["raw_result"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_scanner_input_cannot_rewrite_captured_findings():
    raw = {"dependencies": [{"name": "example", "version": "1.0", "vulns": [{"id": "CVE-EXAMPLE", "fix_versions": []}]}]}
    result = audit(inventory(), raw, code=1)
    raw["dependencies"][0]["vulns"].clear()
    assert result["findings"][0]["vulnerabilities"][0]["id"] == "CVE-EXAMPLE"
    assert result["status"] == "vulnerable"


def test_valid_snapshot_preserves_consumers(tmp_path):
    subject = inventory()
    assert audit(subject)["status"] == "clean"
    path = tmp_path / "input.txt"
    owner.write_frozen_requirements(subject, path)
    assert path.read_text() == "example==1.0\n"
    result = owner.cyclonedx_sbom(subject)
    assert result["components"] == list(subject.components)
    assert result["dependencies"] == list(subject.dependencies)


@pytest.mark.parametrize("consumer", ["requirements", "sbom", "audit"])
def test_mutation_after_admitted_capture_does_not_replace_subject(tmp_path, monkeypatch, consumer):
    subject = inventory()
    original = getattr(owner, "_validated_inventory_snapshot", None)
    assert callable(original)
    def captured(value):
        result = original(value)
        value.components[0]["version"] = "2.0"
        return result
    monkeypatch.setattr(owner, "_validated_inventory_snapshot", captured)
    if consumer == "requirements":
        path = tmp_path / "input.txt"
        owner.write_frozen_requirements(subject, path)
        assert path.read_text() == "example==1.0\n"
    elif consumer == "sbom":
        assert owner.cyclonedx_sbom(subject)["components"][0]["version"] == "1.0"
    else:
        assert audit(subject)["status"] == "clean"
    assert subject.components[0]["version"] == "2.0"


@pytest.mark.parametrize("extra", [float("nan"), {"not-json"}])
def test_nonjson_or_nonfinite_scanner_payload_is_not_clean(extra):
    raw = {"dependencies": [{"name": "example", "version": "1.0", "vulns": []}], "extra": extra}
    assert audit(inventory(), raw)["status"] == "scanner_failure"


def test_malformed_but_rehashed_component_rejects_before_write(tmp_path):
    subject = inventory()
    subject.components[0].pop("version")
    subject = replace(subject, sha256=hashlib.sha256(json.dumps(subject.payload(), sort_keys=True, separators=(",", ":")).encode()).hexdigest())
    path = tmp_path / "not-allocated/input.txt"
    with pytest.raises(owner.DependencyAssuranceError, match="inventory"):
        owner.write_frozen_requirements(subject, path)
    assert not path.parent.exists()

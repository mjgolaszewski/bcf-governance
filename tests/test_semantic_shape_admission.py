from __future__ import annotations

from types import SimpleNamespace
import json
from pathlib import Path

import pytest

from tests.test_semantic_authority import REPO_ROOT, _yaml, contracts
from bcf_governance.tooling.semantic_ownership_registry import Registry, load_registry
from bcf_governance.tooling import semantic_ownership_scan as scan


SHAPES = [
    ({"authoritative_mutation": True}, "cannot mutate or confer authority"),
    ({"authority_conferral": True}, "cannot mutate or confer authority"),
    ({"semantic_kind": "projection"}, "must construct a read model"),
    ({"allowed_mutation_ports": ["app.py::write"]}, "cannot declare mutation or authority ports"),
    ({"semantic_kind": "command", "authoritative_mutation": True}, "requires a declared mutation port"),
    ({"semantic_kind": "command", "authority_conferral": True}, "requires a declared authority port"),
    ({"semantic_kind": "command", "authority_conferral": True,
      "allowed_authority_ports": ["app.py::authorize"], "model_callable": True},
     "model-callable operation .* cannot confer authority"),
]


def late_invalid_payload(changes: dict) -> dict:
    payload = _yaml("governance/application-operations.yml")
    doctor = next(row for row in payload["operations"] if row["population_key"] == "doctor")
    payload["operations"].remove(doctor)
    doctor.update(changes)
    payload["operations"].append(doctor)
    return payload


@pytest.mark.parametrize("changes,cause", SHAPES)
@pytest.mark.parametrize("language", [None, "python"])
def test_late_semantic_contradiction_precedes_population_discovery(
    changes: dict, cause: str, language: str | None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = late_invalid_payload(changes)

    def forbidden(*args, **kwargs):
        pytest.fail("population discovery allocated before authored semantic rejection")

    monkeypatch.setattr(contracts, "_discover_population", forbidden)
    with pytest.raises(contracts.SemanticAuthorityError, match=cause):
        contracts._validate_operations(REPO_ROOT, payload, {}, source_language=language)


@pytest.mark.parametrize("changes,cause", SHAPES)
def test_structural_admission_consumes_the_existing_semantic_shape_predicate(
    changes: dict, cause: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = late_invalid_payload(changes)
    monkeypatch.setattr(contracts, "load_application_operations",
                        lambda root: SimpleNamespace(raw=payload))

    def forbidden(*args, **kwargs):
        pytest.fail("migration resolution allocated before authored semantic rejection")

    monkeypatch.setattr(contracts, "validate_exact_base_migrations", forbidden)
    with pytest.raises(contracts.SemanticAuthorityError, match=cause):
        contracts.validate_semantic_contract_structure(REPO_ROOT, load_registry(REPO_ROOT))


@pytest.mark.parametrize("changes,cause", SHAPES)
def test_actual_authored_scanner_rejects_shape_before_source_allocation(
    changes: dict, cause: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = late_invalid_payload(changes)
    monkeypatch.setattr(contracts, "load_application_operations",
                        lambda root: SimpleNamespace(raw=payload))

    def forbidden(*args, **kwargs):
        pytest.fail("scanner source inventory allocated before authored semantic rejection")

    monkeypatch.setattr(scan, "discover_python_source", forbidden)
    with pytest.raises(contracts.SemanticAuthorityError, match=cause):
        scan.validate_authored_semantic_ownership(REPO_ROOT)


@pytest.mark.parametrize("state", ["disabled", "not_applicable"])
def test_nonenabled_capabilities_keep_contracts_unread(
    state: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(contracts, "capability_states",
                        lambda root: {key: state for key in contracts.CAPABILITIES})

    def forbidden(*args, **kwargs):
        pytest.fail("nonenabled semantic contracts must remain unread")

    monkeypatch.setattr(contracts, "load_semantic_families", forbidden)
    monkeypatch.setattr(contracts, "load_application_operations", forbidden)
    assert contracts.validate_semantic_contract_structure(REPO_ROOT, None) == {
        "families": 0, "operations": 0,
    }


def test_valid_structural_catalog_preserves_counts_without_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args, **kwargs):
        pytest.fail("structural admission must not discover source")

    monkeypatch.setattr(contracts, "_discover_population", forbidden)
    result = contracts.validate_semantic_contract_structure(REPO_ROOT, load_registry(REPO_ROOT))
    assert result == {
        "families": len(_yaml("governance/semantic-families.yml")["families"]),
        "operations": len(_yaml("governance/application-operations.yml")["operations"]),
    }


@pytest.mark.parametrize("state", ["disabled", "not_applicable", "advisory", "blocking"])
@pytest.mark.parametrize("python_only", [False, True])
def test_operation_admission_preserves_independent_registry_order(
    tmp_path: Path, state: str, python_only: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "governance-profile.yml").write_text(json.dumps({
        "semantic_capabilities": {key: state for key in contracts.CAPABILITIES},
    }))
    events: list[str] = []
    source = {"files": [], "types": [], "functions": [], "constructors": [],
              "normalizations": [], "unresolved": []}
    registry = Registry(
        phase="P04", mode="report_only", unresolved_dynamic_policy="report",
        authoritative_python_roots=("src",), generated_mirror_roots=(), entries=(),
        raw={"source_authority": {"typescript_engine": "not_applicable_until_declared_by_consumer"}},
    )

    def canonical_registry(root):
        if "discovery" not in events or (not python_only and "typescript-files" not in events):
            pytest.fail("canonical registry read before independent source discovery")
        events.append("registry")
        return registry

    def operations(root):
        events.append("operations")
        return SimpleNamespace(raw=_yaml("governance/application-operations.yml"))

    monkeypatch.setattr(contracts, "load_application_operations", operations)
    monkeypatch.setattr(scan, "load_registry", canonical_registry)
    monkeypatch.setattr(scan, "discover_python_source",
                        lambda root: (events.append("discovery") or source))
    monkeypatch.setattr(scan, "tracked_typescript_files",
                        lambda root: (events.append("typescript-files") or []))
    monkeypatch.setattr(scan, "resolve_python_imports",
                        lambda root, value, roots: (events.append("imports") or value))
    monkeypatch.setattr(scan, "discover_source",
                        lambda *args, **kwargs: (events.append("complete-source") or
                                                (source, source, {}, registry)))
    result = scan._discover_ownership_inputs(tmp_path, python_only=python_only)
    expected = (["operations"] if state in {"advisory", "blocking"} else [])
    expected += ["discovery"] + ([] if python_only else ["typescript-files"])
    expected += ["registry", "imports"] + ([] if python_only else ["complete-source"])
    assert events == expected
    assert result[1] is source

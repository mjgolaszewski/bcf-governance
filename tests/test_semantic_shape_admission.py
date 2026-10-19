from __future__ import annotations

from types import SimpleNamespace

import pytest

from tests.test_semantic_authority import REPO_ROOT, _yaml, contracts
from bcf_governance.tooling.semantic_ownership_registry import load_registry


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

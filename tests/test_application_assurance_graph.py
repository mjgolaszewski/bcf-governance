from __future__ import annotations

from copy import deepcopy

import pytest

from bcf_governance.tooling.application_assurance_graph import (
    ApplicationAssuranceGraphError,
    compile_application_assurance_graph,
)
from bcf_governance.tooling.evidence_claim_resolution import resolved_session_claims


PACK_GATE = {
    "invocation": {"argv": ["python3", "gate.py"], "cwd": ".", "env": {}, "required_env": []},
    "evidence": {"kind": "gate"},
    "negative_controls": [{"id": "pack-control"}],
}
APPLICATION_GATE = {
    "invocation": {"argv": ["python3", "app_gate.py"], "cwd": ".", "env": {}, "required_env": []},
    "evidence": {"kind": "test_suite"},
    "negative_controls": [{"id": "application-control"}],
}


def _claim(truth: str) -> dict[str, object]:
    return {
        "truth": truth,
        "dependencies": {
            "subject": ["application"],
            "detector": ["detector"],
            "test_population": ["tests"],
            "toolchain": ["toolchain"],
            "trust": ["workflow"],
        },
        "qualification_scope": "subject",
        "profiles": ["normal", "regulated"],
    }


def _graph() -> dict[str, object]:
    return {
        "version": "1.0",
        "dependency_sets": {
            "application": ["src/**"],
            "detector": ["scripts/app_gate.py"],
            "tests": ["tests/**"],
            "toolchain": ["pyproject.toml"],
            "workflow": [".github/workflows/**"],
            "editorial": ["docs/**"],
        },
        "non_proof_dependencies": ["editorial"],
        "groups": {
            "preflight": {
                "producer": "preflight",
                "captured_by_preflight": True,
                "claims": {
                    "governance-contracts-valid": {
                        **_claim("governance contracts validate"),
                        "legacy_gate": "governance-validate",
                        "qualification_scope": "none",
                    }
                },
            },
            "application-tests": {
                "producer": "application-tests",
                "gate": APPLICATION_GATE,
                "command_policy": "automated_tests",
                "rationale": "the adopter owns its application behavior",
                "claims": {
                    "application-behavior-valid": _claim("application behavior passes"),
                    "application-contract-valid": {
                        **_claim("application contracts pass"),
                        "legacy_gate": "application-contract",
                    },
                },
            },
        },
    }


def _compile(graph: object | None = None) -> dict[str, object]:
    return compile_application_assurance_graph(
        _graph() if graph is None else graph,
        pack_gates={
            "governance-validate": PACK_GATE,
            "application-contract": PACK_GATE,
        },
        pack_gate_catalog={
            "governance_validate": {
                "target": "governance-validate",
                "status": "required",
                "command_policy": "governance_validation",
                "rationale": "pack governance remains valid",
            }
        },
    )


def test_consumer_graph_projects_gate_catalog_groups_and_claims_once() -> None:
    projection = _compile()

    assert set(projection["gates"]) == {"application-tests"}
    assert projection["gate_catalog"] == {
        "application-tests": {
            "target": "application-tests",
            "status": "required",
            "command_policy": "automated_tests",
            "rationale": "the adopter owns its application behavior",
        }
    }
    model = projection["claim_model"]
    assert model["execution_groups"]["application-tests"] == {
        "producer": "application-tests",
        "claims": ["application-behavior-valid", "application-contract-valid"],
        "depends_on": [],
    }
    assert model["claims"]["application-behavior-valid"]["legacy_gate"] == (
        "application-tests"
    )


def test_consumer_graph_receipt_cannot_launder_an_unrelated_claim() -> None:
    model = _compile()["claim_model"]
    receipt = {
        "schema_version": "3.0",
        "gate_id": "application-tests",
        "claims": ["application-behavior-valid", "unrelated-claim"],
    }
    receipts = {
        "application-tests": [
            {"gate_id": "application-tests", "result": "verified", "receipt": receipt}
        ]
    }

    assert resolved_session_claims(
        receipts,
        model,
        set(),
        ["application-behavior-valid", "application-contract-valid", "unrelated-claim"],
    ) == {"application-behavior-valid"}


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda graph: graph["groups"]["application-tests"]["claims"][
                "application-behavior-valid"
            ]["dependencies"]["subject"].append("missing"),
            "unknown dependency sets",
        ),
        (
            lambda graph: graph["groups"]["application-tests"].update(
                {"depends_on": ["missing-group"]}
            ),
            "unknown dependencies",
        ),
        (
            lambda graph: graph["groups"]["application-tests"].update(
                {"producer": "governance-validate"}
            ),
            "cannot be overridden",
        ),
    ],
)
def test_consumer_graph_rejects_ambiguous_ownership(mutation, message: str) -> None:
    graph = deepcopy(_graph())
    mutation(graph)
    with pytest.raises(ApplicationAssuranceGraphError, match=message):
        _compile(graph)

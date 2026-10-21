"""Declared train topology is distinct from independently verified closure."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bcf_governance.tooling.governance_validation.common import GovernanceValidationError
from bcf_governance.tooling.governance_validation.supplemental_releases import (
    declared_release_train_terminal,
)


def _catalog():
    phases = ["P32", "P33", "P34", "P35"]
    return {
        "product": {"execution_phases": [
            {"phase_id": phase, "build_block": phase, "release_train": "release_27"}
            for phase in phases
        ]},
        "build": {"phase_sequence": [
            {"phase_id": phase, "build_block": phase,
             "hard_dependencies": [f"P{int(phase[1:]) - 1}"]}
            for phase in phases
        ]},
        "ledger": {
            "active_phase": {"id": "P32", "build_block": "P32"},
            "release_trains": {"release_27": {"target_version": "2.5.0", "status": "active"}},
        },
        "history": {"entries": [{"phase_id": "P31", "release_train": "release_26"}]},
        "version": "2.5.0",
    }


def test_terminal_declaration_does_not_require_or_claim_phase_closure():
    values = _catalog()
    before = deepcopy(values)
    assert declared_release_train_terminal(**values) == "P35"
    assert values == before
    assert "verification_snapshot" not in values["history"]["entries"][0]
    assert values["ledger"]["active_phase"]["id"] == "P32"


def test_terminal_declaration_is_independent_of_authored_list_order():
    values = _catalog()
    values["product"]["execution_phases"].reverse()
    values["build"]["phase_sequence"] = values["build"]["phase_sequence"][2:] + values["build"]["phase_sequence"][:2]
    assert declared_release_train_terminal(**values) == "P35"


def test_single_phase_train_retains_its_declared_terminal():
    values = _catalog()
    values["product"]["execution_phases"] = values["product"]["execution_phases"][:1]
    values["build"]["phase_sequence"] = values["build"]["phase_sequence"][:1]
    assert declared_release_train_terminal(**values) == "P32"


@pytest.mark.parametrize("defect", [
    "duplicate-product", "duplicate-build", "duplicate-history", "missing-build",
    "wrong-build-block", "unknown-active", "wrong-active-block", "wrong-version",
    "ambiguous-version", "supplemental", "unknown-dependency", "self-dependency",
    "duplicate-dependency", "cycle", "multiple-terminals", "missing-history",
    "overlapping-history", "retained-member-without-dependencies", "empty-version",
])
def test_terminal_declaration_rejects_incomplete_or_ambiguous_catalog(defect):
    values = _catalog()
    product, build, ledger, history = (values[key] for key in ("product", "build", "ledger", "history"))
    if defect == "duplicate-product":
        product["execution_phases"].append(deepcopy(product["execution_phases"][0]))
    elif defect == "duplicate-build":
        build["phase_sequence"].append(deepcopy(build["phase_sequence"][0]))
    elif defect == "duplicate-history":
        history["entries"].append(deepcopy(history["entries"][0]))
    elif defect == "missing-build":
        build["phase_sequence"].pop()
    elif defect == "wrong-build-block":
        build["phase_sequence"][0]["build_block"] = "foreign"
    elif defect == "unknown-active":
        ledger["active_phase"]["id"] = "P99"
    elif defect == "wrong-active-block":
        ledger["active_phase"]["build_block"] = "foreign"
    elif defect == "wrong-version":
        values["version"] = "2.3.5"
    elif defect == "ambiguous-version":
        ledger["release_trains"]["other"] = {"target_version": "2.5.0"}
    elif defect == "supplemental":
        ledger["release_trains"]["release_27"]["kind"] = "supplemental_publication"
    elif defect == "unknown-dependency":
        build["phase_sequence"][0]["hard_dependencies"] = ["P99"]
    elif defect == "self-dependency":
        build["phase_sequence"][0]["hard_dependencies"] = ["P32"]
    elif defect == "duplicate-dependency":
        build["phase_sequence"][0]["hard_dependencies"] = ["P31", "P31"]
    elif defect == "cycle":
        build["phase_sequence"][0]["hard_dependencies"] = ["P35"]
    elif defect == "multiple-terminals":
        build["phase_sequence"][-1]["hard_dependencies"] = ["P32"]
    elif defect == "missing-history":
        history["entries"] = []
    elif defect == "overlapping-history":
        history["entries"].append(deepcopy(product["execution_phases"][0]))
    elif defect == "retained-member-without-dependencies":
        history["entries"].append({"phase_id": "P30", "release_train": "release_27"})
    elif defect == "empty-version":
        values["version"] = ""
    with pytest.raises(GovernanceValidationError):
        declared_release_train_terminal(**values)

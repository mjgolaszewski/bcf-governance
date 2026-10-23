"""Maintenance declaration compatibility is distinct from release certification."""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest
import yaml

from bcf_governance.tooling.ci_github_api import GitHubContent
from bcf_governance.tooling.ci_github_identity import MainIdentity
from bcf_governance.tooling.ci_github_release_inputs import require_terminal_release_phase_at_main
from bcf_governance.tooling.governance_validation.common import GovernanceValidationError
from bcf_governance.tooling.governance_validation.supplemental_releases import (
    declared_release_train_terminal,
)


def _maintained_catalog():
    """Minimize retained e39d72a0 P31 ownership, not its complete historical population."""
    block = "adopter-assurance-authority-and-publication-2.3.0"
    return {
        "product": {"execution_phases": [
            {"phase_id": "P31", "build_block": block, "release_train": "release_26"},
        ]},
        "build": {"phase_sequence": [
            {"phase_id": "P31", "build_block": block, "hard_dependencies": ["P30"]},
        ]},
        "ledger": {
            "active_phase": {"id": "P31", "build_block": block,
                             "lifecycle_status": "completed"},
            "release_trains": {
                "release_26": {"target_version": "2.3.0", "status": "completed"},
            },
        },
        "history": {"entries": [{"phase_id": "P30", "release_train": "release_25"}]},
        "version": "2.3.6",
    }


def test_completed_single_phase_maintenance_patch_retains_declared_terminal():
    values = _maintained_catalog()
    before = deepcopy(values)
    assert declared_release_train_terminal(**values) == "P31"
    assert values == before
    assert "verification_snapshot" not in values["history"]["entries"][0]


def test_maintained_patch_terminal_uses_exact_main_and_ignores_candidate(tmp_path, monkeypatch):
    values = _maintained_catalog()
    paths = {
        "product": "plans/product-spec.yml", "build": "plans/build-plan.yml",
        "ledger": "plans/phase-ledger.yml", "history": "plans/phase-history.yml",
    }
    documents = {
        path: {"document": {"path": path}, **values[name]} for name, path in paths.items()
    }
    public = "governance/public-contracts.yml"
    documents[public] = {"document": {"path": public}, "package": {"version": "2.3.6"}}
    (tmp_path / "plans").mkdir()
    (tmp_path / "plans/phase-ledger.yml").write_text("active_phase: {id: P99}\n")
    monkeypatch.chdir(tmp_path)
    reads = []
    main = MainIdentity("101", "main", "a" * 40, "b" * 40)

    def content(repository, path, *, ref):
        assert repository == "owner/repo" and ref == main.checkout_sha
        reads.append(path)
        return GitHubContent(path, "c" * 40, yaml.safe_dump(documents[path]).encode())

    assert require_terminal_release_phase_at_main(
        SimpleNamespace(content=content), repository="owner/repo", main=main,
    ) == "P31"
    assert set(reads) == set(documents)
    assert values["ledger"]["active_phase"]["lifecycle_status"] == "completed"


@pytest.mark.parametrize("defect", [
    "other-minor", "other-major", "lower-patch", "prerelease", "invalid-target",
    "active-train", "planned-train", "active-phase", "missing-phase-status",
    "supplemental-owner", "conflicting-exact-owner", "competing-family-owner",
    "multiple-members", "missing-history", "wrong-build-block",
])
def test_maintenance_fallback_rejects_unqualified_catalog(defect):
    values = _maintained_catalog()
    product, build, ledger = (values[key] for key in ("product", "build", "ledger"))
    train = ledger["release_trains"]["release_26"]
    if defect == "other-minor":
        values["version"] = "2.4.0"
    elif defect == "other-major":
        values["version"] = "3.3.6"
    elif defect == "lower-patch":
        train["target_version"], values["version"] = "2.3.7", "2.3.6"
    elif defect == "prerelease":
        values["version"] = "2.3.6rc1"
    elif defect == "invalid-target":
        train["target_version"] = "2.3"
    elif defect in {"active-train", "planned-train"}:
        train["status"] = defect.split("-")[0]
    elif defect == "active-phase":
        ledger["active_phase"]["lifecycle_status"] = "active"
    elif defect == "missing-phase-status":
        ledger["active_phase"].pop("lifecycle_status")
    elif defect == "supplemental-owner":
        train["kind"] = "supplemental_publication"
    elif defect in {"conflicting-exact-owner", "competing-family-owner"}:
        ledger["release_trains"]["other"] = {
            "target_version": "2.3.6" if defect == "conflicting-exact-owner" else "2.3.1",
            "status": "completed",
        }
    elif defect == "multiple-members":
        product["execution_phases"].append({
            "phase_id": "P32", "build_block": "next", "release_train": "release_26",
        })
        build["phase_sequence"].append({
            "phase_id": "P32", "build_block": "next", "hard_dependencies": ["P31"],
        })
    elif defect == "missing-history":
        values["history"]["entries"] = []
    elif defect == "wrong-build-block":
        build["phase_sequence"][0]["build_block"] = "other"
    with pytest.raises(GovernanceValidationError):
        declared_release_train_terminal(**values)

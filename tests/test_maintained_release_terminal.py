"""Maintenance declaration compatibility is distinct from release certification."""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import yaml

from bcf_governance.tooling.ci_github_api import GitHubContent
from bcf_governance.tooling.ci_github_identity import MainIdentity
from bcf_governance.tooling.ci_github_release_inputs import require_terminal_release_phase_at_main
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

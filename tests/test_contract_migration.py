from __future__ import annotations

from pathlib import Path
import subprocess

import yaml

from bcf_governance.tooling.migrate_contracts import plan_contract_migration
from bcf_governance.tooling.governance_profiles import required_targets


def _repo(tmp_path: Path, *, profile_version: str) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    (repo / "governance-profile.yml").write_text(
        yaml.safe_dump(
            {
                "profile_contract_version": profile_version,
                "profile": {"selected": "standard"},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "--quiet", "-m", "fixture"], check=True)
    return repo


def test_current_contract_needs_no_probabilistic_migration(tmp_path: Path) -> None:
    plan, contract = plan_contract_migration(_repo(tmp_path, profile_version="2.0"))
    assert plan.status == "current"
    assert plan.changed_paths == ()
    assert contract is None


def test_legacy_authority_and_graph_are_reported_together(tmp_path: Path) -> None:
    repo = _repo(tmp_path, profile_version="1.0")
    (repo / "governance").mkdir()
    (repo / "governance/ci-authority.yml").write_text(
        "schema_version: '1.0'\n", encoding="utf-8"
    )
    (repo / "governance/ci-graph.yml").write_text(
        "profile_contract_version: '1.0'\n", encoding="utf-8"
    )
    plan, contract = plan_contract_migration(repo)
    assert plan.status == "blocked"
    assert len(plan.blockers) == 2
    assert "authority 1.0" in plan.blockers[0]
    assert "graph" in plan.blockers[1]
    assert contract is None


def test_required_targets_exclude_only_explicit_not_applicable_gates(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "applicability"
    repo.mkdir()
    (repo / "governance-profile.yml").write_text(
        yaml.safe_dump(
            {
                "release_gate_profile": {
                    "gates": {
                        "required": {"status": "required", "target": "test"},
                        "deferred": {"status": "deferred", "target": "audit"},
                        "optional": {"status": "optional", "target": "package"},
                        "absent": {
                            "status": "not_applicable",
                            "target": "browser-test",
                        },
                    }
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    assert required_targets(repo, "standard", contract_version="2.0") == {
        "audit",
        "package",
        "semantic-ownership",
        "test",
    }

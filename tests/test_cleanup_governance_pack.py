from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
CLEANUP = REPO_ROOT / "scripts" / "cleanup_governance_pack.py"


def _load_cleanup_module():
    spec = importlib.util.spec_from_file_location("cleanup_governance_pack", CLEANUP)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run_cleanup(target: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CLEANUP),
            "--repo-root",
            str(target),
            *args,
        ],
        capture_output=True,
        text=True,
    )


def test_cleanup_plan_reports_safe_moves_and_manual_work(tmp_path: Path) -> None:
    cleanup = _load_cleanup_module()
    repo = tmp_path / "repo"
    (repo / "docs/audits").mkdir(parents=True)
    (repo / "docs/audits/security.md").write_text("# Security\n", encoding="utf-8")
    (repo / "governance/parity-reviews").mkdir(parents=True)
    (repo / "governance/parity-reviews/p1.md").write_text("# P1\n", encoding="utf-8")
    (repo / "governance/repo-cleanup-contract.yml").write_text(
        "document: {}\n", encoding="utf-8"
    )
    (repo / "ops/shared-runtime").mkdir(parents=True)
    (repo / "ops/shared-runtime/AGENTS.yml").write_text("document: {}\n", encoding="utf-8")
    (repo / "plans").mkdir()

    report = cleanup.plan_cleanup(repo)

    assert report.status == "actionable"
    assert report.cleanup_contract == "governance/repo-cleanup-contract.yml"
    assert any(action.destination == "audits/security.md" for action in report.actions)
    assert any(action.destination == "audits/parity-reviews/p1.md" for action in report.actions)
    assert any(action.destination == "audits/README.md" for action in report.actions)
    assert any(action.path == "ops/shared-runtime/AGENTS.yml" for action in report.manual_actions)
    assert any(action.path == "plans" for action in report.manual_actions)


def test_cleanup_apply_moves_audits_and_rewrites_references(tmp_path: Path) -> None:
    cleanup = _load_cleanup_module()
    repo = tmp_path / "repo"
    (repo / "docs/audits").mkdir(parents=True)
    (repo / "docs/audits/security.md").write_text("# Security\n", encoding="utf-8")
    (repo / "docs/guide.md").parent.mkdir(parents=True, exist_ok=True)
    (repo / "docs/guide.md").write_text(
        "See docs/audits/security.md and docs/audits/.\n",
        encoding="utf-8",
    )

    report = cleanup.apply_cleanup(repo, assume_yes=True)

    assert report.applied
    assert (repo / "audits/security.md").exists()
    assert (repo / "audits/README.md").exists()
    assert not (repo / "docs/audits/security.md").exists()
    assert "audits/security.md" in (repo / "docs/guide.md").read_text(encoding="utf-8")
    assert "docs/audits" not in (repo / "docs/guide.md").read_text(encoding="utf-8")
    assert "docs/guide.md" in report.rewritten_files


def test_cleanup_command_outputs_compact_json(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "docs/audits").mkdir(parents=True)
    (repo / "docs/audits/security.md").write_text("# Security\n", encoding="utf-8")

    result = _run_cleanup(repo, "--format", "json", "--compact")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "actionable"
    assert payload["actions"][0]["kind"] == "create_audit_readme"


def test_cleanup_remove_governance_pack_deletes_owned_artifacts_only(tmp_path: Path) -> None:
    cleanup = _load_cleanup_module()
    repo = tmp_path / "repo"
    owned_files = [
        "AGENTS.yml",
        "AGENTS.md",
        "CLAUDE.md",
        "MEMORY.yml",
        "architecture-boundaries.yml",
        "governance-profile.yml",
        "Makefile.fragment",
        "requirements-governance.txt",
        ".github/workflows/governance.yml",
        "docs/OPERATIONS.md",
        "backend/tests/architecture/test_boundaries_ast.py",
        "scripts/check_governance_exposure.py",
        "scripts/scaffold_governance_artifacts.py",
        "scripts/validate_governance_yaml.py",
    ]
    owned_dirs = [
        "audits",
        "contracts/observability",
        "governance",
        "phases",
        "plans",
        "schemas",
        "scripts/governance_validation",
    ]
    for relative_path in owned_files:
        path = repo / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("bcf\n", encoding="utf-8")
    for relative_path in owned_dirs:
        path = repo / relative_path
        path.mkdir(parents=True, exist_ok=True)
        (path / "owned.yml").write_text("bcf: true\n", encoding="utf-8")
    (repo / "app.py").write_text("print('keep')\n", encoding="utf-8")
    app_workflow = repo / ".github/workflows/app.yml"
    app_workflow.write_text("name: app\n", encoding="utf-8")
    mixed_workflow = repo / ".github/workflows/mixed.yml"
    mixed_workflow.write_text("run: make governance-validate\n", encoding="utf-8")

    plan = cleanup.plan_cleanup(repo, remove_governance_pack=True)

    assert plan.status == "actionable"
    assert all(action.kind == "remove_governance_artifact" for action in plan.actions)
    assert {action.path for action in plan.manual_actions} == {".github/workflows/mixed.yml"}
    assert "remove_governance_pack" in plan.warnings[0]

    report = cleanup.apply_cleanup(repo, assume_yes=True, remove_governance_pack=True)

    assert report.applied
    for relative_path in [*owned_files, *owned_dirs]:
        assert not (repo / relative_path).exists()
    assert (repo / "app.py").read_text(encoding="utf-8") == "print('keep')\n"
    assert app_workflow.exists()
    assert mixed_workflow.exists()
    assert any("manual BCF references remain" in warning for warning in report.warnings)


def test_cleanup_remove_governance_pack_cli_outputs_json(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "AGENTS.yml").write_text("document: {}\n", encoding="utf-8")

    result = _run_cleanup(repo, "--remove-governance-pack", "--format", "json", "--compact")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "actionable"
    assert payload["actions"] == [
        {
            "kind": "remove_governance_artifact",
            "source": "AGENTS.yml",
            "destination": None,
            "reason": "remove BCF governance pack-owned artifact or dedicated CI gate",
            "safe_to_apply": True,
        }
    ]


def _write_yaml(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _init_git_repo(repo: Path) -> str:
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "test@example.test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "seed"], cwd=repo, check=True, capture_output=True, text=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_cleanup_archives_closed_phase_triplet_and_writes_history(tmp_path: Path) -> None:
    cleanup = _load_cleanup_module()
    repo = tmp_path / "repo"
    _write_yaml(
        repo / "governance/artifact-manifest.yml",
        {
            "phase_retention_policy": {
                "history_path": "plans/phase-history.yml",
                "active_window": {
                    "include_active": True,
                    "include_next": True,
                    "keep_recent_closed": 0,
                },
                "archive": {
                    "root": "governance/archive/phase-artifacts/",
                    "closed_phase_statuses": ["verified", "closed"],
                    "preserve_hotfix_logs": True,
                },
            }
        },
    )
    _write_yaml(
        repo / "plans/build-plan.yml",
        {
            "phase_sequence": [
                {"phase_id": "P01", "build_block": "foundation"},
                {"phase_id": "P02", "build_block": "delivery"},
            ]
        },
    )
    _write_yaml(repo / "plans/phase-ledger.yml", {"active_phase": {"id": "P02"}})
    _write_yaml(
        repo / "plans/product-spec.yml",
        {
            "execution_phases": [
                {
                    "phase_id": "P01",
                    "build_block": "foundation",
                    "release_train": "release_1",
                },
                {
                    "phase_id": "P02",
                    "build_block": "delivery",
                    "release_train": "release_1",
                },
            ]
        },
    )
    _write_yaml(
        repo / "plans/phase-01-plan.yml",
        {"phase": {"id": "P01", "build_block": "foundation"}},
    )
    _write_yaml(
        repo / "plans/phase-01-workitems.yml",
        {"workitems": [{"id": "P01-P0-01", "status": "DONE"}]},
    )
    _write_yaml(
        repo / "phases/phase-01-log.yml",
        {
            "document": {"status": "verified"},
            "phase": {"id": "P01", "build_block": "foundation"},
            "summary": {"outcome": "verified", "highlights": ["foundation complete"]},
            "execution_evidence": {"executed_commands": ["make test"]},
        },
    )

    plan = cleanup.plan_cleanup(repo, archive_closed_phases=True)
    archive_sources = {
        action.source for action in plan.actions if action.kind == "archive_phase_artifact"
    }
    assert archive_sources == {
        "plans/phase-01-plan.yml",
        "plans/phase-01-workitems.yml",
        "phases/phase-01-log.yml",
    }

    report = cleanup.apply_cleanup(repo, assume_yes=True, archive_closed_phases=True)

    assert report.applied
    assert not (repo / "plans/phase-01-plan.yml").exists()
    assert not (repo / "plans/phase-01-workitems.yml").exists()
    assert not (repo / "phases/phase-01-log.yml").exists()
    assert (repo / "governance/archive/phase-artifacts/phase-01-plan.yml").exists()
    assert (repo / "governance/archive/phase-artifacts/phase-01-workitems.yml").exists()
    assert (repo / "governance/archive/phase-artifacts/phase-01-log.yml").exists()

    history = yaml.safe_load((repo / "plans/phase-history.yml").read_text(encoding="utf-8"))
    entry = history["entries"][0]
    assert entry["phase_id"] == "P01"
    assert entry["status"] == "verified"
    assert entry["summary"] == ["foundation complete"]
    assert entry["validation"] == ["make test"]
    assert {
        artifact["path"] for artifact in entry["archived_artifacts"]
    } == {
        "governance/archive/phase-artifacts/phase-01-plan.yml",
        "governance/archive/phase-artifacts/phase-01-workitems.yml",
        "governance/archive/phase-artifacts/phase-01-log.yml",
    }
    assert all(len(artifact["sha256"]) == 64 for artifact in entry["archived_artifacts"])


def test_cleanup_archive_mode_persists_policy_and_ignores_archive_root(tmp_path: Path) -> None:
    cleanup = _load_cleanup_module()
    repo = tmp_path / "repo"
    _write_yaml(
        repo / "governance/artifact-manifest.yml",
        {
            "phase_retention_policy": {
                "history_path": "plans/phase-history.yml",
                "active_window": {
                    "include_active": True,
                    "include_next": True,
                    "keep_recent_closed": 0,
                },
                "archive": {
                    "root": "governance/archive/phase-artifacts/",
                    "closed_phase_statuses": ["verified", "closed"],
                    "preserve_hotfix_logs": True,
                },
            }
        },
    )
    _write_yaml(
        repo / "plans/build-plan.yml",
        {"phase_sequence": [{"phase_id": "P01"}, {"phase_id": "P02"}]},
    )
    _write_yaml(repo / "plans/phase-ledger.yml", {"active_phase": {"id": "P02"}})
    _write_yaml(repo / "plans/product-spec.yml", {"execution_phases": [{"phase_id": "P01"}]})
    _write_yaml(repo / "plans/phase-01-plan.yml", {"phase": {"build_block": "foundation"}})
    _write_yaml(repo / "plans/phase-01-workitems.yml", {"workitems": []})
    _write_yaml(
        repo / "phases/phase-01-log.yml",
        {"document": {"status": "verified"}, "phase": {"build_block": "foundation"}},
    )

    report = cleanup.apply_cleanup(
        repo,
        assume_yes=True,
        phase_retention_mode="archive",
    )

    assert report.applied
    manifest = yaml.safe_load((repo / "governance/artifact-manifest.yml").read_text(encoding="utf-8"))
    assert manifest["phase_retention_policy"]["mode"] == "archive"
    gitignore = (repo / ".gitignore").read_text(encoding="utf-8")
    assert "governance/archive/phase-artifacts/*" in gitignore
    assert "!governance/archive/phase-artifacts/.gitkeep" in gitignore
    history = yaml.safe_load((repo / "plans/phase-history.yml").read_text(encoding="utf-8"))
    assert history["entries"][0]["retention_source"] == "archive"


def test_cleanup_git_history_mode_removes_triplet_after_verifying_head(
    tmp_path: Path,
) -> None:
    cleanup = _load_cleanup_module()
    repo = tmp_path / "repo"
    _write_yaml(
        repo / "governance/artifact-manifest.yml",
        {
            "phase_retention_policy": {
                "history_path": "plans/phase-history.yml",
                "active_window": {
                    "include_active": True,
                    "include_next": True,
                    "keep_recent_closed": 0,
                },
                "archive": {
                    "root": "governance/archive/phase-artifacts/",
                    "closed_phase_statuses": ["verified", "closed"],
                    "preserve_hotfix_logs": True,
                },
            }
        },
    )
    _write_yaml(
        repo / "plans/build-plan.yml",
        {
            "phase_sequence": [
                {"phase_id": "P01", "build_block": "foundation"},
                {"phase_id": "P02", "build_block": "delivery"},
            ]
        },
    )
    _write_yaml(repo / "plans/phase-ledger.yml", {"active_phase": {"id": "P02"}})
    _write_yaml(
        repo / "plans/product-spec.yml",
        {
            "execution_phases": [
                {"phase_id": "P01", "build_block": "foundation"},
                {"phase_id": "P02", "build_block": "delivery"},
            ]
        },
    )
    _write_yaml(repo / "plans/phase-01-plan.yml", {"phase": {"build_block": "foundation"}})
    _write_yaml(repo / "plans/phase-01-workitems.yml", {"workitems": []})
    _write_yaml(
        repo / "phases/phase-01-log.yml",
        {
            "document": {"status": "verified"},
            "phase": {"build_block": "foundation"},
            "summary": {"highlights": ["done"]},
        },
    )
    commit = _init_git_repo(repo)

    report = cleanup.apply_cleanup(repo, assume_yes=True, phase_retention_mode="git-history")

    assert report.applied
    assert not (repo / "plans/phase-01-plan.yml").exists()
    assert not (repo / "plans/phase-01-workitems.yml").exists()
    assert not (repo / "phases/phase-01-log.yml").exists()
    history = yaml.safe_load((repo / "plans/phase-history.yml").read_text(encoding="utf-8"))
    entry = history["entries"][0]
    assert entry["retention_source"] == "git_history"
    assert entry["retention_ref"] == commit
    assert {artifact["path"] for artifact in entry["archived_artifacts"]} == {
        "plans/phase-01-plan.yml",
        "plans/phase-01-workitems.yml",
        "phases/phase-01-log.yml",
    }
    assert all(artifact["git_commit"] == commit for artifact in entry["archived_artifacts"])


def test_cleanup_phase_history_stays_within_context_budget_for_multiple_phases(
    tmp_path: Path,
) -> None:
    cleanup = _load_cleanup_module()
    repo = tmp_path / "repo"
    phase_ids = [f"P{number:02d}" for number in range(1, 5)]
    _write_yaml(
        repo / "governance/artifact-manifest.yml",
        {
            "phase_retention_policy": {
                "history_path": "plans/phase-history.yml",
                "active_window": {
                    "include_active": True,
                    "include_next": True,
                    "keep_recent_closed": 0,
                },
                "archive": {
                    "root": "governance/archive/phase-artifacts/",
                    "closed_phase_statuses": ["verified", "closed"],
                    "preserve_hotfix_logs": True,
                },
            },
            "context_budgets": {
                "agent_required_files": {"plans/phase-history.yml": 40}
            },
        },
    )
    _write_yaml(
        repo / "plans/build-plan.yml",
        {
            "phase_sequence": [
                {"phase_id": phase_id, "build_block": f"block_{phase_id.lower()}"}
                for phase_id in phase_ids
            ]
        },
    )
    _write_yaml(repo / "plans/phase-ledger.yml", {"active_phase": {"id": "P04"}})
    _write_yaml(
        repo / "plans/product-spec.yml",
        {
            "execution_phases": [
                {
                    "phase_id": phase_id,
                    "build_block": f"block_{phase_id.lower()}",
                    "release_train": "release_1",
                }
                for phase_id in phase_ids
            ]
        },
    )
    for phase_id in phase_ids:
        phase_number = int(phase_id[1:])
        stem = f"phase-{phase_number:02d}"
        build_block = f"block_{phase_id.lower()}"
        _write_yaml(repo / f"plans/{stem}-plan.yml", {"phase": {"id": phase_id, "build_block": build_block}})
        _write_yaml(repo / f"plans/{stem}-workitems.yml", {"workitems": [{"id": f"{phase_id}-W01", "status": "DONE"}]})
        _write_yaml(
            repo / f"phases/{stem}-log.yml",
            {
                "document": {"status": "verified"},
                "phase": {"id": phase_id, "build_block": build_block},
                "summary": {"outcome": "verified", "highlights": [f"{phase_id} done"]},
                "execution_evidence": {"executed_commands": ["make test"]},
            },
        )

    cleanup.apply_cleanup(repo, assume_yes=True, archive_closed_phases=True)

    history_lines = (repo / "plans/phase-history.yml").read_text(encoding="utf-8").splitlines()
    assert len(history_lines) <= 40

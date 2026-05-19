from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


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
    (repo / "ops/shared-runtime").mkdir(parents=True)
    (repo / "ops/shared-runtime/AGENTS.yml").write_text("document: {}\n", encoding="utf-8")
    (repo / "plans").mkdir()

    report = cleanup.plan_cleanup(repo)

    assert report.status == "actionable"
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

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from bcf_governance.tooling.evidence_session_cleanup import (
    SessionCleanupError,
    apply_session_cleanup,
    plan_session_cleanup,
)
from bcf_governance.tooling.evidence_sessions import allocate_session

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
try:
    from scripts.cleanup_ci_resources import (
        discover_resources,
        remove_resources,
        validate_run_id,
    )
finally:
    sys.path.pop(0)


class DockerRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        if "inspect" in command:
            object_id = command[-1]
            return subprocess.CompletedProcess(
                command, 0, f"{object_id}\trun-12345\n", ""
            )
        outputs = {
            "ps": "container-owned\n",
            "network": "network-owned\n",
            "volume": "volume-owned\n",
            "image": "image-owned\nimage-owned\n",
        }
        kind = command[1]
        return subprocess.CompletedProcess(command, 0, outputs.get(kind, ""), "")


@pytest.mark.parametrize("run_id", ["", "all", "*", "bad id", "../../broad"])
def test_ci_cleanup_rejects_unsafe_run_ids(run_id: str) -> None:
    with pytest.raises(ValueError):
        validate_run_id(run_id)


def test_ci_cleanup_discovers_only_exact_label_owned_resources() -> None:
    runner = DockerRunner()

    resources = discover_resources("run-12345", runner)

    assert {(item.kind, item.object_id) for item in resources} == {
        ("container", "container-owned"),
        ("network", "network-owned"),
        ("volume", "volume-owned"),
        ("image", "image-owned"),
    }
    assert all(
        "label=io.bcf-governance.ci-run=run-12345" in command for command in runner.commands
    )


def test_ci_cleanup_removes_only_resources_returned_by_owned_plan() -> None:
    runner = DockerRunner()
    resources = discover_resources("run-12345", runner)
    runner.commands.clear()

    remove_resources(resources, runner)

    assert runner.commands == [
        [
            "docker", "container", "inspect", "--format",
            '{{.Id}}\t{{index .Config.Labels "io.bcf-governance.ci-run"}}',
            "container-owned",
        ],
        ["docker", "rm", "-fv", "container-owned"],
        [
            "docker", "network", "inspect", "--format",
            '{{.Id}}\t{{index .Labels "io.bcf-governance.ci-run"}}',
            "network-owned",
        ],
        ["docker", "network", "rm", "network-owned"],
        [
            "docker", "volume", "inspect", "--format",
            '{{.Name}}\t{{index .Labels "io.bcf-governance.ci-run"}}',
            "volume-owned",
        ],
        ["docker", "volume", "rm", "volume-owned"],
        [
            "docker", "image", "inspect", "--format",
            '{{.Id}}\t{{index .Config.Labels "io.bcf-governance.ci-run"}}',
            "image-owned",
        ],
        ["docker", "image", "rm", "image-owned"],
    ]
    assert all("prune" not in command for command in runner.commands)


def test_ci_cleanup_rejects_forged_ownership_before_delete() -> None:
    runner = DockerRunner()
    resources = discover_resources("run-12345", runner)
    runner.commands.clear()

    def forged(command: list[str]) -> subprocess.CompletedProcess[str]:
        runner.commands.append(command)
        return subprocess.CompletedProcess(command, 0, f"{command[-1]}\tother-run\n", "")

    with pytest.raises(RuntimeError, match="ownership changed"):
        remove_resources(resources, forged)

    assert len(runner.commands) == 1
    assert "inspect" in runner.commands[0]


@pytest.mark.parametrize("unsafe_id", ["*", "../../all", "bad id", "name/escape"])
def test_ci_cleanup_rejects_unsafe_daemon_resource_ids(unsafe_id: str) -> None:
    def unsafe(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, unsafe_id + "\n", "")

    with pytest.raises(RuntimeError, match="unsafe resource identity"):
        discover_resources("run-12345", unsafe)


def _session_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "governance").mkdir(parents=True)
    (repo / ".gitignore").write_text(".artifacts/\n", encoding="utf-8")
    (repo / "governance-profile.yml").write_text(
        "profile:\n  selected: standard\nprofile_contract_version: '2.0'\n",
        encoding="utf-8",
    )
    (repo / "governance/artifact-manifest.yml").write_text(
        "ephemeral_evidence:\n"
        "  roots: [artifacts/, .artifacts/]\n"
        "  durable_reference_required: true\n"
        "  session_retention_hours: 168\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "cleanup@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Cleanup"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "fixture"], cwd=repo, check=True)
    return repo


def test_evidence_session_cleanup_obeys_retention_and_revalidates(tmp_path: Path) -> None:
    repo = _session_repo(tmp_path)
    session = allocate_session(repo, repo / ".artifacts/bcf", ["test"])
    payload = dict(session.payload)
    payload["created_at"] = "2026-08-01T00:00:00Z"
    os.chmod(session.manifest_path, 0o600)
    session.manifest_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.chmod(session.manifest_path, 0o400)
    evaluated_at = datetime(2026, 8, 30, tzinfo=timezone.utc)

    plan = plan_session_cleanup(repo, evaluated_at=evaluated_at)

    assert plan.status == "actionable"
    assert [action.session_id for action in plan.actions] == [session.root.name]
    report = apply_session_cleanup(repo, evaluated_at=evaluated_at)
    assert report.status == "changed"
    assert not session.root.exists()
    assert (repo / ".artifacts/bcf/sessions").is_dir()


def test_evidence_session_cleanup_rejects_symlink_entries(tmp_path: Path) -> None:
    repo = _session_repo(tmp_path)
    sessions = repo / ".artifacts/bcf/sessions"
    sessions.mkdir(parents=True)
    target = tmp_path / "outside"
    target.mkdir()
    (sessions / "unsafe").symlink_to(target, target_is_directory=True)

    with pytest.raises(SessionCleanupError, match="unsafe entry"):
        plan_session_cleanup(repo)

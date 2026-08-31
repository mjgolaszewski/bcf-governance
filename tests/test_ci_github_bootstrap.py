from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from bcf_governance.tooling.ci_github_bootstrap import install_controller
from bcf_governance.tooling.ci_github_identity import GitHubControllerError


COMMIT = "a" * 40
TREE = "b" * 40


class FakeAPI:
    def __init__(self, provider_digest: str) -> None:
        self.provider_digest = provider_digest

    def run(self, repository: str, run_id: object) -> dict[str, object]:
        assert repository == "owner/repo" and str(run_id) == "100"
        return {
            "id": 100,
            "run_attempt": 1,
            "head_sha": COMMIT,
            "head_branch": "main",
            "repository": {"id": 42},
            "head_repository": {"id": 42},
        }

    def artifacts(self, repository: str, run_id: object) -> tuple[dict[str, object], ...]:
        assert repository == "owner/repo" and str(run_id) == "100"
        return ({
            "id": 200,
            "name": f"bcf-trusted-control-{COMMIT}-1",
            "digest": self.provider_digest,
            "expired": False,
        },)


def _artifact(root: Path) -> tuple[Path, str]:
    root.mkdir()
    wheel = root / "bcf_governance-0.7.1-py3-none-any.whl"
    wheel.write_bytes(b"controller-wheel")
    metadata = root / "CONTROL-METADATA.json"
    metadata.write_text(json.dumps({
        "schema_version": "1.0",
        "commit_sha": COMMIT,
        "tree_sha": TREE,
        "workflow_run_id": "100",
        "workflow_run_attempt": "1",
    }, sort_keys=True, separators=(",", ":")) + "\n")
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  ./{path.name}"
        for path in (wheel, metadata)
    ]
    (root / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    return wheel, hashlib.sha256(wheel.read_bytes()).hexdigest()


def test_bootstrap_authenticates_and_installs_one_exact_offline_controller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "artifact"
    wheel, wheel_digest = _artifact(artifact)
    python = tmp_path / "python"
    python.write_text("binary")
    python.chmod(0o700)
    tool_cache = tmp_path / "tool-cache"
    tool_cache.mkdir()
    calls: list[list[str]] = []

    def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[1:3] == ["-m", "venv"]:
            root = Path(command[-1])
            (root / "bin").mkdir(parents=True)
            (root / "bin/python").write_text("python")
        elif "pip" in command:
            executable = Path(command[0]).with_name("bcf")
            executable.write_text("bcf")
            executable.chmod(0o700)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", run)
    provider_digest = "sha256:" + "c" * 64
    result = install_controller(
        FakeAPI(provider_digest),  # type: ignore[arg-type]
        repository="owner/repo",
        artifact_dir=artifact,
        artifact_id=200,
        artifact_name=f"bcf-trusted-control-{COMMIT}-1",
        provider_digest=provider_digest,
        producer_run_id=100,
        producer_run_attempt=1,
        repository_id=42,
        commit_sha=COMMIT,
        tree_sha=TREE,
        wheel_sha256=wheel_digest,
        selected_python=python,
        tool_cache=tool_cache,
    )

    assert result["status"] == "installed"
    install_root = tool_cache / "bcf-governance" / COMMIT
    assert json.loads((install_root / "INSTALL-METADATA.json").read_text())["artifact_id"] == "200"
    pip_call = next(command for command in calls if "pip" in command)
    assert pip_call[-1] == str(wheel)
    assert "--no-index" in pip_call


@pytest.mark.parametrize("mutation", ["provider-digest", "run-attempt", "wheel-digest"])
def test_bootstrap_rejects_inexact_custody_before_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    artifact = tmp_path / "artifact"
    _, wheel_digest = _artifact(artifact)
    python = tmp_path / "python"
    python.write_text("binary")
    python.chmod(0o700)
    tool_cache = tmp_path / "tool-cache"
    tool_cache.mkdir()
    calls: list[list[str]] = []

    def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[1:3] == ["-m", "venv"]:
            root = Path(command[-1])
            (root / "bin").mkdir(parents=True)
            (root / "bin/python").write_text("python")
        elif "pip" in command:
            executable = Path(command[0]).with_name("bcf")
            executable.write_text("bcf")
            executable.chmod(0o700)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", run)
    expected_provider = "sha256:" + "c" * 64
    with pytest.raises(GitHubControllerError):
        install_controller(
            FakeAPI(expected_provider),  # type: ignore[arg-type]
            repository="owner/repo",
            artifact_dir=artifact,
            artifact_id=200,
            artifact_name=f"bcf-trusted-control-{COMMIT}-1",
            provider_digest=("sha256:" + "d" * 64) if mutation == "provider-digest" else expected_provider,
            producer_run_id=100,
            producer_run_attempt=2 if mutation == "run-attempt" else 1,
            repository_id=42,
            commit_sha=COMMIT,
            tree_sha=TREE,
            wheel_sha256=("e" * 64) if mutation == "wheel-digest" else wheel_digest,
            selected_python=python,
            tool_cache=tool_cache,
        )
    assert not (tool_cache / "bcf-governance" / COMMIT).exists()
    assert calls == []

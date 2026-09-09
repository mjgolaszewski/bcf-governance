from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

import pytest

from bcf_governance.tooling.ci_github_bootstrap import (
    install_controller,
    verify_controller_dependency_closure,
    verify_controller_inventory,
)
from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from tests._wheel_fixture import write_wheel


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
    write_wheel(wheel, name="bcf-governance", version="0.7.1")
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


def _dependency_artifact(root: Path) -> None:
    root.mkdir()
    write_wheel(
        root / "bcf_governance-1.0.3-py3-none-any.whl",
        name="bcf-governance",
        version="1.0.3",
        requirements=(
            "alpha>=2",
            "optional; extra == 'dev'",
            "fixture-only; platform_system == 'FixtureOS'",
        ),
    )
    write_wheel(
        root / "alpha-2.0-py3-none-any.whl",
        name="alpha",
        version="2.0",
        requirements=("gamma==3",),
    )
    write_wheel(root / "gamma-3.0-py3-none-any.whl", name="gamma", version="3.0")
    write_wheel(
        root / "fixture_only-4.0-py3-none-any.whl",
        name="fixture-only",
        version="4.0",
    )
    (root / "CONTROL-METADATA.json").write_text(
        json.dumps(
            {
                "schema_version": "1.1",
                "commit_sha": COMMIT,
                "tree_sha": TREE,
                "workflow_run_id": "100",
                "workflow_run_attempt": "1",
                "extra": "",
                "implementation_name": "cpython",
                "implementation_version": "3.12.14",
                "os_name": "posix",
                "platform_machine": "x86_64",
                "platform_python_implementation": "CPython",
                "platform_release": "fixture-release",
                "platform_system": "FixtureOS",
                "platform_version": "fixture-version",
                "python_full_version": "3.12.14",
                "python_version": "3.12",
                "sys_platform": "linux",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_controller_dependency_closure_is_recursive_and_marker_aware(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifact"
    _dependency_artifact(root)

    assert verify_controller_dependency_closure(root) == {
        "alpha": "2.0",
        "bcf-governance": "1.0.3",
        "fixture-only": "4.0",
        "gamma": "3.0",
    }


def test_controller_dependency_markers_use_recorded_build_environment(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifact"
    _dependency_artifact(root)
    (root / "fixture_only-4.0-py3-none-any.whl").unlink()

    with pytest.raises(GitHubControllerError, match="fixture-only"):
        verify_controller_dependency_closure(root)


@pytest.mark.parametrize(
    "mutation",
    ["missing", "version", "duplicate", "direct-url", "malformed", "environment", "metadata"],
)
def test_controller_dependency_closure_rejects_every_ambiguous_runtime(
    tmp_path: Path, mutation: str
) -> None:
    root = tmp_path / "artifact"
    _dependency_artifact(root)
    if mutation == "missing":
        (root / "gamma-3.0-py3-none-any.whl").unlink()
    elif mutation == "version":
        (root / "alpha-2.0-py3-none-any.whl").unlink()
        write_wheel(root / "alpha-1.0-py3-none-any.whl", name="alpha", version="1.0")
    elif mutation == "duplicate":
        write_wheel(root / "alpha-2.1-py3-none-any.whl", name="alpha", version="2.1")
    elif mutation in {"direct-url", "malformed"}:
        write_wheel(
            root / "bcf_governance-1.0.3-py3-none-any.whl",
            name="bcf-governance",
            version="1.0.3",
            requirements=(
                "remote @ https://example.invalid/remote.whl"
                if mutation == "direct-url"
                else "alpha=>2",
            ),
        )
    elif mutation == "environment":
        metadata = root / "CONTROL-METADATA.json"
        value = json.loads(metadata.read_text(encoding="utf-8"))
        del value["platform_system"]
        metadata.write_text(json.dumps(value), encoding="utf-8")
    else:
        with zipfile.ZipFile(
            root / "alpha-2.0-py3-none-any.whl", "a"
        ) as archive:
            archive.writestr("duplicate-2.0.dist-info/METADATA", "Name: duplicate\nVersion: 2.0\n")

    with pytest.raises(GitHubControllerError, match="controller (dependency|metadata)"):
        verify_controller_dependency_closure(root)


def test_controller_inventory_rejects_missing_dependency_before_admission(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifact"
    _dependency_artifact(root)
    (root / "gamma-3.0-py3-none-any.whl").unlink()
    admitted = sorted(root.glob("*.whl")) + [root / "CONTROL-METADATA.json"]
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in admitted
        ),
        encoding="utf-8",
    )

    with pytest.raises(GitHubControllerError, match="controller dependency wheel is missing"):
        verify_controller_inventory(root)


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

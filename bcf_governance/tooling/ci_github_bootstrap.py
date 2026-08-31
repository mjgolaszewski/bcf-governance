"""Trusted offline controller artifact authentication and installation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any

from .ci_github_api import GitHubAPI
from .ci_github_identity import GitHubControllerError, positive_int


def _regular(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise GitHubControllerError(f"{label} must be a regular file")
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_inventory(root: Path) -> tuple[Path, dict[str, str]]:
    if root.is_symlink() or not root.is_dir():
        raise GitHubControllerError("controller artifact root must be a regular directory")
    sums = _regular(root / "SHA256SUMS", "controller checksum inventory")
    declared: dict[str, str] = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  (?:\./)?([A-Za-z0-9_.+-]+)", line)
        if match is None or match.group(2) in declared:
            raise GitHubControllerError("controller checksum inventory is invalid")
        declared[match.group(2)] = match.group(1)
    actual = {
        path.name: path
        for path in root.iterdir()
        if path.name != "SHA256SUMS" and not path.name.startswith(".")
    }
    if set(actual) != set(declared) or any(
        path.is_symlink() or not path.is_file() for path in actual.values()
    ):
        raise GitHubControllerError("controller artifact file inventory is not exact")
    for name, path in actual.items():
        if _sha256(path) != declared[name]:
            raise GitHubControllerError(f"controller artifact digest mismatch: {name}")
    wheels = [path for name, path in actual.items() if name.startswith("bcf_governance-")]
    if len(wheels) != 1 or wheels[0].suffix != ".whl":
        raise GitHubControllerError("controller wheel inventory must contain exactly one wheel")
    return wheels[0], declared


def _metadata(path: Path) -> dict[str, str]:
    try:
        value = json.loads(_regular(path, "controller metadata").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise GitHubControllerError("controller metadata is invalid JSON") from exc
    if not isinstance(value, dict) or any(not isinstance(item, str) for item in value.values()):
        raise GitHubControllerError("controller metadata must contain string fields")
    return value


def _safe_root(root: Path, tool_cache: Path, commit_sha: str) -> Path:
    if tool_cache.is_symlink() or not tool_cache.is_dir():
        raise GitHubControllerError("runner tool cache must be a regular directory")
    expected = tool_cache.resolve() / "bcf-governance" / commit_sha
    if root != expected or root == tool_cache.resolve():
        raise GitHubControllerError("controller install root escaped the tool cache")
    return expected


def install_controller(
    api: GitHubAPI,
    *,
    repository: str,
    artifact_dir: Path,
    artifact_id: object,
    artifact_name: str,
    provider_digest: str,
    producer_run_id: object,
    producer_run_attempt: object,
    repository_id: object,
    commit_sha: str,
    tree_sha: str,
    wheel_sha256: str,
    selected_python: Path,
    tool_cache: Path,
) -> dict[str, Any]:
    """Authenticate one exact controller artifact and install it without network access."""

    if not re.fullmatch(r"[a-f0-9]{40}", commit_sha) or not re.fullmatch(
        r"[a-f0-9]{40}", tree_sha
    ):
        raise GitHubControllerError("controller commit and tree must be exact Git identities")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", provider_digest) or not re.fullmatch(
        r"[a-f0-9]{64}", wheel_sha256
    ):
        raise GitHubControllerError("controller provider and wheel digests must be SHA-256")
    run_id = str(positive_int(producer_run_id, field="controller producer run ID"))
    attempt = positive_int(producer_run_attempt, field="controller producer run attempt")
    expected_repository_id = str(
        positive_int(repository_id, field="controller repository ID")
    )
    run = api.run(repository, run_id)
    if {
        "run_attempt": int(run.get("run_attempt", 0)),
        "head_sha": str(run.get("head_sha")),
        "head_branch": str(run.get("head_branch")),
        "repository_id": str(run.get("repository", {}).get("id")),
        "head_repository_id": str(run.get("head_repository", {}).get("id")),
    } != {
        "run_attempt": attempt,
        "head_sha": commit_sha,
        "head_branch": "main",
        "repository_id": expected_repository_id,
        "head_repository_id": expected_repository_id,
    }:
        raise GitHubControllerError("controller producer run identity is not exact")
    exact_artifacts = [
        value
        for value in api.artifacts(repository, run_id)
        if str(value.get("id")) == str(artifact_id)
        and value.get("name") == artifact_name
        and value.get("digest") == provider_digest
        and value.get("expired") is False
    ]
    if len(exact_artifacts) != 1:
        raise GitHubControllerError("controller provider artifact identity is not exact")
    wheel, _ = _verify_inventory(artifact_dir.resolve())
    if _sha256(wheel) != wheel_sha256:
        raise GitHubControllerError("controller wheel digest does not match custody")
    if _metadata(artifact_dir / "CONTROL-METADATA.json") != {
        "schema_version": "1.0",
        "commit_sha": commit_sha,
        "tree_sha": tree_sha,
        "workflow_run_id": run_id,
        "workflow_run_attempt": str(attempt),
    }:
        raise GitHubControllerError("controller metadata is not the pinned exact-main subject")
    python = _regular(selected_python.resolve(), "selected bootstrap Python")
    cache = tool_cache.resolve()
    install_root = _safe_root(cache / "bcf-governance" / commit_sha, cache, commit_sha)
    install_metadata = install_root / "INSTALL-METADATA.json"
    expected_install = {
        "artifact_id": str(artifact_id),
        "artifact_digest": provider_digest,
        "artifact_run_id": run_id,
        "commit_sha": commit_sha,
        "wheel_sha256": wheel_sha256,
    }
    executable = install_root / "bin/bcf"
    if install_root.exists():
        if install_root.is_symlink() or not install_root.is_dir() or (
            _metadata(install_metadata) != expected_install
        ):
            raise GitHubControllerError("existing controller installation has stale custody")
        subprocess.run([str(executable), "ci-github", "--help"], check=True)
        return {"status": "already_installed", "install_root": str(install_root)}
    install_root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        subprocess.run([str(python), "-m", "venv", str(install_root)], check=True)
        subprocess.run(
            [
                str(install_root / "bin/python"), "-m", "pip", "install",
                "--no-index", "--find-links", str(artifact_dir.resolve()), str(wheel),
            ],
            check=True,
        )
        install_metadata.write_text(
            json.dumps(expected_install, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        subprocess.run([str(executable), "ci-github", "--help"], check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        if install_root.exists() and not install_root.is_symlink():
            shutil.rmtree(install_root)
        raise GitHubControllerError("controller offline installation failed") from exc
    return {"status": "installed", "install_root": str(install_root)}

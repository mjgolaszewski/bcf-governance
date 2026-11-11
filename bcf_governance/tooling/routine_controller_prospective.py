"""Provider-authenticated, non-certifying admission of a pending source normalization."""

from __future__ import annotations

import hashlib
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

from .break_glass_recovery import _safe_archive
from .break_glass_reentry import authenticate_projection_receipt
from .ci_github_api import GitHubAPI
from .ci_github_identity import GitHubControllerError, resolve_main
from .ci_self_controller import (
    compile_resolved_self_controller_pin,
    resolve_self_controller_artifact,
)

POLICY = Path("governance/self-governance-policy.yml")
RECEIPT_PREFIX = "bcf-break-glass-recovery-receipt-"


def _policy(raw: bytes) -> dict[str, Any]:
    try:
        payload = yaml.safe_load(raw)
        runner = payload["runner_security"]
        if not isinstance(runner, dict):
            raise TypeError("runner policy")
        return runner
    except (UnicodeError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise GitHubControllerError("prospective normalization policy is invalid") from exc


def _committed_policy(root: Path) -> bytes:
    result = subprocess.run(
        ["git", "show", f"HEAD:{POLICY.as_posix()}"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode or result.stdout != (root / POLICY).read_bytes():
        raise GitHubControllerError(
            "prospective normalization policy is not exact committed source"
        )
    return result.stdout


def _require_ancestor(root: Path, main_commit: str) -> None:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", main_commit, "HEAD"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise GitHubControllerError(
            "prospective normalization candidate does not descend from current main"
        )


def prospective_normalized_controller_authority(
    api: GitHubAPI, *, repository: str, repo_root: Path
) -> dict[str, str]:
    """Admit exact candidate source from a protected receipt and ordinary N bytes.

    This is a local prospective input only. It does not replace provider main,
    certify a change, grant a merge, or authorize publication.
    """
    root = repo_root.resolve()
    main = resolve_main(api, repository)
    _require_ancestor(root, main.checkout_sha)
    candidate = _policy(_committed_policy(root))
    base_content = api.content(repository, POLICY.as_posix(), ref=main.checkout_sha)
    baseline = _policy(base_content.content)
    pin = candidate.get("trusted_controller_artifact")
    installation = candidate.get("trusted_controller_installation")
    old_pin = baseline.get("trusted_controller_artifact")
    old_installation = baseline.get("trusted_controller_installation")
    if (
        not isinstance(pin, dict)
        or not isinstance(installation, dict)
        or not isinstance(old_pin, dict)
        or not isinstance(old_installation, dict)
    ):
        raise GitHubControllerError("prospective normalization custody is incomplete")
    if (
        pin["BCF_BOOTSTRAP_COMMIT_SHA"] != main.checkout_sha
        or pin["BCF_BOOTSTRAP_TREE_SHA"] != main.tree_sha
        or installation["installed_commit_sha"] != main.checkout_sha
        or installation["subject_commit_sha"] != main.checkout_sha
        or installation["subject_tree_sha"] != main.tree_sha
        or old_pin["BCF_BOOTSTRAP_COMMIT_SHA"] == main.checkout_sha
        or old_installation["installed_commit_sha"] != old_pin["BCF_BOOTSTRAP_COMMIT_SHA"]
        or "trusted_controller_recovery_reentry" in candidate
    ):
        raise GitHubControllerError("candidate is not one exact pending normalization")
    probe_run_id = str(installation["probe_run_id"])
    receipts = [
        artifact
        for artifact in api.artifacts(repository, probe_run_id)
        if str(artifact.get("name", "")).startswith(RECEIPT_PREFIX)
        and artifact.get("expired") is False
    ]
    if len(receipts) != 1:
        raise GitHubControllerError("prospective normalization receipt is absent or ambiguous")
    artifact = receipts[0]
    raw = api.artifact_bytes(repository, artifact["id"], maximum_bytes=1_048_576)
    if artifact.get("digest") != "sha256:" + hashlib.sha256(raw).hexdigest():
        raise GitHubControllerError("prospective normalization receipt digest differs")
    with tempfile.TemporaryDirectory(prefix="bcf-prospective-normalization-") as name:
        extracted = Path(name)
        _safe_archive(raw, extracted)
        files = [
            path.relative_to(extracted).as_posix()
            for path in extracted.rglob("*")
            if path.is_file()
        ]
        if files != ["receipt.json"]:
            raise GitHubControllerError("prospective normalization receipt inventory is not exact")
        receipt, authenticated_artifact, authenticated_main = authenticate_projection_receipt(
            api, root=root, repository=repository, receipt_path=extracted / "receipt.json"
        )
    if (
        str(authenticated_artifact["id"]) != str(artifact["id"])
        or authenticated_main.checkout_sha != main.checkout_sha
        or receipt["pre_recovery_controller"] != old_pin["BCF_BOOTSTRAP_COMMIT_SHA"]
        or receipt["resulting_installed_controller"] != main.checkout_sha
        or receipt["controller_confirmation"] != installation
        or receipt["recovery_only"] is not True
        or receipt["governance_certified"] is not False
    ):
        raise GitHubControllerError(
            "prospective normalization receipt does not bind candidate custody"
        )
    ordinary_subject, ordinary_artifact = resolve_self_controller_artifact(
        api, repository=repository
    )
    if ordinary_subject != {
        "repository_id": main.repository_id,
        "commit_sha": main.checkout_sha,
        "tree_sha": main.tree_sha,
    }:
        raise GitHubControllerError("ordinary controller subject differs from recovery subject")
    ordinary_raw = api.artifact_bytes(repository, ordinary_artifact.artifact_id)
    if ordinary_artifact.provider_digest != "sha256:" + hashlib.sha256(ordinary_raw).hexdigest():
        raise GitHubControllerError("ordinary controller provider digest differs")
    with tempfile.TemporaryDirectory(prefix="bcf-prospective-ordinary-") as name:
        extracted = Path(name)
        _safe_archive(ordinary_raw, extracted)
        compiled = compile_resolved_self_controller_pin(
            subject=ordinary_subject, artifact=ordinary_artifact, artifact_dir=extracted
        )
    if (
        pin != compiled
        or compiled["BCF_BOOTSTRAP_WHEEL_SHA256"] != receipt["artifact"]["wheel_sha256"]
    ):
        raise GitHubControllerError("candidate pin differs from authenticated ordinary controller")
    return {
        "controller_commit_sha": main.checkout_sha,
        "controller_bundle_sha256": compiled["BCF_BOOTSTRAP_WHEEL_SHA256"],
    }

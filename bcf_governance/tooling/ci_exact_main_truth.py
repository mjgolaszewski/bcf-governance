"""Authenticate the exact governance truth artifact used by exact-main finalization."""

from __future__ import annotations

from io import BytesIO
import hashlib
import json
from pathlib import PurePosixPath
from typing import Any
import zipfile

from .ci_github_artifacts import provider_artifact_reference, resolve_role_artifact
from .ci_github_identity import GitHubControllerError, MainIdentity, exact_sha
from .evaluation_scope import EvaluationScopeError, validate_certified_proposition


_MAX_ARCHIVE = 2_000_000
_REPORT_NAME = "truth-report.json"


def authenticated_exact_main_truth(
    api: Any,
    *,
    repository: str,
    main: MainIdentity,
    authority: dict[str, Any],
    run_id: str,
    run_attempt: int,
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    """Return one provider-bound terminal truth report and its closed descriptor."""

    artifact = resolve_role_artifact(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="admission",
        run_id=run_id,
        run_attempt=run_attempt,
        artifact_name=f"bcf-governance-truth-{run_id}-{run_attempt}",
        require_success=False,
    )
    raw = api.artifact_bytes(repository, artifact.artifact_id, maximum_bytes=_MAX_ARCHIVE)
    archive_digest = hashlib.sha256(raw).hexdigest()
    if artifact.provider_digest != f"sha256:{archive_digest}":
        raise GitHubControllerError("governance truth artifact bytes differ from provider digest")
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            members = [member for member in archive.infolist() if not member.is_dir()]
            if len(members) != 1:
                raise GitHubControllerError("governance truth artifact inventory is not exact")
            member = members[0]
            path = PurePosixPath(member.filename)
            if (
                path.name != _REPORT_NAME
                or path.is_absolute()
                or ".." in path.parts
                or member.flag_bits & 0x1
                or member.file_size > _MAX_ARCHIVE
            ):
                raise GitHubControllerError("governance truth artifact member is unsafe")
            report_bytes = archive.read(member)
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        raise GitHubControllerError("governance truth artifact is not a closed ZIP") from exc
    try:
        report = json.loads(report_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubControllerError("governance truth report is invalid JSON") from exc
    if not isinstance(report, dict):
        raise GitHubControllerError("governance truth report must contain an object")
    subject = {"commit_sha": main.checkout_sha, "tree_sha": main.tree_sha}
    proposition: dict[str, Any] = {}
    if "certified_proposition" in report:
        report_subject = report.get("subject")
        if not isinstance(report_subject, dict):
            raise GitHubControllerError("governance truth subject is invalid")
        report_identity = {
            "commit_sha": exact_sha(
                report_subject.get("commit_sha"),
                field="governance truth subject commit SHA",
            ),
            "tree_sha": exact_sha(
                report_subject.get("tree_sha"),
                field="governance truth subject tree SHA",
            ),
        }
        if report_identity != subject:
            raise GitHubControllerError("governance truth subject is not exact main")
        try:
            proposition = validate_certified_proposition(report, subject=subject)
        except EvaluationScopeError as exc:
            raise GitHubControllerError(str(exc)) from exc
        expected_ref = (
            f"github-actions://{repository}/runs/{run_id}/attempts/"
            f"{run_attempt}/bcf-governance-truth"
        )
        if report.get("durable_ref") != expected_ref:
            raise GitHubControllerError("governance truth durable identity is not exact")
    elif not (
        report.get("computed_state") == "failed"
        and report.get("subject", {}).get("commit_sha") == main.checkout_sha
        and isinstance(report.get("evaluation_request"), dict)
    ):
        raise GitHubControllerError("terminal governance observation is incomplete")
    descriptor = {
        "artifact": provider_artifact_reference(artifact),
        "artifact_sha256": archive_digest,
        "report_path": "governance-truth.json",
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
    }
    return report, descriptor, report_bytes

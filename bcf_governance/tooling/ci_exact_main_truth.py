"""Authenticate the exact governance truth artifact used by exact-main finalization."""

from __future__ import annotations

from io import BytesIO
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from tempfile import TemporaryDirectory
from typing import Any
import zipfile

from .ci_github_artifacts import provider_artifact_reference, resolve_role_artifact
from .ci_github_identity import GitHubControllerError, MainIdentity, exact_sha
from .evaluation_scope import EvaluationScopeError, validate_certified_proposition


_MAX_ARCHIVE = 2_000_000
_REPORT_NAME = "truth-report.json"


def validate_exact_main_truth_payload(
    report: dict[str, Any], *, subject: dict[str, str]
) -> dict[str, Any]:
    """Decode the finalizer-owned truth identity and bounded proposition.

    Provider artifact custody is authenticated by ``authenticated_exact_main_truth``.
    This pure boundary deliberately projects only the exact commit/tree identity owned
    by the finalizer, while permitting additive canonical subject metadata.
    """

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
        return validate_certified_proposition(report, subject=subject)
    except EvaluationScopeError as exc:
        raise GitHubControllerError(str(exc)) from exc


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
        proposition = validate_exact_main_truth_payload(report, subject=subject)
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


def authenticate_exact_main_readiness(
    api: Any, *, repository: str, main: MainIdentity, scope: dict[str, Any],
    proposition: dict[str, Any],
) -> None:
    """Run the shared readiness owner on exact provider-owned lifecycle bytes."""

    from .trusted_inputs import (
        _authenticated_lifecycle_source_snapshot, _read_authenticated_lifecycle_blob,
    )
    from .prior_evidence_transport import _mapping
    from .evidence_workitem_lifecycle import (
        WorkitemContractError, validate_bounded_target_successor, validate_evaluation_authored_ready,
    )

    _, selected, blobs, modes = _authenticated_lifecycle_source_snapshot(
        api, repository=repository, policy_subject=main,
    )
    total = 0

    def read(path: Any) -> bytes:
        nonlocal total
        raw, total = _read_authenticated_lifecycle_blob(
            api, repository=repository, selected=selected, blobs=blobs, modes=modes,
            path=path, total=total,
        )
        return raw

    ledger_raw = read("plans/phase-ledger.yml")
    try:
        ledger = _mapping(ledger_raw, label="exact-main lifecycle ledger")
    except ValueError as exc:
        raise GitHubControllerError(str(exc)) from exc
    active = ledger.get("active_phase")
    phase_id = active.get("id") if isinstance(active, dict) else None
    if not isinstance(phase_id, str) or re.fullmatch(r"P[0-9]+", phase_id) is None:
        raise GitHubControllerError("exact-main lifecycle active phase is invalid")
    intent, target = scope.get("intent"), scope.get("target")
    if intent not in {"workitem", "closure"} or not isinstance(target, dict):
        raise GitHubControllerError("exact-main readiness scope is not certifying")
    if intent == "closure" and target != {"kind": "phase", "id": phase_id}:
        raise GitHubControllerError("exact-main closure target is not its admitted phase")
    files = {"plans/phase-ledger.yml": ledger_raw}
    workitems = active.get("workitems")
    files[workitems] = read(workitems)
    if intent == "closure":
        log = active.get("log")
        files[log] = read(log)
        for path in sorted(blobs):
            if PurePosixPath(path).match("phases/phase-[0-9]*-hotfix*.yml"):
                files[path] = read(path)
    with TemporaryDirectory(prefix="bcf-exact-main-lifecycle-") as temporary:
        root = Path(temporary)
        for relative, raw in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        try:
            if intent == "workitem":
                claimed = proposition.get("eligible_successors")
                if not isinstance(claimed, list):
                    raise WorkitemContractError("bounded successor projection is missing or invalid")
                validate_bounded_target_successor(root, target.get("id"), claimed_successors=claimed)
            validate_evaluation_authored_ready(
                root, intent=intent, target=target.get("id"),
                provider_api=api, repository=repository, policy_subject=selected,
            )
        except WorkitemContractError as exc:
            raise GitHubControllerError(f"exact-main lifecycle readiness rejected: {exc}") from exc

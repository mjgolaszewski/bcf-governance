"""Authority-v1.1 exact-main admission, finalization, and publication."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
from pathlib import Path
import secrets
from typing import Any

from .ci_authority_certification import (
    normalize_ci_certification,
    verify_ci_certification,
)
from .ci_authority_decisions import StatusConclusion, StatusContext
from .ci_authority_contracts import authority_role_workflow
from .ci_github_api import GitHubAPI
from .ci_github_authority import (
    authenticate_role_run,
    load_authority,
    packaged_repo_root,
)
from .ci_github_bundle import (
    canonical_json,
    prepare_output,
    verify_bundle,
    write_exclusive,
)
from .ci_exact_main_truth import authenticated_exact_main_truth
from .ci_reuse_attestation_verifier import verify_same_admission_reuse
from .ci_github_identity import (
    GitHubControllerError,
    resolve_main,
    resolve_run_subject,
)
from .ci_github_membership import (
    AdmissionTopologyState,
    admission_ordinal,
    certification_producer_ids,
    classify_admission_topology,
    collect_same_run_producers,
    select_latest_admission,
)
from .ci_github_status import publish as publish_bundle
from .ci_github_status import publish_observation
from .evaluation_scope import EvaluationIntent, evaluation_scope


@dataclass(frozen=True)
class ExactMainResult:
    status: str
    computed_state: str
    admission_run_id: str
    admission_run_attempt: int
    admission_ordinal: int
    bundle_dir: str | None = None


def _write_observation_bundle(
    output_dir: Path,
    *,
    main: Any,
    collector: Any,
    admission_run_id: str,
    admission_attempt: int,
    ordinal: int,
    computed_state: str,
    reason: str | None = None,
) -> Path:
    """Write one exact authenticated non-certification observation bundle."""

    root = prepare_output(output_dir)
    observation = {
        "schema_version": "1.1",
        "kind": "authority_observation",
        "subject": {"commit_sha": main.checkout_sha, "tree_sha": main.tree_sha},
        "admission": {
            "run_id": admission_run_id,
            "run_attempt": admission_attempt,
            "admission_ordinal": str(ordinal),
        },
        "collector": {
            "run_id": collector.run_id,
            "run_attempt": collector.run_attempt,
            "workflow": asdict(collector.workflow),
        },
        "computed_state": computed_state,
    }
    if reason is not None:
        observation["reason"] = reason
    digest = write_exclusive(root / "authority-observation.json", observation)
    manifest = {
        "schema_version": "1.1",
        "kind": "authority_observation",
        "subject": observation["subject"],
        "admission_ordinal": str(ordinal),
        "computed_state": computed_state,
        "files": {"authority-observation.json": digest},
    }
    (root / "bundle-manifest.json").write_bytes(canonical_json(manifest))
    for path in root.rglob("*.json"):
        path.chmod(0o400)
    return root


def admit_exact_main(
    api: GitHubAPI,
    *,
    repository: str,
    expected_sha: str,
    run_id: object,
    run_attempt: object,
    target_url: str,
    evaluation_mode: str = "closure",
    evaluation_target: str | None = None,
) -> dict[str, Any]:
    """Authenticate current main and publish its higher-ordinal pending status."""

    main = resolve_main(api, repository)
    if expected_sha != main.checkout_sha:
        raise GitHubControllerError("admission subject is not current default main")
    authority = load_authority(api, repository, main, required_version="1.1")
    identity = authenticate_role_run(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="admission",
        run_id=run_id,
        run_attempt=run_attempt,
        require_success=False,
    )
    ordinal = admission_ordinal(identity.run_id, identity.run_attempt, 1)
    scope = evaluation_scope(
        evaluation_mode,
        target=evaluation_target,
        phase_id="PENDING",
        subject_commit=main.checkout_sha,
    )
    if scope.intent is EvaluationIntent.PR_PROGRESS:
        raise GitHubControllerError("exact-main admission cannot certify PR progress")
    context = (
        StatusContext.BOUNDED_WORKITEM
        if scope.intent is EvaluationIntent.WORKITEM_CERTIFICATION
        else StatusContext.EXACT_MAIN
    )
    status = publish_observation(
        api,
        repository=repository,
        subject_sha=main.checkout_sha,
        current_default_main_sha=main.checkout_sha,
        admission_ordinal=ordinal,
        control_plane_attempt=identity.run_attempt,
        conclusion=StatusConclusion.PENDING,
        description=f"BCF {scope.intent.value} {scope.target_id} pending"[:140],
        target_url=target_url,
        status_context=context,
    )
    return {
        **status,
        "tree_sha": main.tree_sha,
        "admission_run_id": identity.run_id,
        "admission_run_attempt": identity.run_attempt,
    }


def finalize_exact_main(
    api: GitHubAPI,
    *,
    repository: str,
    collector_run_id: object,
    collector_run_attempt: object,
    trigger_run_id: object | None = None,
    trigger_run_attempt: object | None = None,
    output_dir: Path,
) -> ExactMainResult:
    """Reconstruct one admitted immutable subject and its terminal bundle."""

    if (trigger_run_id is None) != (trigger_run_attempt is None):
        raise GitHubControllerError(
            "admission trigger run ID and attempt must be supplied together"
        )
    main = (
        resolve_main(api, repository)
        if trigger_run_id is None
        else resolve_run_subject(
            api,
            repository,
            run_id=trigger_run_id,
            run_attempt=trigger_run_attempt,
        )
    )
    authority = load_authority(api, repository, main, required_version="1.1")
    collector = authenticate_role_run(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="finalizer",
        run_id=collector_run_id,
        run_attempt=collector_run_attempt,
        require_success=False,
    )
    admission_run_id, admission_attempt = select_latest_admission(
        api,
        repository=repository,
        main=main,
        authority=authority,
        trigger_run_id=trigger_run_id,
        trigger_run_attempt=trigger_run_attempt,
    )
    ordinal = admission_ordinal(admission_run_id, admission_attempt, 1)
    topology = classify_admission_topology(
        api,
        repository=repository,
        main=main,
        authority=authority,
        admission_run_id=admission_run_id,
        admission_run_attempt=admission_attempt,
    )
    if topology.state is AdmissionTopologyState.NONCERTIFYING:
        root = _write_observation_bundle(
            output_dir,
            main=main,
            collector=collector,
            admission_run_id=admission_run_id,
            admission_attempt=admission_attempt,
            ordinal=ordinal,
            computed_state="noncertifying",
            reason=topology.reason,
        )
        return ExactMainResult(
            "noncertifying",
            "noncertifying",
            admission_run_id,
            admission_attempt,
            ordinal,
            str(root),
        )
    truth_report, truth_descriptor, truth_bytes = authenticated_exact_main_truth(
        api,
        repository=repository,
        main=main,
        authority=authority,
        run_id=admission_run_id,
        run_attempt=admission_attempt,
    )
    verify_same_admission_reuse(
        api, repository=repository, main=main, authority=authority,
        run_id=admission_run_id, run_attempt=admission_attempt,
        truth_report=truth_report, repo_root=packaged_repo_root(),
    )
    raw_scope = truth_report.get("evaluation_scope")
    if not isinstance(raw_scope, dict):
        raise GitHubControllerError(
            "certifiable exact-main truth lacks typed evaluation scope"
        )
    required_producers = certification_producer_ids(authority, raw_scope)
    producer_runs = collect_same_run_producers(
        api,
        repository=repository,
        main=main,
        authority=authority,
        admission_run_id=admission_run_id,
        admission_run_attempt=admission_attempt,
        producer_ids=required_producers,
    )
    if any(
        value["attempts"][0]["status"] != "completed" for value in producer_runs
    ):
        root = _write_observation_bundle(
            output_dir,
            main=main,
            collector=collector,
            admission_run_id=admission_run_id,
            admission_attempt=admission_attempt,
            ordinal=ordinal,
            computed_state="pending",
        )
        return ExactMainResult(
            "pending", "pending", admission_run_id, admission_attempt, ordinal,
            str(root),
        )
    admission = authenticate_role_run(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="admission",
        run_id=admission_run_id,
        run_attempt=admission_attempt,
        require_success=False,
    )
    captured_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    shared = {
        "admission_ordinal": str(ordinal),
        "control_plane_run_id": admission_run_id,
        "control_plane_run_attempt": admission_attempt,
        "control_plane_workflow": asdict(admission.workflow),
        "dispatch_sequence": 1,
        "candidate": {"checkout_sha": main.checkout_sha, "tree_sha": main.tree_sha},
        "collection_complete": True,
    }
    snapshots = [
        {
            "schema_version": "1.0",
            "authority_contract_version": "1.1",
            "producer_id": value["producer_id"],
            "repository": {"provider": "github", "repository_id": main.repository_id},
            "authentication": {
                "collector_id": "bcf-trusted-finalizer",
                "provider_api_verified": True,
                "captured_at": captured_at,
            },
            "current_default_main": {
                "checkout_sha": main.checkout_sha,
                "tree_sha": main.tree_sha,
            },
            "admissions": [{**shared, "producer_run": value}],
        }
        for value in producer_runs
    ]
    root = prepare_output(output_dir)
    scoped_truth = bool(truth_report.get("certified_proposition"))
    if scoped_truth:
        (root / "governance-truth.json").write_bytes(truth_bytes)
    authority_path = root / "ci-authority.json"
    write_exclusive(authority_path, authority)
    raw_dir = root / "raw"
    raw_dir.mkdir(mode=0o700)
    descriptors: list[dict[str, Any]] = []
    for snapshot in snapshots:
        relative = f"raw/{snapshot['producer_id']}.json"
        digest = write_exclusive(root / relative, snapshot)
        descriptors.append(
            {
                "producer_id": snapshot["producer_id"],
                "artifact_path": relative,
                "sha256": digest,
                "authenticated_at": captured_at,
            }
        )
    session = {
        "schema_version": "1.0",
        "session_id": secrets.token_hex(16),
        "subject": {"commit_sha": main.checkout_sha, "tree_sha": main.tree_sha},
        "profile": "standard",
        "profile_contract_version": "3.0",
        "producer": {
            "kind": "workflow",
            "provider": "github",
            "repository": repository,
            "repository_id": main.repository_id,
            "run_id": collector.run_id,
            "run_attempt": str(collector.run_attempt),
            "producer_id": "bcf-trusted-finalizer",
        },
        "expected_gate_inventory": ["ci-certification"],
        "expected_producer_inventory": sorted(
            str(value["producer_id"]) for value in producer_runs
        ),
        "created_at": captured_at,
        "session_root_policy": {
            "mode": "0700",
            "root_kind": "external",
            "immutable_manifest": True,
        },
    }
    session_path = root / "evidence-session.json"
    session_digest = write_exclusive(session_path, session)
    report = normalize_ci_certification(
        packaged_repo_root(),
        authority=authority,
        snapshots=snapshots,
        raw_snapshot_descriptors=descriptors,
        evidence_session={
            "session_id": session["session_id"],
            "manifest_sha256": session_digest,
            "run_id": collector.run_id,
            "run_attempt": collector.run_attempt,
        },
        generated_at=captured_at,
        governance_truth=truth_descriptor if scoped_truth else None,
        evaluation_scope=(
            dict(truth_report["evaluation_scope"]) if scoped_truth else None
        ),
        certified_proposition=(
            dict(truth_report["certified_proposition"]) if scoped_truth else None
        ),
    )
    report_path = root / "ci-certification.json"
    write_exclusive(report_path, report)
    verification = verify_ci_certification(
        packaged_repo_root(),
        authority_path=authority_path,
        certification_path=report_path,
        session_manifest_path=session_path,
    )
    manifest = {
        "schema_version": "1.1",
        "kind": "certification",
        "subject": {"commit_sha": main.checkout_sha, "tree_sha": main.tree_sha},
        "admission_ordinal": str(ordinal),
        "computed_state": verification.computed_state,
        "files": {
            path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*.json"))
            if path.name != "bundle-manifest.json"
        },
    }
    (root / "bundle-manifest.json").write_bytes(canonical_json(manifest))
    for path in root.rglob("*.json"):
        path.chmod(0o400)
    return ExactMainResult(
        "terminal",
        verification.computed_state,
        admission_run_id,
        admission_attempt,
        ordinal,
        str(root),
    )


def publish_exact_main(
    api: GitHubAPI,
    *,
    repository: str,
    bundle_dir: Path,
    target_url: str,
    collector_run_id: object,
    collector_run_attempt: object,
    publisher_run_id: object,
    publisher_run_attempt: object,
) -> dict[str, Any]:
    """Authenticate the v1.1 publisher and delegate canonical status publication."""

    publisher_main = resolve_run_subject(
        api,
        repository,
        run_id=publisher_run_id,
        run_attempt=publisher_run_attempt,
    )
    authority = load_authority(
        api, repository, publisher_main, required_version="1.1"
    )
    authenticate_role_run(
        api,
        repository=repository,
        main=publisher_main,
        authority=authority,
        role="status_publisher",
        run_id=publisher_run_id,
        run_attempt=publisher_run_attempt,
        require_success=False,
    )
    finalizer = authority_role_workflow(authority, "finalizer")
    if not (bundle_dir / "bundle-manifest.json").is_file():
        collector = authenticate_role_run(
            api,
            repository=repository,
            main=publisher_main,
            authority=authority,
            role="finalizer",
            run_id=collector_run_id,
            run_attempt=collector_run_attempt,
            require_success=False,
        )
        return {
            "status": "suppressed",
            "reason": "certification_applicability_unproven",
            "subject_sha": publisher_main.checkout_sha,
            "collector_run_id": collector.run_id,
        }
    if bundle_dir.is_symlink():
        raise GitHubControllerError("certification bundle cannot be a symlink")
    manifest = verify_bundle(bundle_dir.resolve())
    if manifest.get("subject") != {
        "commit_sha": publisher_main.checkout_sha,
        "tree_sha": publisher_main.tree_sha,
    }:
        raise GitHubControllerError(
            "status publisher run is not bound to certification subject"
        )
    return publish_bundle(
        api,
        repository=repository,
        bundle_dir=bundle_dir,
        target_url=target_url,
        collector_run_id=collector_run_id,
        collector_run_attempt=collector_run_attempt,
        collector_workflow_path=str(finalizer["active_path"]),
        collector_workflow_id=finalizer["workflow_id"],
        collector_workflow_sha256=str(finalizer["trusted_workflow_sha256"]),
        require_evaluation_scope=True,
    )

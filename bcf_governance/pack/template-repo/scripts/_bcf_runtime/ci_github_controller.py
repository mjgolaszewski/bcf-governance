"""Trusted GitHub admission, provider collection, and certification control."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import yaml

from .ci_authority_certification import (
    normalize_ci_certification,
    verify_ci_certification,
)
from .ci_authority_contracts import validate_ci_contract
from .ci_authority_state import WorkflowIdentity
from .ci_authority_decisions import (
    StatusConclusion,
    StatusContext,
    StatusObservation,
    decide_status_publication,
)
from .ci_github import DISPATCH_EVENTS
from .ci_github_api import GitHubAPI, GitHubAPIError
from .ci_github_identity import (
    GitHubControllerError,
    MainIdentity,
    ProducerNotStarted,
    authenticate_producer_workflow,
    authenticate_trusted_run,
    exact_sha as _sha,
    positive_int as _positive,
    resolve_main,
    select_producer_run,
)


STATUS_CONTEXT = "bcf/exact-main-certification"


@dataclass(frozen=True)
class KickoffResult:
    status: str
    repository_id: str
    checkout_sha: str
    tree_sha: str
    control_plane_run_id: str
    control_plane_run_attempt: int
    dispatch_sequence: int
    admission_ordinal: int
    dispatched: bool
    control_plane_workflow: WorkflowIdentity


@dataclass(frozen=True)
class FinalizeResult:
    status: str
    computed_state: str
    admission_ordinal: int
    bundle_dir: str | None
    producer_runs: tuple[tuple[str, str, int], ...]


def admission_ordinal(run_id: object, run_attempt: object, dispatch_sequence: object) -> int:
    """Map GitHub's authenticated total tuple to one positive total ordinal."""

    run = _positive(run_id, field="control-plane run ID")
    attempt = _positive(run_attempt, field="control-plane run attempt")
    sequence = _positive(dispatch_sequence, field="dispatch sequence")
    if attempt >= 1_000 or sequence >= 1_000:
        raise GitHubControllerError("attempt and dispatch sequence must be below 1000")
    return run * 1_000_000 + attempt * 1_000 + sequence


def kickoff(
    api: GitHubAPI,
    *,
    repository: str,
    expected_sha: str,
    control_run_id: object,
    control_run_attempt: object,
    control_workflow_path: str,
    dispatch_sequence: object = 1,
    dispatch_exact_ref: bool = False,
    control_workflow_id: object | None = None,
    control_workflow_sha256: str | None = None,
) -> KickoffResult:
    """Authenticate one input-free exact-main run and optionally dispatch its worker."""

    main = resolve_main(api, repository)
    subject = _sha(expected_sha, field="kickoff SHA")
    if subject != main.checkout_sha:
        raise GitHubControllerError("kickoff subject is not current default main")
    run_id = str(_positive(control_run_id, field="control-plane run ID"))
    attempt = _positive(control_run_attempt, field="control-plane run attempt")
    sequence = _positive(dispatch_sequence, field="dispatch sequence")
    control_identity = authenticate_trusted_run(
        api,
        repository=repository,
        main=main,
        run_id=run_id,
        run_attempt=attempt,
        workflow_path=control_workflow_path,
        expected_event="push",
        require_success=False,
        expected_workflow_id=control_workflow_id,
        expected_workflow_sha256=control_workflow_sha256,
    )
    ordinal = admission_ordinal(run_id, attempt, sequence)
    payload = {
        "checkout_sha": subject,
        "tree_sha": main.tree_sha,
        "control_plane_run_id": run_id,
        "control_plane_run_attempt": attempt,
        "dispatch_sequence": sequence,
        "admission_ordinal": str(ordinal),
    }
    if dispatch_exact_ref:
        api.dispatch(repository, event_type=DISPATCH_EVENTS[0], client_payload=payload)
    return KickoffResult(
        status="admitted",
        repository_id=main.repository_id,
        checkout_sha=subject,
        tree_sha=main.tree_sha,
        control_plane_run_id=run_id,
        control_plane_run_attempt=attempt,
        dispatch_sequence=sequence,
        admission_ordinal=ordinal,
        dispatched=dispatch_exact_ref,
        control_plane_workflow=control_identity.workflow,
    )


def _packaged_repo_root() -> Path:
    root = Path(__file__).resolve().parents[1] / "pack/template-repo"
    if not (root / "schemas/ci-authority.schema.json").is_file():
        raise GitHubControllerError("installed BCF package lacks CI authority schemas")
    return root


def _load_authority(api: GitHubAPI, repository: str, main: MainIdentity) -> dict[str, Any]:
    content = api.content(repository, "governance/ci-authority.yml", ref=main.checkout_sha)
    try:
        payload = yaml.safe_load(content.content.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise GitHubControllerError("trusted CI authority document is invalid YAML") from exc
    if not isinstance(payload, dict):
        raise GitHubControllerError("trusted CI authority document must contain a mapping")
    validate_ci_contract(_packaged_repo_root(), "authority", payload)
    if payload["repository"] != {
        "provider": "github",
        "repository_id": main.repository_id,
    }:
        raise GitHubControllerError("CI authority repository identity is not current repository")
    return payload


def _job_status(value: object) -> str:
    status = str(value)
    if status not in {"queued", "in_progress", "completed"}:
        raise GitHubControllerError(f"unsupported GitHub job status: {status}")
    return status


def _conclusion(value: object) -> str | None:
    if value is None:
        return None
    conclusion = str(value)
    allowed = {
        "success", "failure", "cancelled", "timed_out", "action_required",
        "neutral", "skipped", "stale",
    }
    if conclusion not in allowed:
        raise GitHubControllerError(f"unsupported GitHub conclusion: {conclusion}")
    return conclusion


def _producer_run(
    api: GitHubAPI,
    repository: str,
    main: MainIdentity,
    producer: dict[str, Any],
) -> dict[str, Any]:
    run = select_producer_run(
        api, repository=repository, main=main, producer=producer
    )
    attempt = _positive(run.get("run_attempt"), field="producer run attempt")
    jobs = api.jobs(repository, run["id"], attempt=attempt)
    return {
        "producer_id": str(producer["producer_id"]),
        "run_id": str(_positive(run.get("id"), field="producer run ID")),
        "workflow": authenticate_producer_workflow(
            api, repository=repository, main=main, producer=producer, run=run
        ),
        "attempts": [
            {
                "run_attempt": attempt,
                "status": _job_status(run.get("status")),
                "conclusion": _conclusion(run.get("conclusion")),
                "jobs": [
                    {
                        "job_id": str(job.get("name", "")),
                        "matrix": {},
                        "status": _job_status(job.get("status")),
                        "conclusion": _conclusion(job.get("conclusion")),
                    }
                    for job in jobs
                ],
            }
        ],
    }


def _canonical(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _write_exclusive(path: Path, payload: dict[str, Any]) -> str:
    raw = _canonical(payload)
    with path.open("xb") as stream:
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()


def _verify_bundle(root: Path) -> dict[str, Any]:
    if root.is_symlink() or not root.is_dir():
        raise GitHubControllerError("certification bundle must be a regular directory")
    manifest_path = root / "bundle-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise GitHubControllerError("certification bundle manifest is missing or unsafe")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GitHubControllerError("certification bundle manifest is invalid") from exc
    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(files, dict) or not files:
        raise GitHubControllerError("certification bundle file inventory is missing")
    actual: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise GitHubControllerError("certification bundle cannot contain symlinks")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    expected = set(files) | {"bundle-manifest.json"}
    if actual != expected:
        raise GitHubControllerError("certification bundle file inventory is not exact")
    for relative, digest in files.items():
        if (
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[a-f0-9]{64}", digest)
        ):
            raise GitHubControllerError("certification bundle digest inventory is invalid")
        path = root / relative
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise GitHubControllerError(
                f"certification bundle digest mismatch: {relative}"
            )
    return manifest


def _prepare_output(path: Path) -> Path:
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir():
        raise GitHubControllerError("certification output parent must be a regular directory")
    path.mkdir(mode=0o700)
    if path.is_symlink():
        raise GitHubControllerError("certification output cannot be a symlink")
    return path.resolve()


def finalize(
    api: GitHubAPI,
    *,
    repository: str,
    control_run_id: object,
    control_run_attempt: object,
    control_workflow_id: object | None,
    control_workflow_path: str,
    control_workflow_sha256: str | None,
    collector_run_id: object,
    collector_run_attempt: object,
    collector_workflow_path: str,
    collector_workflow_id: object | None,
    collector_workflow_sha256: str | None,
    output_dir: Path,
) -> FinalizeResult:
    """Reconstruct all producers and write a terminal normalized bundle once."""

    main = resolve_main(api, repository)
    authority = _load_authority(api, repository, main)
    admission = authority.get("admission_workflow")
    control_blob_oid: object | None = None
    control_definition_commit: object | None = None
    if isinstance(admission, dict):
        authority_id = admission["workflow_id"]
        authority_digest = str(admission["trusted_workflow_sha256"])
        if control_workflow_id is not None and str(control_workflow_id) != str(
            authority_id
        ):
            raise GitHubControllerError("control workflow ID conflicts with canonical authority")
        if (
            control_workflow_sha256 is not None
            and control_workflow_sha256 != authority_digest
        ):
            raise GitHubControllerError("control workflow digest conflicts with canonical authority")
        control_workflow_id = authority_id
        control_workflow_sha256 = authority_digest
        control_blob_oid = admission["trusted_workflow_blob_oid"]
        control_definition_commit = admission["trusted_workflow_definition_commit"]
    control_id = str(_positive(control_run_id, field="control-plane run ID"))
    control_attempt = _positive(control_run_attempt, field="control-plane run attempt")
    control_identity = authenticate_trusted_run(
        api,
        repository=repository,
        main=main,
        run_id=control_id,
        run_attempt=control_attempt,
        workflow_path=control_workflow_path,
        expected_event="push",
        require_success=True,
        expected_workflow_id=control_workflow_id,
        expected_workflow_sha256=control_workflow_sha256,
        expected_workflow_blob_oid=control_blob_oid,
        expected_workflow_definition_commit=control_definition_commit,
    )
    collector_identity = authenticate_trusted_run(
        api,
        repository=repository,
        main=main,
        run_id=collector_run_id,
        run_attempt=collector_run_attempt,
        workflow_path=collector_workflow_path,
        expected_event="workflow_run",
        require_success=False,
        expected_workflow_id=collector_workflow_id,
        expected_workflow_sha256=collector_workflow_sha256,
    )
    ordinal = admission_ordinal(control_id, control_attempt, 1)
    collected_runs: list[dict[str, Any]] = []
    missing_producer = False
    for producer in authority["producers"]:
        try:
            collected_runs.append(_producer_run(api, repository, main, producer))
        except ProducerNotStarted:
            missing_producer = True
    run_values = tuple(collected_runs)
    terminal = all(
        value["attempts"][0]["status"] == "completed" for value in run_values
    )
    selected = tuple(
        (value["producer_id"], value["run_id"], value["attempts"][0]["run_attempt"])
        for value in run_values
    )
    if missing_producer or not terminal:
        return FinalizeResult("pending", "pending", ordinal, None, selected)
    captured_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    shared = {
        "admission_ordinal": str(ordinal),
        "control_plane_run_id": control_id,
        "control_plane_run_attempt": control_attempt,
        "control_plane_workflow": asdict(control_identity.workflow),
        "dispatch_sequence": 1,
        "candidate": {"checkout_sha": main.checkout_sha, "tree_sha": main.tree_sha},
        "collection_complete": True,
    }
    snapshots = [
        {
            "schema_version": "1.0",
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
        for value in run_values
    ]
    root = _prepare_output(output_dir)
    authority_path = root / "ci-authority.json"
    _write_exclusive(authority_path, authority)
    raw_dir = root / "raw"
    raw_dir.mkdir(mode=0o700)
    descriptors: list[dict[str, Any]] = []
    for snapshot in snapshots:
        producer_id = str(snapshot["producer_id"])
        relative = f"raw/{producer_id}.json"
        digest = _write_exclusive(root / relative, snapshot)
        descriptors.append(
            {
                "producer_id": producer_id,
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
        "profile_contract_version": "2.0",
        "producer": {
            "kind": "workflow",
            "provider": "github",
            "repository": repository,
            "repository_id": main.repository_id,
            "run_id": collector_identity.run_id,
            "run_attempt": str(collector_identity.run_attempt),
            "producer_id": "bcf-trusted-finalizer",
        },
        "expected_gate_inventory": ["ci-certification"],
        "expected_producer_inventory": sorted(str(value["producer_id"]) for value in run_values),
        "created_at": captured_at,
        "session_root_policy": {
            "mode": "0700",
            "root_kind": "external",
            "immutable_manifest": True,
        },
    }
    session_path = root / "evidence-session.json"
    session_digest = _write_exclusive(session_path, session)
    evidence_session = {
        "session_id": session["session_id"],
        "manifest_sha256": session_digest,
        "run_id": session["producer"]["run_id"],
        "run_attempt": int(session["producer"]["run_attempt"]),
    }
    report = normalize_ci_certification(
        _packaged_repo_root(),
        authority=authority,
        snapshots=snapshots,
        raw_snapshot_descriptors=descriptors,
        evidence_session=evidence_session,
        generated_at=captured_at,
    )
    report_path = root / "ci-certification.json"
    _write_exclusive(report_path, report)
    verification = verify_ci_certification(
        _packaged_repo_root(),
        authority_path=authority_path,
        certification_path=report_path,
        session_manifest_path=session_path,
    )
    (root / "bundle-manifest.json").write_bytes(
        _canonical(
            {
                "schema_version": "1.0",
                "subject": {"commit_sha": main.checkout_sha, "tree_sha": main.tree_sha},
                "admission_ordinal": str(ordinal),
                "computed_state": verification.computed_state,
                "files": {
                    path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in sorted(root.rglob("*.json"))
                    if path.name != "bundle-manifest.json"
                },
            }
        )
    )
    for path in root.rglob("*.json"):
        path.chmod(0o400)
    return FinalizeResult(
        "terminal",
        verification.computed_state,
        ordinal,
        str(root),
        selected,
    )


def publish(
    api: GitHubAPI,
    *,
    repository: str,
    bundle_dir: Path,
    target_url: str,
    collector_run_id: object,
    collector_run_attempt: object,
    collector_workflow_path: str,
    collector_workflow_id: object | None = None,
    collector_workflow_sha256: str | None = None,
) -> dict[str, Any]:
    """Reverify one authenticated finalizer bundle before status publication."""

    if bundle_dir.is_symlink():
        raise GitHubControllerError("certification bundle cannot be a symlink")
    root = bundle_dir.resolve()
    manifest = _verify_bundle(root)
    report = json.loads((root / "ci-certification.json").read_text(encoding="utf-8"))
    verification = verify_ci_certification(
        _packaged_repo_root(),
        authority_path=root / "ci-authority.json",
        certification_path=root / "ci-certification.json",
        session_manifest_path=root / "evidence-session.json",
    )
    if (
        manifest.get("subject")
        != {
            "commit_sha": report["subject"]["checkout_sha"],
            "tree_sha": report["subject"]["tree_sha"],
        }
        or str(manifest.get("admission_ordinal"))
        != str(report["admission"]["admission_ordinal"])
        or manifest.get("computed_state") != verification.computed_state
    ):
        raise GitHubControllerError(
            "certification bundle manifest does not match verified certification"
        )
    main = resolve_main(api, repository)
    subject = str(report["subject"]["checkout_sha"])
    subject_tree = str(report["subject"]["tree_sha"])
    subject_commit = api.commit(repository, subject)
    observed_tree = subject_commit.get("tree")
    if not isinstance(observed_tree, dict) or str(observed_tree.get("sha")) != subject_tree:
        raise GitHubControllerError("certification subject tree is not provider-authenticated")
    collector_main = MainIdentity(
        repository_id=main.repository_id,
        default_branch=main.default_branch,
        checkout_sha=subject,
        tree_sha=subject_tree,
    )
    collector_identity = authenticate_trusted_run(
        api,
        repository=repository,
        main=collector_main,
        run_id=collector_run_id,
        run_attempt=collector_run_attempt,
        workflow_path=collector_workflow_path,
        expected_event="workflow_run",
        require_success=True,
        expected_workflow_id=collector_workflow_id,
        expected_workflow_sha256=collector_workflow_sha256,
    )
    session = json.loads((root / "evidence-session.json").read_text(encoding="utf-8"))
    producer = session.get("producer")
    if not isinstance(producer, dict) or producer != {
        "kind": "workflow",
        "provider": "github",
        "repository": repository,
        "repository_id": main.repository_id,
        "run_id": collector_identity.run_id,
        "run_attempt": str(collector_identity.run_attempt),
        "producer_id": "bcf-trusted-finalizer",
    }:
        raise GitHubControllerError(
            "certification session is not bound to the authenticated finalizer run"
        )
    conclusion = (
        StatusConclusion.SUCCESS
        if verification.status == "pass"
        else StatusConclusion.FAILURE
    )
    proposed = StatusObservation(
        context=StatusContext.EXACT_MAIN,
        subject_sha=subject,
        admission_ordinal=int(report["admission"]["admission_ordinal"]),
        control_plane_attempt=int(report["admission"]["control_plane_run_attempt"]),
        conclusion=conclusion,
    )
    current = _current_status(api, repository, subject)
    decision = decide_status_publication(
        proposed=proposed,
        current=current,
        trusted_publisher=True,
        current_default_main_sha=main.checkout_sha,
    )
    if decision.publish:
        authoritative_url = _status_target(
            target_url,
            ordinal=proposed.admission_ordinal,
            attempt=proposed.control_plane_attempt,
        )
        api.status(
            repository,
            sha=subject,
            state=conclusion.value,
            context=STATUS_CONTEXT,
            description=f"BCF exact-main {verification.computed_state}",
            target_url=authoritative_url,
        )
    return {
        "status": "published" if decision.publish else "suppressed",
        "reason": decision.reason,
        "subject_sha": subject,
        "computed_state": verification.computed_state,
        "admission_ordinal": proposed.admission_ordinal,
    }


def _status_target(target_url: str, *, ordinal: int, attempt: int) -> str:
    parsed = urlsplit(target_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.fragment:
        raise GitHubControllerError("status target URL must be fragment-free HTTPS")
    query = parse_qs(parsed.query, keep_blank_values=True)
    if "bcf_ordinal" in query or "bcf_attempt" in query:
        raise GitHubControllerError("status target URL already contains BCF authority")
    query["bcf_ordinal"] = [str(ordinal)]
    query["bcf_attempt"] = [str(attempt)]
    encoded = urlencode(sorted((key, item) for key, values in query.items() for item in values))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, encoded, ""))


def _status_observation(payload: dict[str, Any], subject: str) -> StatusObservation:
    if payload.get("context") != STATUS_CONTEXT:
        raise GitHubControllerError("status observation has wrong context")
    target = payload.get("target_url")
    if not isinstance(target, str):
        raise GitHubControllerError("published BCF status lacks authority target URL")
    query = parse_qs(urlsplit(target).query)
    if set(query).intersection({"bcf_ordinal", "bcf_attempt"}) != {
        "bcf_ordinal", "bcf_attempt",
    }:
        raise GitHubControllerError("published BCF status lacks admission authority")
    if len(query["bcf_ordinal"]) != 1 or len(query["bcf_attempt"]) != 1:
        raise GitHubControllerError("published BCF status has duplicate admission authority")
    ordinal = _positive(query["bcf_ordinal"][0], field="published admission ordinal")
    attempt = _positive(query["bcf_attempt"][0], field="published control attempt")
    state = str(payload.get("state"))
    conclusions = {
        "success": StatusConclusion.SUCCESS,
        "failure": StatusConclusion.FAILURE,
        "error": StatusConclusion.FAILURE,
        "pending": StatusConclusion.PENDING,
    }
    if state not in conclusions:
        raise GitHubControllerError("published BCF status has unsupported state")
    return StatusObservation(
        context=StatusContext.EXACT_MAIN,
        subject_sha=subject,
        admission_ordinal=ordinal,
        control_plane_attempt=attempt,
        conclusion=conclusions[state],
    )


def _current_status(api: GitHubAPI, repository: str, subject: str) -> StatusObservation | None:
    matching = [
        value for value in api.commit_statuses(repository, sha=subject)
        if value.get("context") == STATUS_CONTEXT
    ]
    if not matching:
        return None
    observations = [_status_observation(value, subject) for value in matching]
    latest_order = max(
        (value.admission_ordinal, value.control_plane_attempt) for value in observations
    )
    latest = [
        value for value in observations
        if (value.admission_ordinal, value.control_plane_attempt) == latest_order
    ]
    if len({value.conclusion for value in latest}) != 1:
        raise GitHubControllerError("equal published authority has conflicting conclusions")
    return latest[0]


def environment_api() -> GitHubAPI:
    token = os.environ.get("GITHUB_TOKEN", "")
    api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    try:
        return GitHubAPI(token=token, api_url=api_url)
    except GitHubAPIError as exc:
        raise GitHubControllerError(str(exc)) from exc


def result_dict(value: KickoffResult | FinalizeResult) -> dict[str, Any]:
    return asdict(value)

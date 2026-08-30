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
from .ci_authority_decisions import (
    StatusConclusion,
    StatusContext,
    StatusObservation,
    decide_status_publication,
)
from .ci_github import DISPATCH_EVENTS, authenticate_github_run
from .ci_github_api import GitHubAPI, GitHubAPIError


SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")
STATUS_CONTEXT = "bcf/exact-main-certification"


class GitHubControllerError(ValueError):
    """Raised when trusted controller inputs or provider state fail closed."""


class _ProducerNotStarted(Exception):
    """Internal non-error signal for callback fan-in that is not complete yet."""


@dataclass(frozen=True)
class MainIdentity:
    repository_id: str
    default_branch: str
    checkout_sha: str
    tree_sha: str


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


@dataclass(frozen=True)
class FinalizeResult:
    status: str
    computed_state: str
    admission_ordinal: int
    bundle_dir: str | None
    producer_runs: tuple[tuple[str, str, int], ...]


def _sha(value: object, *, field: str) -> str:
    text = str(value)
    if not SHA_PATTERN.fullmatch(text):
        raise GitHubControllerError(f"{field} must be an exact 40-character Git SHA")
    return text


def _positive(value: object, *, field: str) -> int:
    if isinstance(value, bool):
        raise GitHubControllerError(f"{field} must be a positive integer")
    try:
        number = int(str(value))
    except ValueError as exc:
        raise GitHubControllerError(f"{field} must be a positive integer") from exc
    if number < 1:
        raise GitHubControllerError(f"{field} must be a positive integer")
    return number


def admission_ordinal(run_id: object, run_attempt: object, dispatch_sequence: object) -> int:
    """Map GitHub's authenticated total tuple to one positive total ordinal."""

    run = _positive(run_id, field="control-plane run ID")
    attempt = _positive(run_attempt, field="control-plane run attempt")
    sequence = _positive(dispatch_sequence, field="dispatch sequence")
    if attempt >= 1_000 or sequence >= 1_000:
        raise GitHubControllerError("attempt and dispatch sequence must be below 1000")
    return run * 1_000_000 + attempt * 1_000 + sequence


def resolve_main(api: GitHubAPI, repository: str) -> MainIdentity:
    repo = api.repository(repository)
    repository_id = str(_positive(repo.get("id"), field="repository ID"))
    branch = repo.get("default_branch")
    if not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9._/-]+", branch):
        raise GitHubControllerError("default branch is missing or unsafe")
    reference = api.reference(repository, f"heads/{branch}")
    target = reference.get("object")
    if not isinstance(target, dict) or target.get("type") != "commit":
        raise GitHubControllerError("default branch must resolve directly to a commit")
    commit_sha = _sha(target.get("sha"), field="default-main SHA")
    commit = api.commit(repository, commit_sha)
    tree = commit.get("tree")
    if not isinstance(tree, dict):
        raise GitHubControllerError("default-main commit tree is missing")
    return MainIdentity(
        repository_id=repository_id,
        default_branch=branch,
        checkout_sha=commit_sha,
        tree_sha=_sha(tree.get("sha"), field="default-main tree SHA"),
    )


def kickoff(
    api: GitHubAPI,
    *,
    repository: str,
    expected_sha: str,
    control_run_id: object,
    control_run_attempt: object,
    control_workflow_id: object,
    control_workflow_path: str,
    control_workflow_sha256: str,
    dispatch_sequence: object = 1,
    dispatch_exact_ref: bool,
) -> KickoffResult:
    """Authenticate one input-free exact-main run and optionally dispatch its worker."""

    main = resolve_main(api, repository)
    subject = _sha(expected_sha, field="kickoff SHA")
    if subject != main.checkout_sha:
        raise GitHubControllerError("kickoff subject is not current default main")
    run_id = str(_positive(control_run_id, field="control-plane run ID"))
    attempt = _positive(control_run_attempt, field="control-plane run attempt")
    sequence = _positive(dispatch_sequence, field="dispatch sequence")
    _authenticate_control_run(
        api,
        repository=repository,
        main=main,
        run_id=run_id,
        run_attempt=attempt,
        workflow_id=control_workflow_id,
        workflow_path=control_workflow_path,
        workflow_sha256=control_workflow_sha256,
        require_success=False,
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
    )


def _authenticate_control_run(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    run_id: object,
    run_attempt: object,
    workflow_id: object,
    workflow_path: str,
    workflow_sha256: str,
    require_success: bool,
) -> dict[str, Any]:
    numeric_run = str(_positive(run_id, field="control-plane run ID"))
    attempt = _positive(run_attempt, field="control-plane run attempt")
    numeric_workflow = str(_positive(workflow_id, field="control-plane workflow ID"))
    if not workflow_path.startswith(".github/workflows/") or ".." in workflow_path.split("/"):
        raise GitHubControllerError("control-plane workflow path is unsafe")
    if not re.fullmatch(r"[a-f0-9]{64}", workflow_sha256):
        raise GitHubControllerError("control-plane workflow digest must be SHA-256")
    run = api.run(repository, numeric_run)
    workflow = api.workflow(repository, numeric_workflow)
    content = api.content(repository, workflow_path, ref=main.checkout_sha)
    run_repository = run.get("repository")
    observed_repository_id = (
        str(run_repository.get("id")) if isinstance(run_repository, dict) else ""
    )
    observed_attempt = _positive(
        run.get("run_attempt"), field="observed control-plane run attempt"
    )
    authenticated = (
        str(run.get("id")) == numeric_run
        and str(run.get("workflow_id")) == numeric_workflow
        and observed_repository_id == main.repository_id
        and str(run.get("head_sha")) == main.checkout_sha
        and str(run.get("event")) == "push"
        and observed_attempt == attempt
        and str(workflow.get("id")) == numeric_workflow
        and str(workflow.get("path")) == workflow_path
        and hashlib.sha256(content.content).hexdigest() == workflow_sha256
    )
    if require_success:
        authenticated = authenticated and (
            run.get("status") == "completed" and run.get("conclusion") == "success"
        )
    if not authenticated:
        raise GitHubControllerError("control-plane run identity is not authenticated")
    return run


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


def _workflow_identity(
    api: GitHubAPI,
    repository: str,
    main: MainIdentity,
    producer: dict[str, Any],
    run: dict[str, Any],
) -> dict[str, str]:
    expected = producer["workflow"]
    workflow = api.workflow(repository, expected["workflow_id"])
    trusted = api.content(repository, expected["active_path"], ref=main.checkout_sha)
    identity = authenticate_github_run(
        expected_repository_id=main.repository_id,
        expected_workflow_id=str(expected["workflow_id"]),
        expected_active_path=str(expected["active_path"]),
        allowed_events=tuple(str(value) for value in expected["allowed_events"]),
        repository={"id": int(main.repository_id)},
        workflow=workflow,
        run=run,
        trusted_workflow_bytes=trusted.content,
        trusted_workflow_blob_oid=trusted.blob_oid,
        trusted_workflow_definition_commit=str(expected["trusted_workflow_definition_commit"]),
        candidate_tree_sha=main.tree_sha,
    )
    observed = asdict(identity.workflow)
    pinned = {
        "workflow_id": str(expected["workflow_id"]),
        "active_path": str(expected["active_path"]),
        "trusted_workflow_blob_oid": str(expected["trusted_workflow_blob_oid"]),
        "trusted_workflow_sha256": str(expected["trusted_workflow_sha256"]),
        "trusted_workflow_definition_commit": str(expected["trusted_workflow_definition_commit"]),
    }
    if any(str(observed[key]) != value for key, value in pinned.items()):
        raise GitHubControllerError(
            f"producer {producer['producer_id']} trusted workflow bytes do not match authority"
        )
    return {key: str(value) for key, value in observed.items()}


def _selected_run(
    api: GitHubAPI,
    repository: str,
    main: MainIdentity,
    producer: dict[str, Any],
) -> dict[str, Any]:
    expected = producer["workflow"]
    candidates: list[dict[str, Any]] = []
    for event in expected["allowed_events"]:
        candidates.extend(
            api.workflow_runs(
                repository,
                expected["workflow_id"],
                head_sha=main.checkout_sha,
                event=str(event),
            )
        )
    exact = [
        run
        for run in candidates
        if str(run.get("head_sha")) == main.checkout_sha
        and str(run.get("workflow_id")) == str(expected["workflow_id"])
        and str(run.get("repository", {}).get("id")) == main.repository_id
    ]
    if not exact:
        raise _ProducerNotStarted
    return max(exact, key=lambda value: (int(value["id"]), int(value["run_attempt"])))


def _producer_run(
    api: GitHubAPI,
    repository: str,
    main: MainIdentity,
    producer: dict[str, Any],
) -> dict[str, Any]:
    run = _selected_run(api, repository, main, producer)
    attempt = _positive(run.get("run_attempt"), field="producer run attempt")
    jobs = api.jobs(repository, run["id"], attempt=attempt)
    return {
        "producer_id": str(producer["producer_id"]),
        "run_id": str(_positive(run.get("id"), field="producer run ID")),
        "workflow": _workflow_identity(api, repository, main, producer, run),
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
    control_workflow_id: object,
    control_workflow_path: str,
    control_workflow_sha256: str,
    collector_run_id: object,
    collector_run_attempt: object,
    output_dir: Path,
) -> FinalizeResult:
    """Reconstruct all producers and write a terminal normalized bundle once."""

    main = resolve_main(api, repository)
    authority = _load_authority(api, repository, main)
    control_id = str(_positive(control_run_id, field="control-plane run ID"))
    control_attempt = _positive(control_run_attempt, field="control-plane run attempt")
    _authenticate_control_run(
        api,
        repository=repository,
        main=main,
        run_id=control_id,
        run_attempt=control_attempt,
        workflow_id=control_workflow_id,
        workflow_path=control_workflow_path,
        workflow_sha256=control_workflow_sha256,
        require_success=True,
    )
    ordinal = admission_ordinal(control_id, control_attempt, 1)
    collected_runs: list[dict[str, Any]] = []
    missing_producer = False
    for producer in authority["producers"]:
        try:
            collected_runs.append(_producer_run(api, repository, main, producer))
        except _ProducerNotStarted:
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
            "run_id": str(_positive(collector_run_id, field="collector run ID")),
            "run_attempt": str(_positive(collector_run_attempt, field="collector run attempt")),
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
) -> dict[str, Any]:
    """Reverify a trusted bundle and publish only its current exact-main result."""

    root = bundle_dir.resolve()
    report = json.loads((root / "ci-certification.json").read_text(encoding="utf-8"))
    verification = verify_ci_certification(
        _packaged_repo_root(),
        authority_path=root / "ci-authority.json",
        certification_path=root / "ci-certification.json",
        session_manifest_path=root / "evidence-session.json",
    )
    main = resolve_main(api, repository)
    subject = str(report["subject"]["checkout_sha"])
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

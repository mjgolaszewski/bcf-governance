"""Canonical local pull-request context and validation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from typing import Any, Callable, Iterator, Mapping
from contextlib import contextmanager

from jsonschema import Draft202012Validator

from .ci_graph_contracts import CIGraphError, validate_ci_graph
from .ci_graph_execution import exact_main_evaluation
from .ci_authority_decisions import status_context_for_evaluation
from .ci_exact_main_truth import validate_exact_main_truth_payload
from .ci_github_identity import GitHubControllerError
from .evaluation_scope import (
    EvaluationIntent,
    EvaluationScopeError,
    evaluation_scope,
    is_terminal_phase_certification,
)
from .evidence_execution import EvidenceError
from .evidence_scheduling import receipt_duration_ms
from .evidence_sessions import local_producer_identity, select_session
from .governance_evidence import capture_gate
from .governance_truth import TruthfulnessError, derive_truth
from .preflight import PreflightError, run_preflight
from .routine_controller_rotation import (
    ROTATION_POLICY_PATHS,
    alternate_policy_lane_contract,
    controller_policy_digest,
)
from .scaffold_governance_artifacts import ReconcileError, reconcile_steps


class LocalPRError(ValueError):
    """Raised before validation when local and remote PR identity cannot agree."""


Runner = Callable[..., subprocess.CompletedProcess[str]]


BOUNDARY_CHAIN = (
    "preflight",
    "controller_compatibility",
    "pr_evidence",
    "certification",
    "merge",
    "exact_main",
    "controller_lifecycle",
    "bounded_or_phase_truth",
    "finalizer",
    "publisher",
    "successor_or_release_eligibility",
)


class ProspectiveValidationError(ValueError):
    """The exact candidate has a mechanically knowable downstream rejection."""


@dataclass(frozen=True)
class LocalPRContext:
    remote: str
    default_branch: str
    base_sha: str
    head_sha: str
    head_ref: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class CandidateIdentity:
    commit_sha: str
    tree_sha: str
    base_sha: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)


def _checked(
    runner: Runner,
    command: list[str],
    *,
    cwd: Path,
) -> str:
    result = runner(command, cwd=cwd)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise LocalPRError(f"{' '.join(command)}: {detail}")
    return result.stdout.strip()


def resolve_local_pr_context(
    repo_root: Path,
    *,
    remote: str = "origin",
    runner: Runner = _run,
) -> LocalPRContext:
    """Resolve/fetch remote default branch and prove current HEAD descends from it."""

    repo_root = repo_root.resolve()
    symbolic = _checked(
        runner,
        ["git", "ls-remote", "--symref", remote, "HEAD"],
        cwd=repo_root,
    )
    prefix = "ref: refs/heads/"
    default_branch = ""
    for line in symbolic.splitlines():
        if line.startswith(prefix) and line.endswith("\tHEAD"):
            default_branch = line[len(prefix) : -len("\tHEAD")]
            break
    if not default_branch or "/" in default_branch and default_branch.startswith("../"):
        raise LocalPRError("remote HEAD did not identify a safe default branch")
    remote_ref = f"refs/remotes/{remote}/{default_branch}"
    _checked(
        runner,
        [
            "git",
            "fetch",
            "--no-tags",
            remote,
            f"refs/heads/{default_branch}:{remote_ref}",
        ],
        cwd=repo_root,
    )
    base_sha = _checked(runner, ["git", "rev-parse", "--verify", remote_ref], cwd=repo_root)
    head_sha = _checked(runner, ["git", "rev-parse", "--verify", "HEAD"], cwd=repo_root)
    ancestry = runner(
        ["git", "merge-base", "--is-ancestor", base_sha, head_sha], cwd=repo_root
    )
    if ancestry.returncode != 0:
        raise LocalPRError("current HEAD does not descend from the fetched default branch")
    head_ref = _checked(
        runner, ["git", "branch", "--show-current"], cwd=repo_root
    ) or "detached-head"
    return LocalPRContext(
        remote=remote,
        default_branch=default_branch,
        base_sha=base_sha,
        head_sha=head_sha,
        head_ref=head_ref,
    )


def _pr_environment_values(
    context: LocalPRContext, *, event_path: str | None = None
) -> dict[str, str]:
    values = {
        "BCF_ENFORCE_PR_CHANGELOG": "true",
        "BCF_PR_BASE_SHA": context.base_sha,
        "GITHUB_BASE_REF": context.default_branch,
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_HEAD_REF": context.head_ref,
        "GITHUB_SHA": context.head_sha,
    }
    if event_path is not None:
        values["GITHUB_EVENT_PATH"] = event_path
    return values


def run_local_pr_validation(
    repo_root: Path,
    *,
    command: tuple[str, ...],
    remote: str = "origin",
    runner: Runner = _run,
) -> subprocess.CompletedProcess[str]:
    """Run exact argv with the same base and event identity used by remote PR CI."""

    if not command or any(not value for value in command):
        raise LocalPRError("local PR validation requires non-empty exact argv")
    context = resolve_local_pr_context(repo_root, remote=remote, runner=runner)
    event = {
        "pull_request": {
            "base": {"ref": context.default_branch, "sha": context.base_sha},
            "head": {"ref": context.head_ref, "sha": context.head_sha},
        },
        "repository": {"default_branch": context.default_branch},
    }
    with tempfile.TemporaryDirectory(prefix="bcf-local-pr-") as temporary:
        event_path = Path(temporary) / "event.json"
        event_path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")
        environment = os.environ.copy()
        environment.update(_pr_environment_values(context, event_path=str(event_path)))
        return runner(list(command), cwd=repo_root.resolve(), env=environment)


def _candidate_identity(
    repo_root: Path, context: LocalPRContext, *, runner: Runner
) -> CandidateIdentity:
    head = _checked(runner, ["git", "rev-parse", "--verify", "HEAD"], cwd=repo_root)
    tree = _checked(runner, ["git", "rev-parse", "--verify", "HEAD^{tree}"], cwd=repo_root)
    status = _checked(
        runner,
        ["git", "status", "--porcelain=v1", "--untracked-files=all", "--ignored=no"],
        cwd=repo_root,
    )
    if status:
        raise ProspectiveValidationError("prospective validation requires a clean committed tree")
    if head != context.head_sha:
        raise ProspectiveValidationError("local PR context does not bind current HEAD")
    return CandidateIdentity(head, tree, context.base_sha)


@contextmanager
def _pr_environment(context: LocalPRContext) -> Iterator[None]:
    values = _pr_environment_values(context)
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _changed_paths(
    repo_root: Path, identity: CandidateIdentity, *, runner: Runner
) -> tuple[str, ...]:
    output = _checked(
        runner,
        ["git", "diff", "--name-only", identity.base_sha, identity.commit_sha],
        cwd=repo_root,
    )
    return tuple(sorted(value for value in output.splitlines() if value))


def _git_blob(repo_root: Path, *, ref: str, path: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ProspectiveValidationError(
            f"cannot resolve controller policy {path} at {ref}: {detail or 'git show failed'}"
        )
    return result.stdout


def _controller_policy_identity(
    repo_root: Path, identity: CandidateIdentity, *, runner: Runner
) -> dict[str, Any]:
    source_tree = _checked(
        runner,
        ["git", "rev-parse", "--verify", f"{identity.base_sha}^{{tree}}"],
        cwd=repo_root,
    )
    source_digest = controller_policy_digest(
        lambda path: _git_blob(repo_root, ref=identity.base_sha, path=path)
    )
    candidate_digest = controller_policy_digest(
        lambda path: _git_blob(repo_root, ref=identity.commit_sha, path=path)
    )
    return {
        "source": {
            "commit_sha": identity.base_sha,
            "tree_sha": source_tree,
            "policy_sha256": source_digest,
        },
        "candidate": {
            "commit_sha": identity.commit_sha,
            "tree_sha": identity.tree_sha,
            "policy_sha256": candidate_digest,
        },
    }


def _confirm_unchanged(
    repo_root: Path,
    *,
    initial_context: LocalPRContext,
    initial_identity: CandidateIdentity,
    remote: str,
    runner: Runner,
) -> None:
    current_context = resolve_local_pr_context(repo_root, remote=remote, runner=runner)
    if current_context != initial_context:
        raise ProspectiveValidationError(
            "remote PR base or local branch identity changed during validation"
        )
    current_identity = _candidate_identity(repo_root, current_context, runner=runner)
    if current_identity != initial_identity:
        raise ProspectiveValidationError(
            "candidate commit or tree changed during validation"
        )


def _capture_planned_evidence(
    repo_root: Path,
    *,
    python_executable: Path,
    session_manifest: Path,
    session_root: Path,
    producers: tuple[str, ...],
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for producer in producers:
        receipt = capture_gate(
            repo_root,
            producer,
            session_root / producer,
            python_executable=python_executable,
            session_manifest=session_manifest,
        )
        if not receipt.is_file():
            raise ProspectiveValidationError(
                f"local evidence producer {producer} emitted no receipt"
            )
        payload = json.loads(receipt.read_text(encoding="utf-8"))
        duration = receipt_duration_ms(payload)
        if duration is None:
            raise ProspectiveValidationError(
                f"local evidence producer {producer} emitted no valid duration"
            )
        observations.append(
            {
                "producer": producer,
                "duration_ms": duration,
                "claim_count": len(payload.get("claims") or ()),
                "control_count": len(payload.get("behavioral_probes") or ()),
            }
        )
    return observations


def _elapsed_ms(started_ns: int) -> int:
    return max(0, (time.monotonic_ns() - started_ns) // 1_000_000)


def _validate_train_telemetry(repo_root: Path, telemetry: dict[str, Any]) -> None:
    expected_stages = {
        "fixed_point", "planning", "reuse", "setup", "producers",
        "positive_tests", "controls", "normalization", "truth",
        "finalization", "publication",
    }
    observed_stages = [
        str(item.get("stage")) for item in telemetry.get("measurements", ())
        if isinstance(item, dict)
    ]
    if len(observed_stages) != len(set(observed_stages)) or set(observed_stages) != expected_stages:
        raise ProspectiveValidationError(
            "prospective train telemetry stage inventory is not exact"
        )
    producers = [
        str(item.get("producer")) for item in telemetry.get("producer_observations", ())
        if isinstance(item, dict)
    ]
    if len(producers) != len(set(producers)):
        raise ProspectiveValidationError(
            "prospective train telemetry producer inventory is not unique"
        )
    schema = json.loads(
        (repo_root / "schemas/prospective-train-telemetry.schema.json").read_text(
            encoding="utf-8"
        )
    )
    errors = sorted(
        Draft202012Validator(schema).iter_errors(telemetry),
        key=lambda item: list(item.path),
    )
    if errors:
        raise ProspectiveValidationError(
            "prospective train telemetry is invalid: " + errors[0].message
        )


def _require_truth(report: Mapping[str, Any], *, boundary: str) -> dict[str, Any]:
    if report.get("status") != "pass":
        detail = ", ".join(str(value) for value in report.get("issues") or ())
        raise ProspectiveValidationError(
            f"{boundary} rejected candidate: {detail or 'truth failed'}"
        )
    return dict(report)


def _run_prospective_train(
    repo_root: Path,
    *,
    semantic_intent: str,
    evaluation_target: str | None,
    subject_commit: str,
    subject_tree: str,
    remote: str = "origin",
    python_executable: Path,
    execute_evidence: bool = True,
    runner: Runner = _run,
) -> dict[str, Any]:
    """Walk every knowable boundary while preserving provider-required authority."""

    root = repo_root.resolve()
    context = resolve_local_pr_context(root, remote=remote, runner=runner)
    identity = _candidate_identity(root, context, runner=runner)
    measurements: list[dict[str, Any]] = []
    if re.fullmatch(r"[a-f0-9]{40}", subject_commit) is None or re.fullmatch(
        r"[a-f0-9]{40}", subject_tree
    ) is None:
        raise ProspectiveValidationError("prospective train subject identity is malformed")
    if (subject_commit, subject_tree) != (identity.commit_sha, identity.tree_sha):
        raise ProspectiveValidationError(
            "prospective train subject does not match the exact committed tree"
        )
    try:
        requested_scope = evaluation_scope(
            semantic_intent,
            target=evaluation_target,
            phase_id="P00",
            subject_commit=subject_commit,
        )
    except EvaluationScopeError as exc:
        raise ProspectiveValidationError(str(exc)) from exc
    try:
        reconcile_started = time.monotonic_ns()
        for step in reconcile_steps(root, python_executable.resolve()):
            step.check()
        reconcile_duration = _elapsed_ms(reconcile_started)
        measurements.extend(
            [
                {"stage": "fixed_point", "status": "observed", "duration_ms": reconcile_duration},
                {"stage": "normalization", "status": "observed", "duration_ms": reconcile_duration},
            ]
        )
        evaluation = exact_main_evaluation(validate_ci_graph(root).workflows)
        post_merge_mode, post_merge_target = evaluation.mode, evaluation.target
    except (
        CIGraphError,
        ReconcileError,
        PreflightError,
        TruthfulnessError,
        EvidenceError,
    ) as exc:
        raise ProspectiveValidationError(str(exc)) from exc
    expected_target = (
        requested_scope.target_id
        if requested_scope.intent is EvaluationIntent.WORKITEM_CERTIFICATION
        else None
    )
    if (post_merge_mode, post_merge_target) != (
        requested_scope.intent.value,
        expected_target,
    ):
        raise ProspectiveValidationError(
            "prospective train intent/target does not match the canonical exact-main graph"
        )
    changed_paths = _changed_paths(root, identity, runner=runner)
    transition_class = (
        "protected_policy_change"
        if set(changed_paths).intersection(ROTATION_POLICY_PATHS)
        else "runtime_only"
    )
    policy_identity = _controller_policy_identity(root, identity, runner=runner)
    if (
        transition_class == "protected_policy_change"
        and policy_identity["source"]["policy_sha256"]
        == policy_identity["candidate"]["policy_sha256"]
    ):
        raise ProspectiveValidationError(
            "protected controller-policy paths changed without a policy identity change"
        )
    boundaries: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="bcf-prospective-") as temporary:
        artifact_root = Path(temporary) / "evidence"
        with _pr_environment(context):
            try:
                preflight_started = time.monotonic_ns()
                preflight = run_preflight(
                    root,
                    mode="pr",
                    python_executable=python_executable,
                    artifact_root=(artifact_root if execute_evidence else None),
                    expected_producers=(["prospective-local"] if execute_evidence else None),
                    producer_identity=(
                        local_producer_identity(root, "prospective-local")
                        if execute_evidence else None
                    ),
                    evaluation_mode="pr",
                )
                preflight_duration = _elapsed_ms(preflight_started)
            except (PreflightError, EvidenceError) as exc:
                raise ProspectiveValidationError(str(exc)) from exc
        if preflight.get("status") != "pass":
            raise ProspectiveValidationError("canonical PR preflight did not pass")
        measurements.extend(
            [
                {"stage": "planning", "status": "observed", "duration_ms": preflight_duration},
                {"stage": "reuse", "status": "included", "parent": "planning"},
                {"stage": "setup", "status": "included", "parent": "planning"},
            ]
        )
        boundaries.append({"id": "preflight", "state": "proved", "authority": "local"})
        controller = preflight.get("self_controller")
        controller_state = (
            str(controller.get("status")) if isinstance(controller, dict) else "current"
        )
        if controller_state not in {"current", "pending_rotation"}:
            raise ProspectiveValidationError(
                f"controller compatibility is not admissible: {controller_state}"
            )
        transition_requirement = (
            "no_transition"
            if controller_state == "current"
            else "alternate_lane_required"
            if transition_class == "protected_policy_change"
            else "provider_routine_transition_required"
        )
        boundaries.append(
            {
                "id": "controller_compatibility",
                "state": "proved",
                "authority": "installed_controller_parser",
                "controller_state": controller_state,
                "transition_class": transition_class,
                "transition_requirement": transition_requirement,
                "policy_identity": policy_identity,
                **(
                    {"alternate_lane": alternate_policy_lane_contract()}
                    if transition_requirement == "alternate_lane_required"
                    else {}
                ),
                "release_authority": False,
            }
        )
        if not execute_evidence:
            report = {
                "schema_version": "1.0",
                "status": "deterministic_front_door_pass",
                "subject": identity.as_dict(),
                "changed_paths": list(changed_paths),
                "post_merge_evaluation": {
                    "mode": post_merge_mode,
                    "target": post_merge_target,
                },
                "boundaries": boundaries,
                "provider_authority_substituted": False,
            }
            _confirm_unchanged(
                root,
                initial_context=context,
                initial_identity=identity,
                remote=remote,
                runner=runner,
            )
            return report

        try:
            session = select_session(artifact_root / "sessions")
        except EvidenceError as exc:
            raise ProspectiveValidationError(str(exc)) from exc
        nodes = preflight["verification_plan"]["execution_dag"]["nodes"]
        producers = tuple(sorted({str(node["producer"]) for node in nodes}))
        try:
            evidence_started = time.monotonic_ns()
            producer_observations = _capture_planned_evidence(
                root,
                python_executable=python_executable.resolve(),
                session_manifest=session.manifest_path,
                session_root=session.root,
                producers=producers,
            ) or []
            evidence_duration = _elapsed_ms(evidence_started)
            measurements.extend(
                [
                    {"stage": "producers", "status": "observed", "duration_ms": evidence_duration},
                    {"stage": "positive_tests", "status": "included", "parent": "producers"},
                    {"stage": "controls", "status": "included", "parent": "producers"},
                ]
            )
            truth_started = time.monotonic_ns()
            pr_truth = _require_truth(
                derive_truth(root, session.root, evaluation_mode="pr"),
                boundary="PR truth",
            )
            pr_truth_duration = _elapsed_ms(truth_started)
        except (EvidenceError, TruthfulnessError) as exc:
            raise ProspectiveValidationError(str(exc)) from exc
        if pr_truth.get("merge_eligibility") != "eligible":
            raise ProspectiveValidationError("local PR truth is not merge eligible")
        boundaries.append(
            {
                "id": "pr_evidence",
                "state": "proved_non_authoritative",
                "authority": "local_exact_tree_receipts",
                "producers": list(producers),
                "bundle_sha256": pr_truth["bundle_sha256"],
            }
        )
        boundaries.extend(
            [
                {"id": "certification", "state": "provider_required"},
                {"id": "merge", "state": "provider_required"},
                {
                    "id": "exact_main",
                    "state": "fresh_provider_subject_required",
                    "mode": post_merge_mode,
                    "target": post_merge_target,
                },
                {
                    "id": "controller_lifecycle",
                    "state": (
                        "rotation_required" if controller_state == "pending_rotation"
                        else "ordinary_current_required"
                    ),
                    "transition_class": transition_class,
                    **(
                        {"alternate_lane": alternate_policy_lane_contract()}
                        if transition_class == "protected_policy_change"
                        else {}
                    ),
                },
            ]
        )
        try:
            bounded_truth_started = time.monotonic_ns()
            bounded_truth = _require_truth(
                derive_truth(
                    root,
                    session.root,
                    evaluation_mode=post_merge_mode,
                    evaluation_target=post_merge_target,
                ),
                boundary="post-merge semantic truth projection",
            )
            bounded_truth_duration = _elapsed_ms(bounded_truth_started)
        except TruthfulnessError as exc:
            raise ProspectiveValidationError(str(exc)) from exc
        subject = {"commit_sha": identity.commit_sha, "tree_sha": identity.tree_sha}
        try:
            proposition = validate_exact_main_truth_payload(
                bounded_truth, subject=subject
            )
        except GitHubControllerError as exc:
            raise ProspectiveValidationError(str(exc)) from exc
        proposition_sha256 = hashlib.sha256(
            json.dumps(proposition, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        boundaries.extend(
            [
                {
                    "id": "bounded_or_phase_truth",
                    "state": "proved_semantics_provider_reexecution_required",
                    "proposition": proposition,
                },
                {
                    "id": "finalizer",
                    "state": "provider_required",
                    "proposition_sha256": proposition_sha256,
                },
                {
                    "id": "publisher",
                    "state": "provider_required",
                    "scope": post_merge_mode,
                    "status_context": status_context_for_evaluation(
                        post_merge_mode
                    ).value,
                },
                {
                    "id": "successor_or_release_eligibility",
                    "state": "proved_scope",
                    "eligible_successors": proposition["eligible_successors"],
                    "release_authority": is_terminal_phase_certification(
                        {
                            "evaluation_scope": bounded_truth["evaluation_scope"],
                            "certified_proposition": proposition,
                        }
                    ),
                },
            ]
        )
        measurements.extend(
            [
                {
                    "stage": "truth",
                    "status": "observed",
                    "duration_ms": pr_truth_duration + bounded_truth_duration,
                },
                {"stage": "finalization", "status": "provider_required"},
                {"stage": "publication", "status": "provider_required"},
            ]
        )
    if tuple(item["id"] for item in boundaries) != BOUNDARY_CHAIN:
        raise ProspectiveValidationError("prospective authority boundary inventory is not exact")
    _confirm_unchanged(
        root,
        initial_context=context,
        initial_identity=identity,
        remote=remote,
        runner=runner,
    )
    telemetry = {
        "schema_version": "1.0",
        "subject": {"commit_sha": identity.commit_sha, "tree_sha": identity.tree_sha},
        "measurements": measurements,
        "producer_observations": producer_observations,
    }
    _validate_train_telemetry(root, telemetry)
    return {
        "schema_version": "1.0",
        "status": "prospectively_admissible_provider_proof_required",
        "subject": identity.as_dict(),
        "changed_paths": list(changed_paths),
        "post_merge_evaluation": {
            "mode": post_merge_mode,
            "target": post_merge_target,
        },
        "boundaries": boundaries,
        "provider_authority_substituted": False,
        "telemetry": telemetry,
        "ephemeral_state": {
            "scope": "exact_prospective_run",
            "state": "retired",
        },
    }


def run_prospective_train(
    repo_root: Path,
    *,
    semantic_intent: str,
    evaluation_target: str | None,
    subject_commit: str,
    subject_tree: str,
    remote: str = "origin",
    python_executable: Path,
    runner: Runner = _run,
) -> dict[str, Any]:
    """Execute the complete locally knowable chain; no partial public mode exists."""

    return _run_prospective_train(
        repo_root,
        semantic_intent=semantic_intent,
        evaluation_target=evaluation_target,
        subject_commit=subject_commit,
        subject_tree=subject_tree,
        remote=remote,
        python_executable=python_executable,
        execute_evidence=True,
        runner=runner,
    )

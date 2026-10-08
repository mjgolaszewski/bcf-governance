"""Canonical local pull-request context and validation."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Any, Callable, Mapping

from .ci_graph_contracts import CIGraphError, validate_ci_graph
from .ci_graph_post_merge import post_merge_evaluation
from .ci_authority_pins import verify_provider_workflow_authority
from .ci_controller_policy import graph_controller_policy_path
from .ci_authority_prospective_lanes import (
    ProspectiveLaneError,
    ordinary_authority_applicability,
    prospective_policy_binding,
    provider_boundaries,
    terminal_boundaries,
)
from .ci_exact_main_truth import validate_exact_main_truth_payload
from .ci_github_identity import GitHubControllerError
from .ci_graph_execution import local_gate_job_environments
from .controller_custody_prospective import validate_controller_custody_graph
from .evaluation_scope import (
    EvaluationIntent,
    EvaluationScopeError,
    evaluation_scope,
)
from .evidence_execution import EvidenceError
from .evidence_sessions import allocate_session, local_producer_identity
from .evidence_workitem_lifecycle import (
    WorkitemContractError,
    validate_evaluation_authored_ready,
)
from .governance_truth import TruthfulnessError, derive_truth
from .preflight import PreflightError, run_preflight
from .ci_authority_prospective_telemetry import (
    ProspectiveTelemetryError,
    elapsed_ms as _elapsed_ms,
    validate_train_telemetry,
)
from .ci_github_api import GitHubAPI
from .routine_controller_provider import effective_controller_authority
from .trusted_controller_compatibility import classify_trusted_controller_applicability
from .routine_controller_rotation import alternate_policy_lane_contract
from .repository_comparison_context import local_push_environment
from .scaffold_governance_artifacts import (
    ReconcileError,
    check_reconcile_steps,
    reconcile_steps,
)
from .local_execution_admission import (
    LocalExecutionAdmissionError,
    local_gate_lease,
    selected_toolchain_environment,
    validate_local_toolchain,
)
from .local_proof_bundles import (
    LocalProofBundleError,
    cached_producer_observations,
    capture_producers,
    proof_identity,
    restore_proof_bundle,
    store_proof_bundle,
)
from .operational_observations import (
    amplification_observation,
    lifecycle_projection,
    progress_event,
    validate_operational_observation,
    validate_progress_stream,
)
from .local_pr_context import (
    CandidateIdentity,
    LocalPRContext,
    LocalPRError,
    LocalValidationLane,
    ProspectiveValidationError,
    Runner,
    _checked,
    _candidate_identity,
    _changed_paths,
    _confirm_unchanged as _confirm_context_unchanged,
    _pr_environment,
    _run,
    resolve_local_pr_context,
    run_local_pr_validation,
)


ProgressSink = Callable[[dict[str, Any]], None]
_capture_planned_evidence = capture_producers


def _confirm_unchanged(
    repo_root: Path,
    *,
    initial_context: LocalPRContext,
    initial_identity: CandidateIdentity,
    remote: str,
    runner: Runner,
) -> None:
    """Reauthenticate through this module's injectable canonical resolvers."""

    _confirm_context_unchanged(
        repo_root,
        initial_context=initial_context,
        initial_identity=initial_identity,
        remote=remote,
        runner=runner,
        context_resolver=resolve_local_pr_context,
        identity_resolver=_candidate_identity,
    )


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


def _require_truth(report: Mapping[str, Any], *, boundary: str) -> dict[str, Any]:
    if report.get("status") != "pass":
        detail = ", ".join(str(value) for value in report.get("issues") or ())
        raise ProspectiveValidationError(
            f"{boundary} rejected candidate: {detail or 'truth failed'}"
        )
    return dict(report)


def _validate_train_telemetry(repo_root: Path, telemetry: dict[str, Any]) -> None:
    try:
        validate_train_telemetry(repo_root, telemetry)
    except ProspectiveTelemetryError as exc:
        raise ProspectiveValidationError(str(exc)) from exc


def canonical_prospective_inputs(
    repo_root: Path,
    *,
    remote: str = "origin",
    runner: Runner = _run,
) -> dict[str, str | None]:
    """Derive the immutable subject and proposition for a local train."""

    root = repo_root.resolve()
    context = resolve_local_pr_context(root, remote=remote, runner=runner)
    identity = _candidate_identity(root, context, runner=runner)
    try:
        evaluation = post_merge_evaluation(validate_ci_graph(root).graph)
    except CIGraphError as exc:
        raise ProspectiveValidationError(str(exc)) from exc
    return {
        "semantic_intent": evaluation.mode,
        "evaluation_target": evaluation.target,
        "subject_commit": identity.commit_sha,
        "subject_tree": identity.tree_sha,
    }


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
    controller_authority: Mapping[str, Any] | None = None,
    repository: str | None = None,
    provider_api: GitHubAPI | None = None,
    toolchain_identity: Mapping[str, Any] | None = None,
    validation_lane: LocalValidationLane = LocalValidationLane.PROVIDER_PR,
    runner: Runner = _run,
    progress_sink: ProgressSink | None = None,
) -> dict[str, Any]:
    """Walk every knowable boundary while preserving provider-required authority."""

    root = repo_root.resolve()
    context = resolve_local_pr_context(root, remote=remote, runner=runner)
    identity = _candidate_identity(root, context, runner=runner)
    measurements: list[dict[str, Any]] = []
    progress: list[dict[str, Any]] = []
    progress_started = time.monotonic_ns()

    def emit(stage: str, state: str) -> None:
        event = progress_event(
            execution_id=subject_commit,
            sequence=len(progress) + 1,
            stage=stage,
            state=state,
            monotonic_ms=_elapsed_ms(progress_started),
        )
        progress.append(event)
        validate_operational_observation(root, event)
        if progress_sink is not None:
            progress_sink(event)

    def fail_stage(stage: str) -> None:
        if progress and progress[-1]["stage"] == stage and progress[-1]["state"] == "started":
            emit(stage, "failed")
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
        validate_evaluation_authored_ready(
            root, intent=requested_scope.intent.value, target=requested_scope.target_id
        )
    except (EvaluationScopeError, WorkitemContractError) as exc:
        raise ProspectiveValidationError(str(exc)) from exc
    try:
        emit("fixed_point", "started")
        reconcile_started = time.monotonic_ns()
        reconciliation = check_reconcile_steps(
            root, reconcile_steps(root, python_executable)
        )
        reconcile_duration = _elapsed_ms(reconcile_started)
        measurements.extend(
            [
                {"stage": "fixed_point", "status": "observed", "duration_ms": reconcile_duration},
                {"stage": "normalization", "status": "observed", "duration_ms": reconcile_duration},
            ]
        )
        evaluation, custody_contract = validate_controller_custody_graph(root, python_executable=python_executable)
        post_merge_mode, post_merge_target = evaluation.mode, evaluation.target
        emit("fixed_point", "complete")
    except (
        CIGraphError,
        GitHubControllerError,
        ReconcileError,
        PreflightError,
        TruthfulnessError,
        EvidenceError,
    ) as exc:
        fail_stage("fixed_point")
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
            "prospective train intent/target does not match canonical post-merge authority"
        )
    changed_paths = _changed_paths(root, identity, runner=runner)
    custody_state = str(custody_contract.get("custody_state", "managed_controller"))
    try:
        base_tree = _checked(
            runner,
            ["git", "rev-parse", "--verify", f"{identity.base_sha}^{{tree}}"],
            cwd=root,
        )
        transition_class, policy_identity = prospective_policy_binding(
            root,
            lane=evaluation.lane,
            custody_state=custody_state,
            changed_paths=changed_paths,
            base_sha=identity.base_sha,
            base_tree=base_tree,
            candidate_sha=identity.commit_sha,
            candidate_tree=identity.tree_sha,
        )
    except ProspectiveLaneError as exc:
        raise ProspectiveValidationError(str(exc)) from exc
    authority_applicability = None
    if custody_state == "ordinary_executable_controller":
        try:
            authority_applicability = ordinary_authority_applicability(policy_identity)
        except ProspectiveLaneError as exc:
            raise ProspectiveValidationError(str(exc)) from exc
    verify_provider_authority = repository is not None and (
        custody_state != "ordinary_executable_controller"
        or authority_applicability == "provider_verification_required"
    )
    if verify_provider_authority:
        if provider_api is None:
            raise ProspectiveValidationError(
                "provider-authenticated prospective validation requires a provider API"
            )
        verify_provider_workflow_authority(
            root,
            authority_path=Path("governance/ci-authority.yml"),
            api=provider_api,
            repository=repository,
        )
        graph = validate_ci_graph(root).graph
        if graph_controller_policy_path(graph) is not None:
            controller_authority = effective_controller_authority(
                provider_api, repository=repository
            )
    boundaries: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="bcf-prospective-") as temporary:
        artifact_root = Path(temporary) / "evidence"
        with _pr_environment(context, validation_lane=validation_lane):
            try:
                emit("preflight", "started")
                preflight_started = time.monotonic_ns()
                preflight = run_preflight(
                    root,
                    mode="pr",
                    python_executable=python_executable,
                    evaluation_mode="pr",
                    transported_authority=controller_authority,
                )
                preflight_duration = _elapsed_ms(preflight_started)
                emit("preflight", "complete")
            except (PreflightError, EvidenceError) as exc:
                fail_stage("preflight")
                raise ProspectiveValidationError(str(exc)) from exc
        if preflight.get("status") != "pass":
            raise ProspectiveValidationError("canonical PR preflight did not pass")
        controller = preflight.get("self_controller")
        controller_state = (
            "not_adopted"
            if evaluation.lane == "direct_protected_main"
            else "ordinary_executable"
            if custody_state == "ordinary_executable_controller"
            else classify_trusted_controller_applicability(
                root, target_commit=str(controller_authority["controller_commit_sha"])
            ).state.value
            if controller_authority is not None
            else str(controller.get("status"))
            if isinstance(controller, dict)
            else "current"
        )
        if controller_state not in {
            "current", "pending_rotation", "not_adopted", "ordinary_executable"
        }:
            raise ProspectiveValidationError(
                f"controller compatibility is not admissible: {controller_state}"
            )
        try:
            with local_push_environment(
                base_sha=context.base_sha, head_sha=context.head_sha
            ):
                post_merge_preflight = run_preflight(
                    root,
                    mode="release",
                    python_executable=python_executable,
                    evaluation_mode=post_merge_mode,
                    evaluation_target=post_merge_target,
                    transported_authority=controller_authority,
                    controller_state_expectation=(
                        "prospective_pending_rotation"
                        if controller_state == "pending_rotation"
                        else None
                    ),
                )
        except (PreflightError, EvidenceError, ValueError) as exc:
            raise ProspectiveValidationError(
                f"canonical direct-push preflight rejected the candidate: {exc}"
            ) from exc
        if post_merge_preflight.get("status") != "pass":
            raise ProspectiveValidationError(
                "canonical direct-push preflight did not pass"
            )
        measurements.extend(
            [
                {"stage": "planning", "status": "observed", "duration_ms": preflight_duration},
                {"stage": "reuse", "status": "included", "parent": "planning"},
                {"stage": "setup", "status": "included", "parent": "planning"},
            ]
        )
        boundaries.append({"id": "preflight", "state": "proved", "authority": "local"})
        transition_requirement = (
            "direct_protected_main"
            if controller_state == "not_adopted"
            else "ordinary_exact_main"
            if controller_state == "ordinary_executable"
            else "no_transition"
            if controller_state == "current"
            else str(controller.get("transition_requirement"))
            if isinstance(controller, dict)
            and controller.get("transition_requirement") == "alternate_lane_required"
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
                "effective_controller_source": (
                    "direct_graph_policy"
                    if controller_state == "not_adopted"
                    else "declared_executable_controller"
                    if controller_state == "ordinary_executable"
                    else "provider_authenticated" if controller_authority is not None
                    else "source_policy"
                ),
                **(
                    {"alternate_lane": alternate_policy_lane_contract()}
                    if transition_requirement == "alternate_lane_required"
                    else {}
                ),
                "release_authority": False,
                "controller_custody_contract": custody_contract,
                **(
                    {"provider_authority_applicability": authority_applicability}
                    if authority_applicability is not None
                    else {}
                ),
            }
        )
        if not execute_evidence:
            report = {
                "schema_version": "1.0",
                "status": "deterministic_front_door_pass",
                "subject": identity.as_dict(),
                "changed_paths": list(changed_paths),
                "post_merge_evaluation": evaluation.as_dict(),
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

        verification_plan = preflight["verification_plan"]
        nodes = verification_plan["execution_dag"]["nodes"]
        producers = tuple(str(node["producer"]) for node in nodes)
        if len(producers) != len(set(producers)) or any(not value for value in producers):
            raise ProspectiveValidationError(
                "planned local producer topology is incomplete or ambiguous"
            )
        try:
            producer_environments = local_gate_job_environments(
                validate_ci_graph(root).graph, producers
            )
        except CIGraphError as exc:
            raise ProspectiveValidationError(str(exc)) from exc
        bundle_identity = None
        bundle_manifest = None
        bundle_reused = False
        session_root = None
        if repository is not None:
            try:
                bundle_identity = proof_identity(
                    repository=repository,
                    base_commit=identity.base_sha,
                    base_tree=base_tree,
                    candidate_commit=identity.commit_sha,
                    candidate_tree=identity.tree_sha,
                    evaluation_mode=post_merge_mode,
                    evaluation_target=post_merge_target,
                    verification_plan=verification_plan,
                    controller={
                        "state": controller_state,
                        "authority": dict(controller_authority or {}),
                        "custody": custody_contract,
                    },
                    policy=policy_identity,
                    toolchain=dict(toolchain_identity or {}),
                    python_executable=python_executable,
                )
                session_root = artifact_root / "reused"
                bundle_manifest = restore_proof_bundle(
                    root, identity=bundle_identity, destination=session_root
                )
                if bundle_manifest is None:
                    session_root = None
                else:
                    bundle_reused = True
            except LocalProofBundleError as exc:
                raise ProspectiveValidationError(str(exc)) from exc
        session = None
        if session_root is None:
            try:
                session = allocate_session(
                    root,
                    artifact_root,
                    producers,
                    expected_producers=["prospective-local"],
                    producer_identity=local_producer_identity(root, "prospective-local"),
                    verification_plan=verification_plan,
                )
                session_root = session.root
            except EvidenceError as exc:
                raise ProspectiveValidationError(str(exc)) from exc
        try:
            emit("evidence", "started")
            evidence_started = time.monotonic_ns()
            producer_observations = (
                cached_producer_observations(session_root, producers)
                if bundle_manifest is not None
                else _capture_planned_evidence(
                    root,
                    python_executable=python_executable,
                    session_manifest=session.manifest_path,
                    session_root=session_root,
                    producers=producers,
                    producer_environments=producer_environments,
                ) or []
            )
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
                derive_truth(root, session_root, evaluation_mode="pr"),
                boundary="PR truth",
            )
            pr_truth_duration = _elapsed_ms(truth_started)
            emit("evidence", "complete")
        except (EvidenceError, TruthfulnessError, LocalProofBundleError) as exc:
            fail_stage("evidence")
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
            [{"id": "certification", "state": "provider_required"},
             {"id": "merge", "state": "provider_required"},
             *provider_boundaries(
                 evaluation,
                 controller_state=controller_state,
                 transition_class=transition_class,
                 policy_identity=policy_identity,
                 controller_probe=(
                     custody_contract.get("no_transition_callback_probe")
                 ),
             )]
        )
        if transition_requirement == "alternate_lane_required":
            boundaries[-1]["alternate_lane"] = alternate_policy_lane_contract()
        try:
            emit("bounded_truth", "started")
            bounded_truth_started = time.monotonic_ns()
            bounded_truth = _require_truth(
                derive_truth(
                    root,
                    session_root,
                    evaluation_mode=post_merge_mode,
                    evaluation_target=post_merge_target,
                ),
                boundary="post-merge semantic truth projection",
            )
            bounded_truth_duration = _elapsed_ms(bounded_truth_started)
            emit("bounded_truth", "complete")
        except TruthfulnessError as exc:
            fail_stage("bounded_truth")
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
        if bundle_identity is not None and bundle_manifest is None:
            try:
                bundle_manifest = store_proof_bundle(
                    root, identity=bundle_identity, source=session_root
                )
            except LocalProofBundleError as exc:
                raise ProspectiveValidationError(str(exc)) from exc
        boundaries.extend(
            [{
                "id": "bounded_or_phase_truth",
                "state": "proved_semantics_provider_reexecution_required",
                "proposition": proposition,
            }, *terminal_boundaries(
                evaluation,
                proposition=proposition,
                proposition_sha256=proposition_sha256,
                bounded_truth=bounded_truth,
            )]
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
    emit("prospective_train", "complete")
    validate_progress_stream(progress)
    lifecycle = lifecycle_projection(root)
    validate_operational_observation(root, lifecycle)
    amplification = amplification_observation(
        train_id=str(lifecycle["phase_id"]),
        commit_sha=identity.commit_sha,
        tree_sha=identity.tree_sha,
        events=[
            {"event_id": f"commit:{identity.commit_sha}", "kind": "commits", "duration_ms": 0},
            *[
                {
                    "event_id": f"producer:{item['producer']}",
                    "kind": "jobs",
                    "duration_ms": item["duration_ms"],
                }
                for item in producer_observations
            ],
        ],
    )
    validate_operational_observation(root, amplification)
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
        "post_merge_evaluation": evaluation.as_dict(),
        "boundaries": boundaries,
        "provider_authority_substituted": False,
        "proof_bundle": (
            {
                "status": "reused" if bundle_reused else "created",
                "bundle_sha256": bundle_manifest["bundle_sha256"],
                "authority": "local_non_authoritative",
            }
            if bundle_manifest is not None
            else {
                "status": "not_persisted",
                "authority": "local_non_authoritative",
            }
        ),
        "telemetry": telemetry,
        "reconciliation": reconciliation,
        "progress": progress,
        "operational_observations": {
            "lifecycle": lifecycle,
            "amplification": amplification,
        },
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
    repository: str | None = None,
    provider_api: GitHubAPI | None = None,
    validation_lane: LocalValidationLane = LocalValidationLane.PROVIDER_PR,
    runner: Runner = _run,
    progress_sink: ProgressSink | None = None,
) -> dict[str, Any]:
    """Execute the complete locally knowable chain; no partial public mode exists."""

    try:
        requested_scope = evaluation_scope(
            semantic_intent,
            target=evaluation_target,
            phase_id="P00",
            subject_commit=subject_commit,
        )
        validate_evaluation_authored_ready(
            repo_root.resolve(), intent=requested_scope.intent.value, target=requested_scope.target_id
        )
    except (EvaluationScopeError, WorkitemContractError) as exc:
        raise ProspectiveValidationError(str(exc)) from exc
    try:
        with local_gate_lease(subject_commit):
            try:
                compiled_graph = validate_ci_graph(repo_root.resolve())
                graph = compiled_graph.graph
                lane = post_merge_evaluation(graph).lane
            except CIGraphError as exc:
                raise ProspectiveValidationError(str(exc)) from exc
            admission = validate_local_toolchain(
                repo_root.resolve(),
                python_executable,
                toolchain_command=compiled_graph.commands.get(
                    "bootstrap-test-toolchain"
                ),
            )
            with selected_toolchain_environment(admission):
                result = _run_prospective_train(
                    repo_root,
                    semantic_intent=semantic_intent,
                    evaluation_target=evaluation_target,
                    subject_commit=subject_commit,
                    subject_tree=subject_tree,
                    remote=remote,
                    python_executable=python_executable,
                    execute_evidence=True,
                    repository=repository if lane == "trusted_exact_main" else None,
                    provider_api=provider_api if lane == "trusted_exact_main" else None,
                    toolchain_identity=admission.as_dict(),
                    validation_lane=validation_lane,
                    runner=runner,
                    progress_sink=progress_sink,
                )
            result["local_execution_admission"] = admission.as_dict()
            return result
    except LocalExecutionAdmissionError as exc:
        raise ProspectiveValidationError(str(exc)) from exc

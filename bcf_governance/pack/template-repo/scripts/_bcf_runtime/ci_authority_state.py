"""Pure provider-neutral CI admission and certification state evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AuthorityContractError(ValueError):
    """Raised when normalized authority input is internally ambiguous."""


class AuthorityState(StrEnum):
    PENDING = "pending"
    FAILED = "failed"
    OBSOLETE = "obsolete"
    SUCCESSFUL = "successful"
    ACTIVE = "active"
    CERTIFIED = "certified"


class CertificationStage(StrEnum):
    PROVIDER_OBSERVED = "provider_observed"
    NORMALIZED = "normalized"
    TRUTH_VERIFIED = "truth_verified"


class RunStatus(StrEnum):
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


SUCCESS = "success"


@dataclass(frozen=True, order=True)
class JobKey:
    job_id: str
    matrix: tuple[tuple[str, str], ...] = ()

    @classmethod
    def create(cls, job_id: str, matrix: dict[str, str] | None = None) -> JobKey:
        if not job_id:
            raise AuthorityContractError("job_id must be non-empty")
        normalized = tuple(sorted((str(key), str(value)) for key, value in (matrix or {}).items()))
        return cls(job_id=job_id, matrix=normalized)


@dataclass(frozen=True)
class WorkflowIdentity:
    provider: str
    repository_id: str
    workflow_id: str
    active_path: str
    trusted_workflow_blob_oid: str
    trusted_workflow_sha256: str
    trusted_workflow_definition_commit: str
    event: str


@dataclass(frozen=True)
class CandidateIdentity:
    checkout_sha: str
    tree_sha: str


@dataclass(frozen=True)
class JobObservation:
    key: JobKey
    status: RunStatus
    conclusion: str | None = None


@dataclass(frozen=True)
class RunAttempt:
    attempt: int
    status: RunStatus
    conclusion: str | None
    jobs: tuple[JobObservation, ...]


@dataclass(frozen=True)
class ProducerContract:
    producer_id: str
    workflow: WorkflowIdentity
    expected_jobs: tuple[JobKey, ...]


@dataclass(frozen=True)
class ProducerRun:
    producer_id: str
    run_id: str
    workflow: WorkflowIdentity
    attempts: tuple[RunAttempt, ...]


@dataclass(frozen=True)
class Admission:
    admission_ordinal: int
    control_plane_run_id: str
    control_plane_attempt: int
    candidate: CandidateIdentity
    collection_complete: bool
    producer_runs: tuple[ProducerRun, ...]


@dataclass(frozen=True)
class AuthorityEvaluation:
    state: AuthorityState
    admission_ordinal: int | None
    selected_attempts: tuple[tuple[str, int], ...]
    reasons: tuple[str, ...]


def _unique_by(values: tuple[object, ...], key: str, *, name: str) -> None:
    seen: set[object] = set()
    for value in values:
        candidate = getattr(value, key)
        if candidate in seen:
            raise AuthorityContractError(f"duplicate {name}: {candidate}")
        seen.add(candidate)


def _validate_contracts(contracts: tuple[ProducerContract, ...]) -> None:
    _unique_by(contracts, "producer_id", name="producer contract")
    workflows = [contract.workflow for contract in contracts]
    if len(set(workflows)) != len(workflows):
        raise AuthorityContractError("producer contracts must have unique workflow identities")
    for contract in contracts:
        if not contract.expected_jobs:
            raise AuthorityContractError(
                f"producer {contract.producer_id} must declare at least one job"
            )
        if len(set(contract.expected_jobs)) != len(contract.expected_jobs):
            raise AuthorityContractError(
                f"producer {contract.producer_id} has duplicate expected jobs"
            )


def _select_admission(admissions: tuple[Admission, ...]) -> Admission | None:
    if not admissions:
        return None
    if any(admission.admission_ordinal <= 0 for admission in admissions):
        raise AuthorityContractError("admission ordinals must be positive")
    _unique_by(admissions, "admission_ordinal", name="admission ordinal")
    return max(admissions, key=lambda admission: admission.admission_ordinal)


def _authenticate_admissions(
    contracts: tuple[ProducerContract, ...], admissions: tuple[Admission, ...]
) -> None:
    expected = {contract.producer_id: contract.workflow for contract in contracts}
    for admission in admissions:
        for run in admission.producer_runs:
            workflow = expected.get(run.producer_id)
            if workflow is not None and run.workflow != workflow:
                raise AuthorityContractError(
                    f"producer {run.producer_id} workflow identity is not authenticated"
                )


def _select_attempt(run: ProducerRun) -> RunAttempt | None:
    if not run.attempts:
        return None
    if any(attempt.attempt <= 0 for attempt in run.attempts):
        raise AuthorityContractError("run attempts must be positive")
    _unique_by(run.attempts, "attempt", name=f"attempt for {run.producer_id}")
    return max(run.attempts, key=lambda attempt: attempt.attempt)


def _evaluate_producer(
    contract: ProducerContract,
    run: ProducerRun,
) -> tuple[int | None, tuple[str, ...], bool]:
    attempt = _select_attempt(run)
    if attempt is None:
        return None, (f"{contract.producer_id}:attempt_missing",), True
    if attempt.status is not RunStatus.COMPLETED:
        return attempt.attempt, (f"{contract.producer_id}:attempt_pending",), True
    if attempt.conclusion != SUCCESS:
        return attempt.attempt, (f"{contract.producer_id}:attempt_{attempt.conclusion or 'unset'}",), False
    actual_keys = tuple(observation.key for observation in attempt.jobs)
    if len(set(actual_keys)) != len(actual_keys):
        raise AuthorityContractError(
            f"producer {contract.producer_id} attempt {attempt.attempt} has duplicate jobs"
        )
    if set(actual_keys) != set(contract.expected_jobs):
        return attempt.attempt, (f"{contract.producer_id}:job_inventory_mismatch",), False
    failed_jobs = sorted(
        observation.key.job_id
        for observation in attempt.jobs
        if observation.status is not RunStatus.COMPLETED
        or observation.conclusion != SUCCESS
    )
    if failed_jobs:
        return (
            attempt.attempt,
            tuple(f"{contract.producer_id}:job_not_successful:{job}" for job in failed_jobs),
            False,
        )
    return attempt.attempt, (), False


def evaluate_authority(
    *,
    contracts: tuple[ProducerContract, ...],
    admissions: tuple[Admission, ...],
    current_default_main_sha: str,
    current_default_main_tree: str,
    stage: CertificationStage = CertificationStage.PROVIDER_OBSERVED,
) -> AuthorityEvaluation:
    """Evaluate the highest authenticated admission without side effects."""

    _validate_contracts(contracts)
    _authenticate_admissions(contracts, admissions)
    selected = _select_admission(admissions)
    if selected is None:
        return AuthorityEvaluation(AuthorityState.PENDING, None, (), ("admission_missing",))
    if (
        selected.candidate.checkout_sha != current_default_main_sha
        or selected.candidate.tree_sha != current_default_main_tree
    ):
        return AuthorityEvaluation(
            AuthorityState.OBSOLETE,
            selected.admission_ordinal,
            (),
            ("default_main_moved",),
        )

    _unique_by(selected.producer_runs, "producer_id", name="producer run")
    runs = {run.producer_id: run for run in selected.producer_runs}
    expected = {contract.producer_id for contract in contracts}
    actual = set(runs)
    missing = tuple(f"producer_missing:{value}" for value in sorted(expected - actual))
    unexpected = tuple(
        f"producer_unexpected:{value}" for value in sorted(actual - expected)
    )
    inventory_reasons = missing + unexpected
    if inventory_reasons:
        state = (
            AuthorityState.FAILED
            if selected.collection_complete or unexpected
            else AuthorityState.PENDING
        )
        return AuthorityEvaluation(state, selected.admission_ordinal, (), inventory_reasons)

    attempts: list[tuple[str, int]] = []
    reasons: list[str] = []
    pending = False
    failed = False
    for contract in contracts:
        attempt, producer_reasons, producer_pending = _evaluate_producer(
            contract, runs[contract.producer_id]
        )
        if attempt is not None:
            attempts.append((contract.producer_id, attempt))
        reasons.extend(producer_reasons)
        pending = pending or producer_pending
        failed = failed or bool(producer_reasons and not producer_pending)
    if reasons:
        state = (
            AuthorityState.PENDING
            if pending and not failed and not selected.collection_complete
            else AuthorityState.FAILED
        )
        return AuthorityEvaluation(
            state,
            selected.admission_ordinal,
            tuple(sorted(attempts)),
            tuple(sorted(reasons)),
        )

    states = {
        CertificationStage.PROVIDER_OBSERVED: AuthorityState.SUCCESSFUL,
        CertificationStage.NORMALIZED: AuthorityState.ACTIVE,
        CertificationStage.TRUTH_VERIFIED: AuthorityState.CERTIFIED,
    }
    return AuthorityEvaluation(
        states[stage],
        selected.admission_ordinal,
        tuple(sorted(attempts)),
        (),
    )

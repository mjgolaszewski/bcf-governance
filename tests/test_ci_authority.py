from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from bcf_governance.tooling.ci_authority_contracts import (
    CIAuthorityContractError,
    authority_role_jobs,
    validate_ci_contract,
)
from bcf_governance.tooling.ci_authority_state import (
    Admission,
    AuthorityContractError,
    AuthorityState,
    CandidateIdentity,
    CertificationStage,
    JobKey,
    JobObservation,
    ProducerContract,
    ProducerRun,
    RunAttempt,
    RunStatus,
    WorkflowIdentity,
    evaluate_authority,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SHA_A = "a" * 40
SHA_B = "b" * 40
TREE = "c" * 40
DIGEST = "d" * 64
SESSION = "e" * 32


def _workflow(*, workflow_id: str = "101", event: str = "workflow_dispatch") -> WorkflowIdentity:
    return WorkflowIdentity(
        provider="github",
        repository_id="42",
        workflow_id=workflow_id,
        active_path=f".github/workflows/{workflow_id}.yml",
        trusted_workflow_blob_oid=SHA_A,
        trusted_workflow_sha256=DIGEST,
        trusted_workflow_definition_commit=SHA_A,
        event=event,
    )


def _contract(
    producer_id: str = "unit",
    *,
    workflow_id: str = "101",
    jobs: tuple[JobKey, ...] | None = None,
) -> ProducerContract:
    return ProducerContract(
        producer_id=producer_id,
        workflow=_workflow(workflow_id=workflow_id),
        expected_jobs=jobs or (JobKey.create("test", {"python": "3.14"}),),
    )


def _attempt(
    contract: ProducerContract,
    *,
    attempt: int = 1,
    status: RunStatus = RunStatus.COMPLETED,
    conclusion: str | None = "success",
    jobs: tuple[JobObservation, ...] | None = None,
) -> RunAttempt:
    return RunAttempt(
        attempt=attempt,
        status=status,
        conclusion=conclusion,
        jobs=jobs
        if jobs is not None
        else tuple(
            JobObservation(key=key, status=RunStatus.COMPLETED, conclusion="success")
            for key in contract.expected_jobs
        ),
    )


def _admission(
    contracts: tuple[ProducerContract, ...],
    *,
    ordinal: int = 1,
    commit: str = SHA_A,
    tree: str = TREE,
    collection_complete: bool = True,
    attempts: dict[str, tuple[RunAttempt, ...]] | None = None,
) -> Admission:
    attempts = attempts or {}
    runs = tuple(
        ProducerRun(
            producer_id=contract.producer_id,
            run_id=f"run-{ordinal}-{contract.producer_id}",
            workflow=contract.workflow,
            attempts=attempts.get(contract.producer_id, (_attempt(contract),)),
        )
        for contract in contracts
    )
    return Admission(
        admission_ordinal=ordinal,
        control_plane_run_id=f"control-{ordinal}",
        control_plane_attempt=1,
        control_plane_workflow=_workflow(workflow_id="100", event="push"),
        candidate=CandidateIdentity(checkout_sha=commit, tree_sha=tree),
        collection_complete=collection_complete,
        producer_runs=runs,
    )


def _evaluate(
    contracts: tuple[ProducerContract, ...],
    admissions: tuple[Admission, ...],
    *,
    stage: CertificationStage = CertificationStage.PROVIDER_OBSERVED,
    commit: str = SHA_A,
    tree: str = TREE,
):
    return evaluate_authority(
        contracts=contracts,
        admissions=admissions,
        current_default_main_sha=commit,
        current_default_main_tree=tree,
        stage=stage,
    )


def _authority_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "repository": {"provider": "github", "repository_id": "42"},
        "admission_workflow": {
            "workflow_id": "100",
            "active_path": ".github/workflows/bcf-exact-main.yml",
            "trusted_workflow_blob_oid": SHA_A,
            "trusted_workflow_sha256": DIGEST,
            "trusted_workflow_definition_commit": SHA_A,
            "allowed_events": ["push"],
        },
        "producers": [
            {
                "producer_id": "unit",
                "workflow": {
                    "workflow_id": "101",
                    "active_path": ".github/workflows/test.yml",
                    "trusted_workflow_blob_oid": SHA_A,
                    "trusted_workflow_sha256": DIGEST,
                    "trusted_workflow_definition_commit": SHA_A,
                    "allowed_events": ["workflow_dispatch"],
                },
                "expected_jobs": [
                    {"job_id": "test", "matrix": {"python": "3.14"}}
                ],
            }
        ],
        "trusted_external_inputs": [],
    }


def _authority_v11_payload() -> dict[str, object]:
    workflow_names = (
        "admission", "governance", "finalizer", "status", "bootstrap", "probe",
        "release-authorizer", "release-build", "release-verifier",
        "release-collector", "release-publisher", "canary",
    )
    registry = {
        name: {
            "workflow_id": str(100 + index),
            "active_path": f".github/workflows/{name}.yml",
            "trusted_workflow_blob_oid": SHA_A,
            "trusted_workflow_sha256": DIGEST,
            "trusted_workflow_definition_commit": SHA_A,
            "allowed_events": ["workflow_call" if name == "governance" else "workflow_dispatch"],
        }
        for index, name in enumerate(workflow_names)
    }
    registry["admission"]["job_roles"] = {
        "admission": "admission",
        "unit": "producer",
    }
    for name in workflow_names:
        if name not in {"admission", "governance"}:
            registry[name]["expected_jobs"] = [{"job_id": f"{name}-job"}]
    registry["canary"]["expected_jobs"] = [
        {"job_id": "canary-admit", "role": "admission"},
        {"job_id": "canary-a", "role": "producer"},
        {"job_id": "canary-b", "role": "producer"},
        {"job_id": "canary-observe", "role": "observer"},
    ]
    registry["canary"]["job_roles"] = {
        "admit": "admission",
        "producer-a": "producer",
        "producer-b": "producer",
        "observe": "observer",
    }
    return {
        "schema_version": "1.1",
        "repository": {"provider": "github", "repository_id": "42"},
        "workflow_registry": registry,
        "roles": {
            "admission": "admission",
            "reusable_producers": ["governance"],
            "finalizer": "finalizer",
            "status_publisher": "status",
            "bootstrap": "bootstrap",
            "probe": "probe",
            "release_authorizer": "release-authorizer",
            "release_build": "release-build",
            "release_verifier": "release-verifier",
            "release_collector": "release-collector",
            "release_publisher": "release-publisher",
            "authority_canary": "canary",
        },
        "admission_jobs": [{"job_id": "admit-exact-main"}],
        "producers": [
            {
                "producer_id": "unit",
                "workflow_ref": "governance",
                "expected_jobs": [{"job_id": "test", "matrix": {"python": "3.14"}}],
            }
        ],
        "trusted_external_inputs": [],
    }


def _capability_na_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "record_id": "typescript-absent",
        "subject": {"kind": "capability", "id": "typescript_soip"},
        "repository_scope": ".",
        "rationale": "No tracked TypeScript source root exists.",
        "supporting_evidence": ["governance/canonical-representations.yml"],
        "approving_governance_role": "repository_owner",
        "subject_commit": SHA_A,
        "profile": "standard",
        "profile_contract_version": "2.0",
        "reviewed_at": "2026-08-30T00:00:00Z",
        "re_review_trigger": {"kind": "tracked_path_exists", "value": "**/*.ts"},
        "release_claim_uses_ci_evidence": False,
    }


def _certification_payload() -> dict[str, object]:
    workflow = {
        "provider": "github",
        "repository_id": "42",
        "workflow_id": "101",
        "active_path": ".github/workflows/test.yml",
        "trusted_workflow_blob_oid": SHA_A,
        "trusted_workflow_sha256": DIGEST,
        "trusted_workflow_definition_commit": SHA_A,
        "event": "workflow_dispatch",
    }
    candidate = {
        "checkout_sha": SHA_A,
        "tree_sha": TREE,
        "current_default_main_sha": SHA_A,
    }
    return {
        "schema_version": "1.0",
        "repository": {"provider": "github", "repository_id": "42"},
        "subject": candidate,
        "admission": {
            "admission_ordinal": "101001",
            "control_plane_run_id": "101",
            "control_plane_run_attempt": 1,
            "control_plane_workflow": {
                **workflow,
                "workflow_id": "100",
                "active_path": ".github/workflows/bcf-exact-main.yml",
                "event": "push",
            },
            "dispatch_sequence": 1,
            "candidate": candidate,
            "producer_runs": [
                {
                    "producer_id": "unit",
                    "workflow": workflow,
                    "selected_attempt": {
                        "run_id": "201",
                        "run_attempt": 2,
                        "status": "completed",
                        "conclusion": "success",
                        "exact_job_inventory": True,
                    },
                }
            ],
        },
        "raw_snapshots": [
            {
                "producer_id": "unit",
                "artifact_path": "raw/unit.json",
                "sha256": DIGEST,
                "authenticated_at": "2026-08-30T00:00:00Z",
            }
        ],
        "evidence_session": {
            "session_id": SESSION,
            "manifest_sha256": DIGEST,
            "run_id": "101",
            "run_attempt": 1,
        },
        "state": "active",
        "evaluation": {
            "exact_producer_inventory": True,
            "exact_job_inventory": True,
            "selected_attempts": [{"producer_id": "unit", "run_attempt": 2}],
            "reasons": [],
        },
        "generated_at": "2026-08-30T00:00:00Z",
    }


def test_ci_authority_and_certification_contracts_accept_exact_documents() -> None:
    validate_ci_contract(REPO_ROOT, "authority", _authority_payload())
    validate_ci_contract(REPO_ROOT, "certification", _certification_payload())
    validate_ci_contract(REPO_ROOT, "capability_na", _capability_na_payload())


def test_authority_v11_accepts_one_registry_and_closed_role_references() -> None:
    validate_ci_contract(REPO_ROOT, "authority", _authority_v11_payload())


def test_authority_v11_bridge_remains_readable_but_cannot_claim_privileged_jobs() -> None:
    payload = _authority_v11_payload()
    for workflow in payload["workflow_registry"].values():  # type: ignore[union-attr]
        workflow.pop("job_roles", None)
        workflow.pop("expected_jobs", None)

    validate_ci_contract(REPO_ROOT, "authority", payload)
    with pytest.raises(CIAuthorityContractError, match="lacks exact job inventory"):
        authority_role_jobs(payload, "release_verifier")


def test_self_authority_inventory_is_enriched_only_for_privileged_roles() -> None:
    import yaml

    payload = yaml.safe_load(
        (REPO_ROOT / "governance/ci-authority.yml").read_text(encoding="utf-8")
    )
    identity = {
        "workflow_id", "active_path", "trusted_workflow_blob_oid",
        "trusted_workflow_sha256", "trusted_workflow_definition_commit",
        "allowed_events",
    }
    admission = payload["roles"]["admission"]
    reusable = set(payload["roles"]["reusable_producers"])
    privileged = {
        reference
        for role, reference in payload["roles"].items()
        if role not in {"admission", "reusable_producers"}
    }

    assert set(payload["workflow_registry"][admission]) == identity | {"job_roles"}
    assert all(set(payload["workflow_registry"][reference]) == identity for reference in reusable)
    assert all(
        set(payload["workflow_registry"][reference]) >= identity | {"expected_jobs"}
        for reference in privileged
    )


@pytest.mark.parametrize(
    "mutation",
    ["missing-role-pin", "unknown-role-ref", "duplicate-workflow", "inline-producer", "missing-role-jobs", "missing-canary-source-roles", "duplicate-role-jobs"],
)
def test_authority_v11_rejects_incomplete_or_duplicated_semantic_ownership(
    mutation: str,
) -> None:
    payload = _authority_v11_payload()
    if mutation == "missing-role-pin":
        del payload["roles"]["release_verifier"]  # type: ignore[index]
    elif mutation == "unknown-role-ref":
        payload["roles"]["release_verifier"] = "missing"  # type: ignore[index]
    elif mutation == "duplicate-workflow":
        payload["workflow_registry"]["probe"] = dict(  # type: ignore[index]
            payload["workflow_registry"]["bootstrap"]  # type: ignore[index]
        )
    elif mutation == "inline-producer":
        producer = payload["producers"][0]  # type: ignore[index]
        producer["workflow"] = payload["workflow_registry"]["governance"]  # type: ignore[index]
    elif mutation == "missing-role-jobs":
        del payload["workflow_registry"]["release-verifier"]["expected_jobs"]  # type: ignore[index]
    elif mutation == "missing-canary-source-roles":
        del payload["workflow_registry"]["canary"]["job_roles"]  # type: ignore[index]
    else:
        jobs = payload["workflow_registry"]["canary"]["expected_jobs"]  # type: ignore[index]
        jobs.append(deepcopy(jobs[0]))
    with pytest.raises(CIAuthorityContractError):
        validate_ci_contract(REPO_ROOT, "authority", payload)


def test_v1_authority_remains_valid_without_admission_workflow() -> None:
    payload = _authority_payload()
    payload.pop("admission_workflow")

    validate_ci_contract(REPO_ROOT, "authority", payload)


def test_authority_rejects_duplicate_semantic_owners() -> None:
    payload = _authority_payload()
    payload["producers"].append(deepcopy(payload["producers"][0]))  # type: ignore[union-attr,index]

    with pytest.raises(CIAuthorityContractError, match="unique producer_id"):
        validate_ci_contract(REPO_ROOT, "authority", payload)


def test_authority_rejects_duplicate_matrix_job_identity() -> None:
    payload = _authority_payload()
    producer = payload["producers"][0]  # type: ignore[index]
    producer["expected_jobs"].append(deepcopy(producer["expected_jobs"][0]))

    with pytest.raises(CIAuthorityContractError, match="duplicate expected jobs"):
        validate_ci_contract(REPO_ROOT, "authority", payload)


def test_authority_rejects_duplicate_workflow_and_external_input_identity() -> None:
    payload = _authority_payload()
    duplicate = deepcopy(payload["producers"][0])  # type: ignore[index]
    duplicate["producer_id"] = "package"
    payload["producers"].append(duplicate)  # type: ignore[union-attr]

    with pytest.raises(CIAuthorityContractError, match="share workflow identity"):
        validate_ci_contract(REPO_ROOT, "authority", payload)

    payload = _authority_payload()
    external_input = {
        "input_id": "identity-contract",
        "source_repository": {"provider": "github", "repository_id": "84"},
        "producer_ref": SHA_A,
        "artifact_name": "identity-contract.json",
        "digest_algorithm": "sha256",
        "required": True,
    }
    payload["trusted_external_inputs"] = [external_input, deepcopy(external_input)]

    with pytest.raises(CIAuthorityContractError, match="unique input_id"):
        validate_ci_contract(REPO_ROOT, "authority", payload)


def test_authority_rejects_unsafe_workflow_path() -> None:
    payload = _authority_payload()
    payload["producers"][0]["workflow"]["active_path"] = "../workflow.yml"  # type: ignore[index]

    with pytest.raises(CIAuthorityContractError, match="does not match"):
        validate_ci_contract(REPO_ROOT, "authority", payload)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"profile": "regulated"}, "regulated requirements"),
        ({"release_claim_uses_ci_evidence": True}, "CI authority cannot be N/A"),
        ({"expires_at": "2026-08-29T00:00:00Z", "re_review_trigger": None}, "later than"),
    ],
)
def test_capability_na_fails_closed(mutation: dict[str, object], message: str) -> None:
    payload = _capability_na_payload()
    for key, value in mutation.items():
        if value is None:
            payload.pop(key, None)
        else:
            payload[key] = value

    with pytest.raises(CIAuthorityContractError, match=message):
        validate_ci_contract(REPO_ROOT, "capability_na", payload)


def test_capability_na_expiration_is_evaluated_deterministically() -> None:
    payload = _capability_na_payload()
    payload.pop("re_review_trigger")
    payload["expires_at"] = "2026-08-31T00:00:00Z"

    with pytest.raises(CIAuthorityContractError, match="has expired"):
        validate_ci_contract(
            REPO_ROOT,
            "capability_na",
            payload,
            evaluated_at=datetime(2026, 9, 1, tzinfo=UTC),
        )


def test_certification_rejects_snapshot_inventory_drift() -> None:
    payload = _certification_payload()
    payload["raw_snapshots"][0]["producer_id"] = "other"  # type: ignore[index]

    with pytest.raises(CIAuthorityContractError, match="exactly match"):
        validate_ci_contract(REPO_ROOT, "certification", payload)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("candidate", "exactly match the admitted candidate"),
        ("repository", "workflow identity must match"),
        ("attempt", "selected attempts must match"),
        ("green", "exact current-main green evidence"),
    ],
)
def test_certification_identity_and_computed_state_fail_closed(
    mutation: str, message: str
) -> None:
    payload = _certification_payload()
    if mutation == "candidate":
        payload["subject"] = {**payload["subject"], "checkout_sha": SHA_B}  # type: ignore[arg-type]
    elif mutation == "repository":
        payload["admission"]["producer_runs"][0]["workflow"]["repository_id"] = "99"  # type: ignore[index]
    elif mutation == "attempt":
        payload["evaluation"]["selected_attempts"][0]["run_attempt"] = 1  # type: ignore[index]
    else:
        payload["subject"]["current_default_main_sha"] = SHA_B  # type: ignore[index]

    with pytest.raises(CIAuthorityContractError, match=message):
        validate_ci_contract(REPO_ROOT, "certification", payload)


def test_normalized_report_cannot_claim_certified() -> None:
    payload = _certification_payload()
    payload["state"] = "certified"

    with pytest.raises(CIAuthorityContractError, match="is not one of"):
        validate_ci_contract(REPO_ROOT, "certification", payload)


@pytest.mark.parametrize(
    ("stage", "state"),
    [
        (CertificationStage.PROVIDER_OBSERVED, AuthorityState.SUCCESSFUL),
        (CertificationStage.NORMALIZED, AuthorityState.ACTIVE),
        (CertificationStage.TRUTH_VERIFIED, AuthorityState.CERTIFIED),
    ],
)
def test_green_exact_inventory_advances_only_by_explicit_stage(
    stage: CertificationStage, state: AuthorityState
) -> None:
    contracts = (_contract(),)
    result = _evaluate(contracts, (_admission(contracts),), stage=stage)

    assert result.state is state
    assert result.selected_attempts == (("unit", 1),)
    assert result.reasons == ()


def test_no_authenticated_admission_is_pending() -> None:
    result = _evaluate((_contract(),), ())

    assert result.state is AuthorityState.PENDING
    assert result.reasons == ("admission_missing",)


def test_latest_admitted_terminal_failure_revokes_prior_success() -> None:
    contract = _contract()
    older = _admission((contract,), ordinal=7)
    failed = _attempt(contract, conclusion="failure")
    newer = _admission((contract,), ordinal=8, attempts={"unit": (failed,)})

    result = _evaluate((contract,), (newer, older))

    assert result.state is AuthorityState.FAILED
    assert result.admission_ordinal == 8
    assert result.reasons == ("unit:attempt_failure",)


def test_latest_attempt_within_admitted_run_is_authoritative() -> None:
    contract = _contract()
    failed = _attempt(contract, attempt=1, conclusion="failure")
    passed = _attempt(contract, attempt=2)
    admission = _admission((contract,), attempts={"unit": (passed, failed)})

    result = _evaluate((contract,), (admission,))

    assert result.state is AuthorityState.SUCCESSFUL
    assert result.selected_attempts == (("unit", 2),)


def test_identical_tree_at_a_different_commit_is_obsolete() -> None:
    contract = _contract()
    result = _evaluate((contract,), (_admission((contract,), commit=SHA_A),), commit=SHA_B)

    assert result.state is AuthorityState.OBSOLETE
    assert result.reasons == ("default_main_moved",)


def test_missing_producer_is_pending_until_collection_closes_then_fails() -> None:
    first = _contract("unit", workflow_id="101")
    second = _contract("package", workflow_id="102")
    partial = _admission((first,), collection_complete=False)

    pending = _evaluate((first, second), (partial,))
    closed = replace(partial, collection_complete=True)
    failed = _evaluate((first, second), (closed,))

    assert pending.state is AuthorityState.PENDING
    assert failed.state is AuthorityState.FAILED
    assert failed.reasons == ("producer_missing:package",)


def test_unexpected_producer_fails_immediately() -> None:
    contract = _contract()
    unexpected_contract = _contract("rogue", workflow_id="999")
    with_rogue = _admission((contract, unexpected_contract), collection_complete=False)
    rogue_result = _evaluate((contract,), (with_rogue,))

    assert rogue_result.state is AuthorityState.FAILED
    assert rogue_result.reasons == ("producer_unexpected:rogue",)


def test_workflow_identity_is_authenticated_before_ordinal_precedence() -> None:
    contract = _contract()
    changed_run = ProducerRun(
        producer_id="unit",
        run_id="run-2-unit",
        workflow=_workflow(workflow_id="changed"),
        attempts=(_attempt(contract),),
    )
    changed = Admission(
        admission_ordinal=2,
        control_plane_run_id="control-2",
        control_plane_attempt=1,
        control_plane_workflow=_workflow(workflow_id="100", event="push"),
        candidate=CandidateIdentity(SHA_A, TREE),
        collection_complete=False,
        producer_runs=(changed_run,),
    )
    valid = _admission((contract,), ordinal=1)

    with pytest.raises(AuthorityContractError, match="not authenticated"):
        _evaluate((contract,), (valid, changed))


def test_exact_matrix_inventory_rejects_missing_or_extra_cells() -> None:
    contract = _contract()
    wrong_job = JobObservation(
        key=JobKey.create("test", {"python": "3.13"}),
        status=RunStatus.COMPLETED,
        conclusion="success",
    )
    admission = _admission(
        (contract,), attempts={"unit": (_attempt(contract, jobs=(wrong_job,)),)}
    )

    result = _evaluate((contract,), (admission,))

    assert result.state is AuthorityState.FAILED
    assert result.reasons == ("unit:job_inventory_mismatch",)


def test_order_of_callbacks_cannot_change_total_admission_precedence() -> None:
    contract = _contract()
    admissions = tuple(_admission((contract,), ordinal=value) for value in (4, 9, 2))

    forward = _evaluate((contract,), admissions)
    reverse = _evaluate((contract,), tuple(reversed(admissions)))

    assert forward == reverse
    assert forward.admission_ordinal == 9


@pytest.mark.parametrize(
    ("duplicate", "message"),
    [
        ("ordinal", "duplicate admission ordinal"),
        ("attempt", "duplicate attempt"),
        ("job", "duplicate jobs"),
    ],
)
def test_ambiguous_normalized_authority_is_rejected(
    duplicate: str, message: str
) -> None:
    contract = _contract()
    if duplicate == "ordinal":
        admissions = (_admission((contract,), ordinal=1), _admission((contract,), ordinal=1))
    elif duplicate == "attempt":
        attempt = _attempt(contract)
        admissions = (
            _admission((contract,), attempts={"unit": (attempt, attempt)}),
        )
    else:
        observation = _attempt(contract).jobs[0]
        admissions = (
            _admission(
                (contract,),
                attempts={"unit": (_attempt(contract, jobs=(observation, observation)),)},
            ),
        )

    with pytest.raises(AuthorityContractError, match=message):
        _evaluate((contract,), admissions)

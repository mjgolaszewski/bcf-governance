from __future__ import annotations

import pytest

from bcf_governance.tooling.governance_install.runtime_custody import (
    RuntimeCustodySnapshot,
    RuntimeCustodyState,
)
from bcf_governance.tooling.governance_install.runtime_custody_operations import (
    RuntimeCustodyDisposition,
    RuntimeCustodyOperation,
    decide_runtime_custody_operation,
)


def _snapshot(state: RuntimeCustodyState) -> RuntimeCustodySnapshot:
    return RuntimeCustodySnapshot(
        state=state,
        version=(
            None
            if state
            in {
                RuntimeCustodyState.ABSENT,
                RuntimeCustodyState.LOCAL_UNRELEASED,
                RuntimeCustodyState.PARTIAL_UNEXPLAINED,
            }
            else "2.1.4"
        ),
        runtime_owned={},
        consumer_preserved={},
        legacy_overlap=(),
        provenance_claim={},
        lock_bytes=None,
    )


@pytest.mark.parametrize(
    ("state", "operation", "disposition"),
    [
        (
            RuntimeCustodyState.ABSENT,
            RuntimeCustodyOperation.FRESH_INSTALL,
            RuntimeCustodyDisposition.ALLOW_FRESH_INSTALL,
        ),
        (
            RuntimeCustodyState.ABSENT,
            RuntimeCustodyOperation.FORCE_RESCAFFOLD,
            RuntimeCustodyDisposition.ALLOW_FRESH_INSTALL,
        ),
        (
            RuntimeCustodyState.ABSENT,
            RuntimeCustodyOperation.LOCAL_UPGRADE,
            RuntimeCustodyDisposition.REJECT_NOT_INSTALLED,
        ),
        (
            RuntimeCustodyState.ABSENT,
            RuntimeCustodyOperation.RELEASE_UPGRADE_REQUEST,
            RuntimeCustodyDisposition.REJECT_NOT_INSTALLED,
        ),
        (
            RuntimeCustodyState.ABSENT,
            RuntimeCustodyOperation.REMOVE_RUNTIME,
            RuntimeCustodyDisposition.REJECT_DELETION_AUTHORITY_ABSENT,
        ),
        (
            RuntimeCustodyState.LOCAL_UNRELEASED,
            RuntimeCustodyOperation.FRESH_INSTALL,
            RuntimeCustodyDisposition.REJECT_ALREADY_INSTALLED,
        ),
        (
            RuntimeCustodyState.LOCAL_UNRELEASED,
            RuntimeCustodyOperation.FORCE_RESCAFFOLD,
            RuntimeCustodyDisposition.REQUIRE_EXPLICIT_RESCAFFOLD_CONFIRMATION,
        ),
        (
            RuntimeCustodyState.LOCAL_UNRELEASED,
            RuntimeCustodyOperation.LOCAL_UPGRADE,
            RuntimeCustodyDisposition.ALLOW_LOCAL_NONAUTHORITATIVE,
        ),
        (
            RuntimeCustodyState.LOCAL_UNRELEASED,
            RuntimeCustodyOperation.RELEASE_UPGRADE_REQUEST,
            RuntimeCustodyDisposition.REQUIRE_TARGET_RELEASE_AUTHENTICATION,
        ),
        (
            RuntimeCustodyState.LOCAL_UNRELEASED,
            RuntimeCustodyOperation.REMOVE_RUNTIME,
            RuntimeCustodyDisposition.REJECT_DELETION_AUTHORITY_ABSENT,
        ),
        (
            RuntimeCustodyState.PARTIAL_UNEXPLAINED,
            RuntimeCustodyOperation.FRESH_INSTALL,
            RuntimeCustodyDisposition.REJECT_PARTIAL_INSTALLATION,
        ),
        (
            RuntimeCustodyState.PARTIAL_UNEXPLAINED,
            RuntimeCustodyOperation.FORCE_RESCAFFOLD,
            RuntimeCustodyDisposition.REQUIRE_EXPLICIT_RESCAFFOLD_CONFIRMATION,
        ),
        (
            RuntimeCustodyState.PARTIAL_UNEXPLAINED,
            RuntimeCustodyOperation.LOCAL_UPGRADE,
            RuntimeCustodyDisposition.REJECT_PARTIAL_INSTALLATION,
        ),
        (
            RuntimeCustodyState.PARTIAL_UNEXPLAINED,
            RuntimeCustodyOperation.RELEASE_UPGRADE_REQUEST,
            RuntimeCustodyDisposition.REJECT_PARTIAL_INSTALLATION,
        ),
        (
            RuntimeCustodyState.PARTIAL_UNEXPLAINED,
            RuntimeCustodyOperation.REMOVE_RUNTIME,
            RuntimeCustodyDisposition.REJECT_DELETION_AUTHORITY_ABSENT,
        ),
        (
            RuntimeCustodyState.NORMALIZED_EXACT,
            RuntimeCustodyOperation.FRESH_INSTALL,
            RuntimeCustodyDisposition.REJECT_ALREADY_INSTALLED,
        ),
        (
            RuntimeCustodyState.NORMALIZED_EXACT,
            RuntimeCustodyOperation.FORCE_RESCAFFOLD,
            RuntimeCustodyDisposition.REQUIRE_EXPLICIT_RESCAFFOLD_CONFIRMATION,
        ),
        (
            RuntimeCustodyState.NORMALIZED_EXACT,
            RuntimeCustodyOperation.LOCAL_UPGRADE,
            RuntimeCustodyDisposition.REJECT_RELEASE_ASSETS_REQUIRED,
        ),
        (
            RuntimeCustodyState.NORMALIZED_EXACT,
            RuntimeCustodyOperation.RELEASE_UPGRADE_REQUEST,
            RuntimeCustodyDisposition.REQUIRE_TARGET_RELEASE_AUTHENTICATION,
        ),
        (
            RuntimeCustodyState.NORMALIZED_EXACT,
            RuntimeCustodyOperation.REMOVE_RUNTIME,
            RuntimeCustodyDisposition.REJECT_DELETION_AUTHORITY_ABSENT,
        ),
        (
            RuntimeCustodyState.LEGACY_OVERLAP_EXACT,
            RuntimeCustodyOperation.FRESH_INSTALL,
            RuntimeCustodyDisposition.REJECT_ALREADY_INSTALLED,
        ),
        (
            RuntimeCustodyState.LEGACY_OVERLAP_EXACT,
            RuntimeCustodyOperation.FORCE_RESCAFFOLD,
            RuntimeCustodyDisposition.REQUIRE_EXPLICIT_RESCAFFOLD_CONFIRMATION,
        ),
        (
            RuntimeCustodyState.LEGACY_OVERLAP_EXACT,
            RuntimeCustodyOperation.LOCAL_UPGRADE,
            RuntimeCustodyDisposition.REJECT_RELEASE_ASSETS_REQUIRED,
        ),
        (
            RuntimeCustodyState.LEGACY_OVERLAP_EXACT,
            RuntimeCustodyOperation.RELEASE_UPGRADE_REQUEST,
            RuntimeCustodyDisposition.REQUIRE_TARGET_RELEASE_AUTHENTICATION,
        ),
        (
            RuntimeCustodyState.LEGACY_OVERLAP_EXACT,
            RuntimeCustodyOperation.REMOVE_RUNTIME,
            RuntimeCustodyDisposition.REJECT_DELETION_AUTHORITY_ABSENT,
        ),
    ],
)
def test_custody_operation_matrix_is_closed_and_typed(
    state: RuntimeCustodyState,
    operation: RuntimeCustodyOperation,
    disposition: RuntimeCustodyDisposition,
) -> None:
    decision = decide_runtime_custody_operation(
        _snapshot(state),
        operation,
        target_version="2.1.5",
    )

    assert decision.disposition is disposition
    assert decision.allowed is (
        disposition
        in {
            RuntimeCustodyDisposition.ALLOW_FRESH_INSTALL,
            RuntimeCustodyDisposition.ALLOW_LOCAL_NONAUTHORITATIVE,
            RuntimeCustodyDisposition.REQUIRE_EXPLICIT_RESCAFFOLD_CONFIRMATION,
            RuntimeCustodyDisposition.REQUIRE_TARGET_RELEASE_AUTHENTICATION,
        }
    )


def test_operation_contract_has_no_generic_inapplicable_outcome() -> None:
    assert {value.value for value in RuntimeCustodyDisposition} == {
        "allow_fresh_install",
        "allow_local_nonauthoritative",
        "require_explicit_rescaffold_confirmation",
        "require_target_release_authentication",
        "reject_not_installed",
        "reject_already_installed",
        "reject_partial_installation",
        "reject_release_assets_required",
        "reject_downgrade",
        "reject_deletion_authority_absent",
    }


def test_operation_matrix_covers_every_declared_state_and_operation() -> None:
    decisions = {
        (state, operation): decide_runtime_custody_operation(
            _snapshot(state), operation, target_version="2.1.5"
        )
        for state in RuntimeCustodyState
        for operation in RuntimeCustodyOperation
    }

    assert len(decisions) == len(RuntimeCustodyState) * len(RuntimeCustodyOperation)


@pytest.mark.parametrize(
    "operation",
    [
        RuntimeCustodyOperation.LOCAL_UPGRADE,
        RuntimeCustodyOperation.RELEASE_UPGRADE_REQUEST,
    ],
)
def test_newer_installed_runtime_rejects_downgrade(
    operation: RuntimeCustodyOperation,
) -> None:
    snapshot = RuntimeCustodySnapshot(
        state=RuntimeCustodyState.NORMALIZED_EXACT,
        version="2.2.0",
        runtime_owned={},
        consumer_preserved={},
        legacy_overlap=(),
        provenance_claim={},
        lock_bytes=b"{}",
    )

    decision = decide_runtime_custody_operation(
        snapshot,
        operation,
        target_version="2.1.5",
    )

    assert decision.disposition is RuntimeCustodyDisposition.REJECT_DOWNGRADE
    assert decision.allowed is False

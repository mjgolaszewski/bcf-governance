"""Operation contracts derived from typed installed-runtime custody state."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..release_versions import parse_release_version
from .runtime_custody import RuntimeCustodySnapshot, RuntimeCustodyState


class RuntimeCustodyOperation(StrEnum):
    """Mutations whose authority depends on installed-runtime custody."""

    FRESH_INSTALL = "fresh_install"
    FORCE_RESCAFFOLD = "force_rescaffold"
    LOCAL_UPGRADE = "local_upgrade"
    CANDIDATE_QUALIFICATION = "candidate_qualification"
    RELEASE_UPGRADE_REQUEST = "release_upgrade_request"
    REMOVE_RUNTIME = "remove_runtime"


class RuntimeCustodyDisposition(StrEnum):
    """Closed outcomes; inapplicable is never an implicit bypass."""

    ALLOW_FRESH_INSTALL = "allow_fresh_install"
    ALLOW_LOCAL_NONAUTHORITATIVE = "allow_local_nonauthoritative"
    ALLOW_ISOLATED_CANDIDATE_QUALIFICATION = "allow_isolated_candidate_qualification"
    REQUIRE_EXPLICIT_RESCAFFOLD_CONFIRMATION = (
        "require_explicit_rescaffold_confirmation"
    )
    REQUIRE_TARGET_RELEASE_AUTHENTICATION = "require_target_release_authentication"
    REJECT_NOT_INSTALLED = "reject_not_installed"
    REJECT_ALREADY_INSTALLED = "reject_already_installed"
    REJECT_PARTIAL_INSTALLATION = "reject_partial_installation"
    REJECT_RELEASE_ASSETS_REQUIRED = "reject_release_assets_required"
    REJECT_DOWNGRADE = "reject_downgrade"
    REJECT_DELETION_AUTHORITY_ABSENT = "reject_deletion_authority_absent"


@dataclass(frozen=True)
class RuntimeCustodyDecision:
    operation: RuntimeCustodyOperation
    state: RuntimeCustodyState
    disposition: RuntimeCustodyDisposition

    @property
    def allowed(self) -> bool:
        return self.disposition in {
            RuntimeCustodyDisposition.ALLOW_FRESH_INSTALL,
            RuntimeCustodyDisposition.ALLOW_LOCAL_NONAUTHORITATIVE,
            RuntimeCustodyDisposition.ALLOW_ISOLATED_CANDIDATE_QUALIFICATION,
            RuntimeCustodyDisposition.REQUIRE_EXPLICIT_RESCAFFOLD_CONFIRMATION,
            RuntimeCustodyDisposition.REQUIRE_TARGET_RELEASE_AUTHENTICATION,
        }


_OPERATION_MATRIX = {
    RuntimeCustodyState.ABSENT: {
        RuntimeCustodyOperation.FRESH_INSTALL: RuntimeCustodyDisposition.ALLOW_FRESH_INSTALL,
        RuntimeCustodyOperation.FORCE_RESCAFFOLD: RuntimeCustodyDisposition.ALLOW_FRESH_INSTALL,
        RuntimeCustodyOperation.LOCAL_UPGRADE: RuntimeCustodyDisposition.REJECT_NOT_INSTALLED,
        RuntimeCustodyOperation.CANDIDATE_QUALIFICATION: RuntimeCustodyDisposition.REJECT_NOT_INSTALLED,
        RuntimeCustodyOperation.RELEASE_UPGRADE_REQUEST: (
            RuntimeCustodyDisposition.REJECT_NOT_INSTALLED
        ),
        RuntimeCustodyOperation.REMOVE_RUNTIME: (
            RuntimeCustodyDisposition.REJECT_DELETION_AUTHORITY_ABSENT
        ),
    },
    RuntimeCustodyState.LOCAL_UNRELEASED: {
        RuntimeCustodyOperation.FRESH_INSTALL: RuntimeCustodyDisposition.REJECT_ALREADY_INSTALLED,
        RuntimeCustodyOperation.FORCE_RESCAFFOLD: (
            RuntimeCustodyDisposition.REQUIRE_EXPLICIT_RESCAFFOLD_CONFIRMATION
        ),
        RuntimeCustodyOperation.LOCAL_UPGRADE: (
            RuntimeCustodyDisposition.ALLOW_LOCAL_NONAUTHORITATIVE
        ),
        RuntimeCustodyOperation.CANDIDATE_QUALIFICATION: (
            RuntimeCustodyDisposition.ALLOW_ISOLATED_CANDIDATE_QUALIFICATION
        ),
        RuntimeCustodyOperation.RELEASE_UPGRADE_REQUEST: (
            RuntimeCustodyDisposition.REQUIRE_TARGET_RELEASE_AUTHENTICATION
        ),
        RuntimeCustodyOperation.REMOVE_RUNTIME: (
            RuntimeCustodyDisposition.REJECT_DELETION_AUTHORITY_ABSENT
        ),
    },
    RuntimeCustodyState.PARTIAL_UNEXPLAINED: {
        RuntimeCustodyOperation.FRESH_INSTALL: (
            RuntimeCustodyDisposition.REJECT_PARTIAL_INSTALLATION
        ),
        RuntimeCustodyOperation.FORCE_RESCAFFOLD: (
            RuntimeCustodyDisposition.REQUIRE_EXPLICIT_RESCAFFOLD_CONFIRMATION
        ),
        RuntimeCustodyOperation.LOCAL_UPGRADE: (
            RuntimeCustodyDisposition.REJECT_PARTIAL_INSTALLATION
        ),
        RuntimeCustodyOperation.CANDIDATE_QUALIFICATION: (
            RuntimeCustodyDisposition.REJECT_PARTIAL_INSTALLATION
        ),
        RuntimeCustodyOperation.RELEASE_UPGRADE_REQUEST: (
            RuntimeCustodyDisposition.REJECT_PARTIAL_INSTALLATION
        ),
        RuntimeCustodyOperation.REMOVE_RUNTIME: (
            RuntimeCustodyDisposition.REJECT_DELETION_AUTHORITY_ABSENT
        ),
    },
    RuntimeCustodyState.NORMALIZED_EXACT: {
        RuntimeCustodyOperation.FRESH_INSTALL: RuntimeCustodyDisposition.REJECT_ALREADY_INSTALLED,
        RuntimeCustodyOperation.FORCE_RESCAFFOLD: (
            RuntimeCustodyDisposition.REQUIRE_EXPLICIT_RESCAFFOLD_CONFIRMATION
        ),
        RuntimeCustodyOperation.LOCAL_UPGRADE: (
            RuntimeCustodyDisposition.REJECT_RELEASE_ASSETS_REQUIRED
        ),
        RuntimeCustodyOperation.CANDIDATE_QUALIFICATION: (
            RuntimeCustodyDisposition.ALLOW_ISOLATED_CANDIDATE_QUALIFICATION
        ),
        RuntimeCustodyOperation.RELEASE_UPGRADE_REQUEST: (
            RuntimeCustodyDisposition.REQUIRE_TARGET_RELEASE_AUTHENTICATION
        ),
        RuntimeCustodyOperation.REMOVE_RUNTIME: (
            RuntimeCustodyDisposition.REJECT_DELETION_AUTHORITY_ABSENT
        ),
    },
    RuntimeCustodyState.LEGACY_OVERLAP_EXACT: {
        RuntimeCustodyOperation.FRESH_INSTALL: RuntimeCustodyDisposition.REJECT_ALREADY_INSTALLED,
        RuntimeCustodyOperation.FORCE_RESCAFFOLD: (
            RuntimeCustodyDisposition.REQUIRE_EXPLICIT_RESCAFFOLD_CONFIRMATION
        ),
        RuntimeCustodyOperation.LOCAL_UPGRADE: (
            RuntimeCustodyDisposition.REJECT_RELEASE_ASSETS_REQUIRED
        ),
        RuntimeCustodyOperation.CANDIDATE_QUALIFICATION: (
            RuntimeCustodyDisposition.ALLOW_ISOLATED_CANDIDATE_QUALIFICATION
        ),
        RuntimeCustodyOperation.RELEASE_UPGRADE_REQUEST: (
            RuntimeCustodyDisposition.REQUIRE_TARGET_RELEASE_AUTHENTICATION
        ),
        RuntimeCustodyOperation.REMOVE_RUNTIME: (
            RuntimeCustodyDisposition.REJECT_DELETION_AUTHORITY_ABSENT
        ),
    },
    RuntimeCustodyState.CANDIDATE_QUALIFICATION_EXACT: {
        RuntimeCustodyOperation.FRESH_INSTALL: RuntimeCustodyDisposition.REJECT_ALREADY_INSTALLED,
        RuntimeCustodyOperation.FORCE_RESCAFFOLD: RuntimeCustodyDisposition.REQUIRE_EXPLICIT_RESCAFFOLD_CONFIRMATION,
        RuntimeCustodyOperation.LOCAL_UPGRADE: RuntimeCustodyDisposition.REJECT_RELEASE_ASSETS_REQUIRED,
        RuntimeCustodyOperation.CANDIDATE_QUALIFICATION: RuntimeCustodyDisposition.ALLOW_ISOLATED_CANDIDATE_QUALIFICATION,
        RuntimeCustodyOperation.RELEASE_UPGRADE_REQUEST: RuntimeCustodyDisposition.REQUIRE_TARGET_RELEASE_AUTHENTICATION,
        RuntimeCustodyOperation.REMOVE_RUNTIME: RuntimeCustodyDisposition.REJECT_DELETION_AUTHORITY_ABSENT,
    },
}


def decide_runtime_custody_operation(
    snapshot: RuntimeCustodySnapshot,
    operation: RuntimeCustodyOperation,
    *,
    target_version: str | None = None,
) -> RuntimeCustodyDecision:
    """Resolve one operation without reinterpreting custody in a consumer."""

    disposition = _OPERATION_MATRIX[snapshot.state][operation]
    if (
        operation
        in {
            RuntimeCustodyOperation.LOCAL_UPGRADE,
            RuntimeCustodyOperation.CANDIDATE_QUALIFICATION,
            RuntimeCustodyOperation.RELEASE_UPGRADE_REQUEST,
        }
        and snapshot.version is not None
        and target_version is not None
        and parse_release_version(snapshot.version).ordering_key
        > parse_release_version(target_version).ordering_key
    ):
        disposition = RuntimeCustodyDisposition.REJECT_DOWNGRADE
    elif (
        operation
        in {
            RuntimeCustodyOperation.LOCAL_UPGRADE,
            RuntimeCustodyOperation.CANDIDATE_QUALIFICATION,
            RuntimeCustodyOperation.RELEASE_UPGRADE_REQUEST,
        }
        and disposition
        in {
            RuntimeCustodyDisposition.ALLOW_LOCAL_NONAUTHORITATIVE,
            RuntimeCustodyDisposition.ALLOW_ISOLATED_CANDIDATE_QUALIFICATION,
            RuntimeCustodyDisposition.REQUIRE_TARGET_RELEASE_AUTHENTICATION,
        }
        and target_version is None
    ):
        raise ValueError("upgrade custody decision requires target_version")
    return RuntimeCustodyDecision(
        operation=operation,
        state=snapshot.state,
        disposition=disposition,
    )

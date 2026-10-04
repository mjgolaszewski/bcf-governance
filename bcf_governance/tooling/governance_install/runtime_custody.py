"""Typed installed-runtime custody classification for ordinary adopters."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


RUNTIME_LOCK_PATH = "governance/bcf-runtime-lock.json"
CANDIDATE_QUALIFICATION_PATH = "governance/bcf-candidate-qualification.json"
LOCAL_INSTALLATION_MARKERS = (
    "governance-profile.yml",
    "scripts/_bcf_runtime/install_governance_pack.py",
)


class RuntimeCustodyState(StrEnum):
    """Mechanically distinguish supported installed-runtime repository states."""

    ABSENT = "absent"
    LOCAL_UNRELEASED = "local_unreleased"
    PARTIAL_UNEXPLAINED = "partial_unexplained"
    NORMALIZED_EXACT = "normalized_exact"
    LEGACY_OVERLAP_EXACT = "legacy_overlap_exact"
    CANDIDATE_QUALIFICATION_EXACT = "candidate_qualification_exact"


class RuntimeCustodyFailure(StrEnum):
    """Stable fail-closed classifications for unsupported custody states."""

    LOCK_UNREADABLE = "lock_unreadable"
    SCHEMA_INVALID = "schema_invalid"
    CONTRADICTORY_OVERLAP = "contradictory_overlap"
    RUNTIME_OWNED_DRIFT = "runtime_owned_drift"
    CONSUMER_PRESERVED_DRIFT = "consumer_preserved_drift"


class RuntimeCustodyError(ValueError):
    """Reject a repository state before any consumer mutates it."""

    def __init__(
        self,
        failure: RuntimeCustodyFailure,
        *,
        paths: tuple[str, ...] = (),
        detail: str = "",
    ) -> None:
        self.failure = failure
        self.paths = paths
        self.detail = detail
        suffix = f": {', '.join(paths)}" if paths else (f": {detail}" if detail else "")
        super().__init__(f"{failure.value}{suffix}")


@dataclass(frozen=True)
class RuntimeCustodySnapshot:
    """Exact local custody observation; persisted provenance is not reauthenticated."""

    state: RuntimeCustodyState
    version: str | None
    runtime_owned: dict[str, str]
    consumer_preserved: dict[str, str]
    legacy_overlap: tuple[str, ...]
    provenance_claim: dict[str, object]
    lock_bytes: bytes | None

    @property
    def deletion_authorized(self) -> bool:
        """A persisted inventory alone never confers destructive authority."""

        return False


def _read_mapping(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeCustodyError(
            RuntimeCustodyFailure.LOCK_UNREADABLE,
            detail=f"{label} must be one nonsymlink file",
        )
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeCustodyError(RuntimeCustodyFailure.LOCK_UNREADABLE) from exc
    if not isinstance(value, dict):
        raise RuntimeCustodyError(
            RuntimeCustodyFailure.LOCK_UNREADABLE,
            detail=f"{label} must contain an object",
        )
    return value, raw


def runtime_custody_schema_path(repo_root: Path) -> Path:
    """Select local schema bytes or the exact executing runtime projection."""

    relative = Path("schemas/bcf-runtime-lock.schema.json")
    local = repo_root / relative
    if local.exists() or local.is_symlink():
        return local
    module = Path(__file__).resolve()
    candidates = (
        module.parents[2] / "pack/template-repo" / relative,
        module.parents[3] / relative,
    )
    return next(
        (
            candidate
            for candidate in candidates
            if candidate.is_file() and not candidate.is_symlink()
        ),
        local,
    )


def _verify_inventory(
    repo_root: Path,
    inventory: dict[str, str],
    *,
    failure: RuntimeCustodyFailure,
) -> None:
    drift: list[str] = []
    for relative, expected in sorted(inventory.items()):
        path = repo_root / relative
        if (
            not path.is_file()
            or path.is_symlink()
            or hashlib.sha256(path.read_bytes()).hexdigest() != expected
        ):
            drift.append(relative)
    if drift:
        raise RuntimeCustodyError(failure, paths=tuple(drift))


def inspect_runtime_custody(
    repo_root: Path,
    *,
    schema_path: Path | None = None,
) -> RuntimeCustodySnapshot:
    """Classify exact installed custody without granting operation authority."""

    lock_path = repo_root / RUNTIME_LOCK_PATH
    qualification_path = repo_root / CANDIDATE_QUALIFICATION_PATH
    if lock_path.exists() and qualification_path.exists():
        raise RuntimeCustodyError(
            RuntimeCustodyFailure.CONTRADICTORY_OVERLAP,
            paths=(RUNTIME_LOCK_PATH, CANDIDATE_QUALIFICATION_PATH),
        )
    if qualification_path.exists():
        payload, marker_bytes = _read_mapping(
            qualification_path, label="candidate qualification marker"
        )
        required = {
            "schema_version",
            "kind",
            "non_authoritative",
            "runtime_version",
            "candidate",
            "adopter",
            "predecessor_runtime_lock_sha256",
            "files",
            "preserved_consumer_files",
        }
        if (
            set(payload) != required
            or payload.get("schema_version") != "1.0"
            or payload.get("kind") != "candidate_qualification"
            or payload.get("non_authoritative") is not True
            or not isinstance(payload.get("runtime_version"), str)
            or not isinstance(payload.get("files"), dict)
            or not isinstance(payload.get("preserved_consumer_files"), dict)
        ):
            raise RuntimeCustodyError(
                RuntimeCustodyFailure.SCHEMA_INVALID,
                detail="candidate qualification marker is malformed",
            )
        for label, identity in (
            ("candidate", payload.get("candidate")),
            ("adopter", payload.get("adopter")),
        ):
            expected_keys = (
                {"commit_sha", "tree_sha", "pack_manifest_sha256"}
                if label == "candidate"
                else {"commit_sha", "tree_sha"}
            )
            if (
                not isinstance(identity, dict)
                or set(identity) != expected_keys
                or any(
                    not isinstance(value, str)
                    or len(value) != (64 if key == "pack_manifest_sha256" else 40)
                    or any(char not in "0123456789abcdef" for char in value)
                    for key, value in identity.items()
                )
            ):
                raise RuntimeCustodyError(
                    RuntimeCustodyFailure.SCHEMA_INVALID,
                    detail="candidate qualification identity is malformed",
                )
        predecessor_digest = payload.get("predecessor_runtime_lock_sha256")
        if (
            not isinstance(predecessor_digest, str)
            or len(predecessor_digest) != 64
            or any(char not in "0123456789abcdef" for char in predecessor_digest)
        ):
            raise RuntimeCustodyError(
                RuntimeCustodyFailure.SCHEMA_INVALID,
                detail="candidate qualification predecessor digest is malformed",
            )
        runtime_owned = dict(payload["files"])
        preserved = dict(payload["preserved_consumer_files"])
        overlap = tuple(sorted(set(runtime_owned) & set(preserved)))
        if overlap:
            raise RuntimeCustodyError(
                RuntimeCustodyFailure.CONTRADICTORY_OVERLAP, paths=overlap
            )
        _verify_inventory(
            repo_root,
            runtime_owned,
            failure=RuntimeCustodyFailure.RUNTIME_OWNED_DRIFT,
        )
        _verify_inventory(
            repo_root,
            preserved,
            failure=RuntimeCustodyFailure.CONSUMER_PRESERVED_DRIFT,
        )
        return RuntimeCustodySnapshot(
            state=RuntimeCustodyState.CANDIDATE_QUALIFICATION_EXACT,
            version=str(payload["runtime_version"]),
            runtime_owned=dict(sorted(runtime_owned.items())),
            consumer_preserved=dict(sorted(preserved.items())),
            legacy_overlap=(),
            provenance_claim={
                "candidate": payload["candidate"],
                "adopter": payload["adopter"],
                "predecessor_runtime_lock_sha256": predecessor_digest,
                "non_authoritative": True,
            },
            lock_bytes=marker_bytes,
        )
    if not lock_path.exists():
        markers = tuple(repo_root / relative for relative in LOCAL_INSTALLATION_MARKERS)
        present = tuple(path.exists() or path.is_symlink() for path in markers)
        exact = tuple(path.is_file() and not path.is_symlink() for path in markers)
        state = (
            RuntimeCustodyState.LOCAL_UNRELEASED
            if all(exact)
            else RuntimeCustodyState.PARTIAL_UNEXPLAINED
            if any(present)
            else RuntimeCustodyState.ABSENT
        )
        return RuntimeCustodySnapshot(
            state=state,
            version=None,
            runtime_owned={},
            consumer_preserved={},
            legacy_overlap=(),
            provenance_claim={},
            lock_bytes=None,
        )
    if not lock_path.is_file() or lock_path.is_symlink():
        raise RuntimeCustodyError(RuntimeCustodyFailure.LOCK_UNREADABLE)
    payload, lock_bytes = _read_mapping(lock_path, label="runtime lock")
    effective_schema = schema_path or runtime_custody_schema_path(repo_root)
    schema, _schema_bytes = _read_mapping(
        effective_schema, label="runtime lock schema"
    )
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        raise RuntimeCustodyError(
            RuntimeCustodyFailure.SCHEMA_INVALID,
            detail=errors[0].message,
        )

    runtime_owned = dict(payload["files"])
    consumer_preserved = dict(payload["preserved_consumer_files"])
    overlap = tuple(sorted(set(runtime_owned) & set(consumer_preserved)))
    contradictory = tuple(
        path
        for path in overlap
        if runtime_owned[path] != consumer_preserved[path]
    )
    if contradictory:
        raise RuntimeCustodyError(
            RuntimeCustodyFailure.CONTRADICTORY_OVERLAP,
            paths=contradictory,
        )

    # Consumer preservation wins exact legacy overlap. The normalized producer
    # must not claim those paths as runtime-owned in its successor receipt.
    normalized_runtime = {
        path: digest for path, digest in runtime_owned.items() if path not in overlap
    }
    _verify_inventory(
        repo_root,
        normalized_runtime,
        failure=RuntimeCustodyFailure.RUNTIME_OWNED_DRIFT,
    )
    _verify_inventory(
        repo_root,
        consumer_preserved,
        failure=RuntimeCustodyFailure.CONSUMER_PRESERVED_DRIFT,
    )
    provenance_keys = (
        "version",
        "source_repository",
        "source_repository_id",
        "source_commit",
        "release_id",
        "release_url",
        "wheel_sha256",
        "source_archive_sha256",
        "checksum_manifest_sha256",
    )
    return RuntimeCustodySnapshot(
        state=(
            RuntimeCustodyState.LEGACY_OVERLAP_EXACT
            if overlap
            else RuntimeCustodyState.NORMALIZED_EXACT
        ),
        version=str(payload["version"]),
        runtime_owned=dict(sorted(normalized_runtime.items())),
        consumer_preserved=dict(sorted(consumer_preserved.items())),
        legacy_overlap=overlap,
        provenance_claim={key: payload[key] for key in provenance_keys if key in payload},
        lock_bytes=lock_bytes,
    )

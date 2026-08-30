"""Digest-bound handoff for optional trusted external CI inputs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
from typing import Any


class TrustedInputError(ValueError):
    """Raised when an external input crosses the trusted boundary without custody."""


@dataclass(frozen=True)
class TrustedInputVerification:
    input_id: str
    source_repository_id: str
    producer_ref: str
    artifact_name: str
    sha256: str
    verified_by: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def verify_trusted_input(
    *,
    contract: dict[str, Any],
    handoff: dict[str, Any],
    artifact_path: Path,
    executor_role: str,
) -> TrustedInputVerification:
    """Verify authenticated metadata and bytes only in a trusted collector role."""

    if executor_role != "trusted-collector":
        raise TrustedInputError("trusted external inputs may only be acquired by a trusted collector")
    if not artifact_path.is_file() or artifact_path.is_symlink():
        raise TrustedInputError("trusted input artifact must be a regular file")
    required = ("input_id", "source_repository", "producer_ref", "artifact_name")
    if any(contract.get(key) != handoff.get(key) for key in required):
        raise TrustedInputError("trusted input handoff metadata does not match its contract")
    source = contract.get("source_repository")
    if not isinstance(source, dict) or source.get("provider") != "github":
        raise TrustedInputError("trusted input source repository is invalid")
    if contract.get("digest_algorithm") != "sha256":
        raise TrustedInputError("trusted input digest algorithm must be sha256")
    digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    if handoff.get("sha256") != digest:
        raise TrustedInputError("trusted input artifact digest does not match authenticated handoff")
    if handoff.get("provider_authenticated") is not True:
        raise TrustedInputError("trusted input handoff was not reconstructed from provider state")
    return TrustedInputVerification(
        input_id=str(contract["input_id"]),
        source_repository_id=str(source["repository_id"]),
        producer_ref=str(contract["producer_ref"]),
        artifact_name=str(contract["artifact_name"]),
        sha256=digest,
        verified_by=executor_role,
    )

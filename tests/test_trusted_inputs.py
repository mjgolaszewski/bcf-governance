from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from bcf_governance.tooling.trusted_inputs import TrustedInputError, verify_trusted_input


def _contract() -> dict[str, object]:
    return {
        "input_id": "identity-contracts",
        "source_repository": {"provider": "github", "repository_id": "101"},
        "producer_ref": "a" * 40,
        "artifact_name": "contracts",
        "digest_algorithm": "sha256",
        "required": True,
    }


def test_trusted_input_requires_authenticated_digest_bound_handoff(tmp_path: Path) -> None:
    artifact = tmp_path / "contracts.tar"
    artifact.write_bytes(b"contract bytes")
    handoff = {
        **_contract(),
        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "provider_authenticated": True,
    }
    result = verify_trusted_input(
        contract=_contract(),
        handoff=handoff,
        artifact_path=artifact,
        executor_role="trusted-collector",
    )
    assert result.sha256 == handoff["sha256"]


@pytest.mark.parametrize(
    ("role", "authenticated", "digest", "message"),
    [
        ("candidate", True, "valid", "trusted collector"),
        ("trusted-collector", False, "valid", "provider state"),
        ("trusted-collector", True, "bad", "digest"),
    ],
)
def test_trusted_input_boundary_mutants_fail(
    tmp_path: Path, role: str, authenticated: bool, digest: str, message: str
) -> None:
    artifact = tmp_path / "contracts.tar"
    artifact.write_bytes(b"contract bytes")
    actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
    handoff = {
        **_contract(),
        "sha256": actual if digest == "valid" else "0" * 64,
        "provider_authenticated": authenticated,
    }
    with pytest.raises(TrustedInputError, match=message):
        verify_trusted_input(
            contract=_contract(), handoff=handoff, artifact_path=artifact, executor_role=role
        )

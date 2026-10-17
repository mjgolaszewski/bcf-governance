"""Digest-bound handoff for optional trusted external CI inputs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory
from typing import Any

from .ci_authority_certification import (
    CertificationVerification, verify_ci_certification,
)
from .ci_github_api import GitHubAPI
from .ci_github_artifacts import ProviderArtifact, resolve_role_artifact
from .ci_github_authority import load_authority, packaged_repo_root
from .ci_github_bundle import verify_bundle
from .ci_github_identity import GitHubControllerError, MainIdentity, exact_sha, resolve_main
from .ci_github_release_inputs import _exact_finalizer_run
from .controller_transition_provider_custody import github_is_ancestor
from .evaluation_scope import is_terminal_phase_certification
from .prior_evidence_transport import MAX_ARCHIVE_BYTES, _archive_files


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


def verify_phase_closure_input(
    api: GitHubAPI, *, repository: str, phase_id: str,
    source_commit: str, source_tree: str,
) -> tuple[ProviderArtifact, CertificationVerification, bytes]:
    """Acquire an exact historical phase certificate through provider authority.

    Expected coordinates are assertions, not authority. Consumers still derive
    their prerequisite population from protected lifecycle policy. No candidate
    schema path or caller assertion of provider authentication is accepted.
    """

    if not isinstance(phase_id, str) or re.fullmatch(r"P[0-9]+", phase_id) is None:
        raise GitHubControllerError("phase prerequisite identity is invalid")
    source_commit = exact_sha(source_commit, field="phase prerequisite commit")
    source_tree = exact_sha(source_tree, field="phase prerequisite tree")
    trusted_schema_root = packaged_repo_root()
    current = resolve_main(api, repository)
    commit = api.commit(repository, source_commit)
    tree = commit.get("tree")
    if (commit.get("sha") != source_commit or not isinstance(tree, dict)
            or tree.get("sha") != source_tree):
        raise GitHubControllerError("phase prerequisite source is not exact")
    if not github_is_ancestor(
        api, repository, base=source_commit, head=current.checkout_sha,
    ):
        raise GitHubControllerError("phase prerequisite is outside default-branch lineage")
    subject = MainIdentity(
        repository_id=current.repository_id, default_branch=current.default_branch,
        checkout_sha=source_commit, tree_sha=source_tree,
    )
    authority = load_authority(api, repository, subject, required_version="1.1")
    selected = _exact_finalizer_run(
        api, repository=repository, main=subject, authority=authority,
    )
    artifact = resolve_role_artifact(
        api, repository=repository, main=subject, authority=authority,
        role="finalizer", run_id=selected[0], run_attempt=selected[1],
        artifact_name=f"bcf-exact-main-certification-{selected[0]}-{selected[1]}",
        require_success=True,
    )
    raw = api.artifact_bytes(repository, artifact.artifact_id, maximum_bytes=MAX_ARCHIVE_BYTES)
    if "sha256:" + hashlib.sha256(raw).hexdigest() != artifact.provider_digest:
        raise GitHubControllerError("phase prerequisite artifact provider digest mismatch")
    files = _archive_files(raw)
    expected_subject = {"commit_sha": source_commit, "tree_sha": source_tree}
    try:
        with TemporaryDirectory(prefix="bcf-phase-input-") as temporary:
            root = Path(temporary)
            for relative, data in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            manifest = verify_bundle(root)
            if json.loads((root / "ci-authority.json").read_bytes()) != authority:
                raise GitHubControllerError("phase prerequisite authority is not provider source")
            verification = verify_ci_certification(
                trusted_schema_root, authority_path=root / "ci-authority.json",
                certification_path=root / "ci-certification.json",
                session_manifest_path=root / "evidence-session.json",
            )
            certification = json.loads((root / "ci-certification.json").read_bytes())
            session = json.loads((root / "evidence-session.json").read_bytes())
    except (OSError, ValueError) as exc:
        if isinstance(exc, GitHubControllerError):
            raise
        raise GitHubControllerError(f"phase prerequisite certification is invalid: {exc}") from exc
    if verification.status != "pass" or verification.computed_state != "certified":
        raise GitHubControllerError("phase prerequisite is not independently certified")
    if (not is_terminal_phase_certification(certification)
            or verification.evaluation_scope != {
                "intent": "closure", "target": {"kind": "phase", "id": phase_id},
            }
            or verification.certified_proposition is None
            or verification.certified_proposition.get("subject") != expected_subject):
        raise GitHubControllerError("phase prerequisite terminal scope or subject is not exact")
    if (manifest.get("kind") != "certification"
            or manifest.get("subject") != expected_subject
            or manifest.get("computed_state") != verification.computed_state
            or str(manifest.get("admission_ordinal")) != str(verification.admission_ordinal)):
        raise GitHubControllerError("phase prerequisite manifest is not exact")
    producer = session.get("producer", {})
    if (str(producer.get("run_id")), str(producer.get("run_attempt"))) != (
        artifact.run_id, str(artifact.run_attempt),
    ) or producer.get("repository") != repository or str(
        producer.get("repository_id")
    ) != current.repository_id:
        raise GitHubControllerError("phase prerequisite session is not its provider finalizer")
    if resolve_main(api, repository) != current or _exact_finalizer_run(
        api, repository=repository, main=subject, authority=authority,
    ) != selected:
        raise GitHubControllerError("phase prerequisite provider frontier moved")
    fresh = resolve_role_artifact(
        api, repository=repository, main=subject, authority=authority,
        role="finalizer", run_id=selected[0], run_attempt=selected[1],
        artifact_name=artifact.artifact_name, require_success=True,
    )
    if fresh != artifact:
        raise GitHubControllerError("phase prerequisite artifact changed during verification")
    return artifact, verification, raw


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

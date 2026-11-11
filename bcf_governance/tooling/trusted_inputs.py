"""Digest-bound handoff for optional trusted external CI inputs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
import re
from tempfile import TemporaryDirectory
from typing import Any, Mapping

from .ci_authority_contracts import validate_ci_contract
from .ci_authority_certification import (
    CertificationVerification, verify_ci_certification,
)
from .ci_github_api import GitHubAPI
from .ci_github_artifacts import ProviderArtifact, resolve_role_artifact
from .ci_github_authority import load_authority, packaged_repo_root
from .ci_github_bundle import verify_bundle
from .ci_github_identity import GitHubControllerError, MainIdentity, exact_sha, resolve_main
from .ci_github_release_inputs import _exact_finalizer_run, _exact_role_run
from .controller_transition_provider_custody import github_is_ancestor
from .evaluation_scope import is_terminal_phase_certification
from .prior_evidence_transport import MAX_ARCHIVE_BYTES, MAX_EXPANDED_BYTES, _archive_files, _mapping


_MAX_LIFECYCLE_SOURCE_BYTES = 2_000_000


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


def _authenticated_phase_policy_subject(
    api: GitHubAPI, *, repository: str, policy_subject: MainIdentity | None,
) -> tuple[MainIdentity, MainIdentity]:
    """Authenticate policy source while retaining the separate current frontier."""
    if policy_subject is not None:
        if not isinstance(policy_subject, MainIdentity):
            raise GitHubControllerError("admitted phase policy subject is invalid")
        exact_sha(policy_subject.checkout_sha, field="admitted phase policy commit")
        exact_sha(policy_subject.tree_sha, field="admitted phase policy tree")
    packaged_repo_root()
    current = resolve_main(api, repository)
    selected = policy_subject if policy_subject is not None else current
    if selected != current:
        if (selected.repository_id != current.repository_id
                or selected.default_branch != current.default_branch):
            raise GitHubControllerError("admitted phase policy repository/default is contradictory")
        commit = api.commit(repository, selected.checkout_sha)
        tree = commit.get("tree")
        if (commit.get("sha") != selected.checkout_sha or not isinstance(tree, dict)
                or tree.get("sha") != selected.tree_sha):
            raise GitHubControllerError("admitted phase policy source is not exact")
        if not github_is_ancestor(
            api, repository, base=selected.checkout_sha, head=current.checkout_sha,
        ):
            raise GitHubControllerError("admitted phase policy is outside default-branch lineage")
    return current, selected


def _authenticated_lifecycle_source_snapshot(
    api: GitHubAPI, *, repository: str, policy_subject: MainIdentity | None,
) -> tuple[MainIdentity, MainIdentity, dict[str, str], dict[str, str]]:
    """Capture exact provider lifecycle source facts for the consuming query."""
    if not callable(getattr(api, "complete_tree_with_modes", None)):
        raise GitHubControllerError("exact-main lifecycle source inventory is unavailable")
    current, selected = _authenticated_phase_policy_subject(
        api, repository=repository, policy_subject=policy_subject,
    )
    inventory = api.complete_tree_with_modes(repository, selected.tree_sha)
    if not isinstance(inventory, (tuple, list)):
        raise GitHubControllerError("exact-main lifecycle source inventory is invalid")
    blobs: dict[str, str] = {}
    modes: dict[str, str] = {}
    for row in inventory:
        if not isinstance(row, (tuple, list)) or len(row) != 3:
            raise GitHubControllerError("exact-main lifecycle source inventory is invalid")
        path, oid, mode = row
        if (not isinstance(path, str) or not path or path in blobs
                or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts):
            raise GitHubControllerError("exact-main lifecycle source inventory is ambiguous")
        if not isinstance(mode, str) or mode not in {"100644", "100755", "120000"}:
            raise GitHubControllerError("exact-main lifecycle source mode is invalid")
        modes[path] = mode
        blobs[path] = exact_sha(oid, field="exact-main lifecycle blob")
    return current, selected, blobs, modes


def _read_authenticated_lifecycle_blob(
    api: GitHubAPI, *, repository: str, selected: MainIdentity,
    blobs: Mapping[str, str], modes: Mapping[str, str], path: Any, total: int,
) -> tuple[bytes, int]:
    """Consume a blob from the locally authenticated inventory and byte budget."""
    if (not isinstance(path, str) or "\\" in path
            or PurePosixPath(path).as_posix() != path
            or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts
            or not PurePosixPath(path).parts or path not in blobs):
        raise GitHubControllerError("exact-main lifecycle source path is unsafe or missing")
    if modes[path] not in {"100644", "100755"}:
        raise GitHubControllerError("exact-main lifecycle source is not a regular blob")
    content = api.content(repository, path, ref=selected.checkout_sha)
    raw = content.content
    if not isinstance(raw, bytes):
        raise GitHubControllerError("exact-main lifecycle source bytes are invalid")
    total += len(raw)
    if total > _MAX_LIFECYCLE_SOURCE_BYTES:
        raise GitHubControllerError("exact-main lifecycle source exceeds bounded input")
    digest = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if content.path != path or content.blob_oid != blobs[path] or digest != blobs[path]:
        raise GitHubControllerError("exact-main lifecycle source blob is not exact")
    return raw, total


def verify_required_phase_closure_inputs(
    api: GitHubAPI, *, repository: str, phase_id: str | None,
    policy_subject: MainIdentity | None = None,
) -> tuple[MainIdentity, dict[str, tuple[ProviderArtifact, CertificationVerification, bytes]]]:
    """Derive and verify the protected plan's complete predecessor population."""

    if (phase_id is None and policy_subject is None) or (phase_id is not None and (
            not isinstance(phase_id, str) or re.fullmatch(r"P[0-9]+", phase_id) is None)):
        raise GitHubControllerError("phase prerequisite target is invalid")
    current, selected, blobs, modes = _authenticated_lifecycle_source_snapshot(
        api, repository=repository, policy_subject=policy_subject,
    )
    total = 0
    documents: dict[str, dict[str, Any]] = {}
    for path in ("plans/build-plan.yml", "plans/phase-ledger.yml", "plans/phase-history.yml"):
        raw, total = _read_authenticated_lifecycle_blob(
            api, repository=repository, selected=selected, blobs=blobs, modes=modes,
            path=path, total=total,
        )
        documents[path] = _mapping(raw, label=f"protected {path}")
    phases = documents["plans/build-plan.yml"].get("phase_sequence")
    if not isinstance(phases, list) or not all(isinstance(value, dict) for value in phases):
        raise GitHubControllerError("protected phase sequence is invalid")
    active = documents["plans/phase-ledger.yml"].get("active_phase")
    if (not isinstance(active, dict) or not isinstance(active.get("id"), str)
            or re.fullmatch(r"P[0-9]+", active["id"]) is None):
        raise GitHubControllerError("protected active phase identity is invalid")
    if phase_id is None:
        phase_id = active["id"]
    matches = [value for value in phases if value.get("phase_id") == phase_id]
    if len(matches) != 1:
        raise GitHubControllerError("protected phase target is missing or ambiguous")
    dependencies = matches[0].get("hard_dependencies")
    if (not isinstance(dependencies, list)
            or any(not isinstance(value, str) or re.fullmatch(r"P[0-9]+", value) is None
                   for value in dependencies)
            or len(dependencies) != len(set(dependencies)) or phase_id in dependencies):
        raise GitHubControllerError("protected phase dependency population is invalid")
    history = documents["plans/phase-history.yml"].get("entries")
    if not isinstance(history, list) or not all(isinstance(value, dict) for value in history):
        raise GitHubControllerError("protected phase history inventory is invalid")
    subjects: dict[str, tuple[str, str]] = {}
    for predecessor in sorted(dependencies):
        retained = [value for value in history if value.get("phase_id") == predecessor]
        if predecessor == active["id"]:
            if retained:
                raise GitHubControllerError("active phase prerequisite has contradictory retained history")
            subjects[predecessor] = selected.checkout_sha, selected.tree_sha
            continue
        if len(retained) != 1:
            raise GitHubControllerError("phase prerequisite history locator is missing or ambiguous")
        snapshot = retained[0].get("verification_snapshot")
        if not isinstance(snapshot, dict):
            raise GitHubControllerError("phase prerequisite history snapshot is missing")
        commit = exact_sha(snapshot.get("commit_sha"), field="retained phase commit")
        tree = exact_sha(snapshot.get("tree_sha"), field="retained phase tree")
        if retained[0].get("retention_ref") != commit:
            raise GitHubControllerError("phase prerequisite retention locator is contradictory")
        subjects[predecessor] = commit, tree
    # Complete cheap population and coordinate validation before any proof download.
    if resolve_main(api, repository) != current:
        raise GitHubControllerError("protected phase dependency frontier moved")
    inputs = {
        predecessor: verify_phase_closure_input(
            api, repository=repository, phase_id=predecessor,
            source_commit=commit, source_tree=tree,
        )
        for predecessor, (commit, tree) in subjects.items()
    }
    if resolve_main(api, repository) != current:
        raise GitHubControllerError("protected phase dependency frontier moved")
    return selected, inputs


def _registered_inputs(
    api: GitHubAPI, repository: str,
) -> tuple[MainIdentity, dict[str, dict[str, Any]]]:
    current = resolve_main(api, repository)
    authority = load_authority(api, repository, current, required_version="1.1")
    population = authority.get("trusted_external_inputs", [])
    return current, {value["input_id"]: value for value in population}


def _admit_input(
    contract: dict[str, Any], handoff: dict[str, Any], artifact_path: Path,
) -> os.stat_result:
    validate_ci_contract(
        packaged_repo_root(), "authority", contract, definition="trustedExternalInput",
    )
    if "acquisition" not in contract:
        raise TrustedInputError("trusted input requires an explicit protected acquisition binding")
    required = ("input_id", "source_repository", "producer_ref", "artifact_name")
    if any(contract[key] != handoff.get(key) for key in required):
        raise TrustedInputError("trusted input handoff metadata does not match protected policy")
    if any(key in handoff and handoff[key] != value for key, value in contract.items()):
        raise TrustedInputError("trusted input handoff policy metadata is contradictory")
    if re.fullmatch(r"[a-f0-9]{64}", str(handoff.get("sha256", ""))) is None:
        raise TrustedInputError("trusted input handoff digest must be SHA-256")
    metadata = artifact_path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_EXPANDED_BYTES:
        raise TrustedInputError("trusted input artifact must be a bounded regular file")
    return metadata


def _source_input(
    api: GitHubAPI, source_repository: str, contract: dict[str, Any],
) -> tuple[MainIdentity, MainIdentity, dict[str, Any], tuple[str, int], ProviderArtifact]:
    current = resolve_main(api, source_repository)
    if current.repository_id != contract["source_repository"]["repository_id"]:
        raise TrustedInputError("trusted input source repository identity is contradictory")
    source_commit = exact_sha(contract["producer_ref"], field="trusted input producer commit")
    commit = api.commit(source_repository, source_commit)
    tree = commit.get("tree")
    if commit.get("sha") != source_commit or not isinstance(tree, dict):
        raise TrustedInputError("trusted input producer commit/tree is not exact")
    source_tree = exact_sha(tree.get("sha"), field="trusted input producer tree")
    if not github_is_ancestor(api, source_repository, base=source_commit, head=current.checkout_sha):
        raise TrustedInputError("trusted input producer is outside default-branch lineage")
    subject = MainIdentity(current.repository_id, current.default_branch, source_commit, source_tree)
    authority = load_authority(api, source_repository, subject, required_version="1.1")
    binding = contract["acquisition"]
    selected = _exact_role_run(
        api, repository=source_repository, main=subject, authority=authority,
        role=binding["role"], event=binding["event"],
    )
    artifact = resolve_role_artifact(
        api, repository=source_repository, main=subject, authority=authority,
        role=binding["role"], run_id=selected[0], run_attempt=selected[1],
        artifact_name=contract["artifact_name"], require_success=True,
    )
    return current, subject, authority, selected, artifact


def verify_trusted_input(
    *, contract: dict[str, Any], handoff: dict[str, Any], artifact_path: Path,
    executor_role: str, api: GitHubAPI | None = None,
    repository: str | None = None, source_repository: str | None = None,
) -> TrustedInputVerification:
    """Reconstruct protected producer custody; caller metadata is assertion only."""

    if executor_role != "trusted-collector":
        raise TrustedInputError("trusted external inputs may only be acquired by a trusted collector")
    if api is None or not repository or not source_repository:
        raise TrustedInputError("trusted input requires authenticated provider state")
    try:
        metadata = _admit_input(contract, handoff, artifact_path)
        consumer, population = _registered_inputs(api, repository)
        if population.get(contract["input_id"]) != contract:
            raise TrustedInputError("trusted input contract is not exact protected consumer policy")
        current, subject, authority, selected, artifact = _source_input(api, source_repository, contract)
        raw = api.artifact_bytes(source_repository, artifact.artifact_id, maximum_bytes=MAX_ARCHIVE_BYTES)
        if len(raw) > MAX_ARCHIVE_BYTES or "sha256:" + hashlib.sha256(raw).hexdigest() != artifact.provider_digest:
            raise TrustedInputError("trusted input artifact provider digest mismatch")
        payload_rule = contract["acquisition"]["payload"]
        payload = raw
        if payload_rule["kind"] == "archive_member":
            files = _archive_files(raw, require_canonical_paths=True)
            if payload_rule["path"] not in files:
                raise TrustedInputError("trusted input declared archive member is missing")
            payload = files[payload_rule["path"]]
        # The provider digest covers the archive; this digest covers the explicit payload domain.
        digest = hashlib.sha256(payload).hexdigest()
        if handoff["sha256"] != digest:
            raise TrustedInputError("trusted input payload digest does not match authenticated provider bytes")
        fd = os.open(artifact_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            actual = os.fstat(stream.fileno())
            if (actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns) != (
                metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns,
            ) or not stat.S_ISREG(actual.st_mode):
                raise TrustedInputError("trusted input local file changed during acquisition")
            if stream.read(MAX_EXPANDED_BYTES + 1) != payload:
                raise TrustedInputError("trusted input local bytes differ from authenticated payload")
        fresh = _source_input(api, source_repository, contract)
        if fresh != (current, subject, authority, selected, artifact) or resolve_main(api, repository) != consumer:
            raise TrustedInputError("trusted input provider frontier changed during verification")
    except (ValueError, OSError, KeyError, TypeError) as exc:
        if isinstance(exc, TrustedInputError):
            raise
        raise TrustedInputError(f"trusted input provider state is invalid: {exc}") from exc
    return TrustedInputVerification(
        input_id=contract["input_id"], source_repository_id=current.repository_id,
        producer_ref=subject.checkout_sha, artifact_name=artifact.artifact_name,
        sha256=digest, verified_by="provider-state",
    )


def verify_required_trusted_inputs(
    api: GitHubAPI, *, repository: str, handoffs: dict[str, dict[str, Any]],
    artifact_paths: dict[str, Path], source_repositories: dict[str, str],
) -> dict[str, TrustedInputVerification]:
    """Derive required population and admit every input before any download."""

    try:
        consumer, population = _registered_inputs(api, repository)
        supplied = set(handoffs)
        required = {key for key, rule in population.items() if rule["required"]}
        if (not required <= supplied or supplied - population.keys()
                or set(artifact_paths) != supplied or set(source_repositories) != supplied):
            raise TrustedInputError("trusted input required population is missing or contradictory")
        for key in sorted(supplied):
            if not isinstance(source_repositories[key], str) or not source_repositories[key]:
                raise TrustedInputError("trusted input source repository locator is missing")
            _admit_input(population[key], handoffs[key], artifact_paths[key])
            _source_input(api, source_repositories[key], population[key])
        results = {
            key: verify_trusted_input(
                api=api, repository=repository, source_repository=source_repositories[key],
                contract=population[key], handoff=handoffs[key], artifact_path=artifact_paths[key],
                executor_role="trusted-collector",
            ) for key in sorted(supplied)
        }
        if resolve_main(api, repository) != consumer:
            raise TrustedInputError("trusted input consumer population moved during verification")
        return results
    except (ValueError, OSError, KeyError, TypeError) as exc:
        if isinstance(exc, TrustedInputError):
            raise
        raise TrustedInputError(f"trusted input provider state is invalid: {exc}") from exc

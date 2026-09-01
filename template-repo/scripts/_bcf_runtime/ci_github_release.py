"""Authority-v1.1 release authorization, verification, collection, and inspection."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable

from .ci_authority_certification import verify_ci_certification
from .ci_authority_contracts import authority_role_workflow
from .ci_github_api import GitHubAPI
from .ci_github_bootstrap import controller_metadata, verify_controller_inventory
from .ci_github_artifacts import (
    authenticate_role_artifact,
    provider_digest,
    resolve_role_artifact,
)
from .ci_github_authority import (
    authenticate_role_job_inventory,
    load_authority,
    packaged_repo_root,
)
from .ci_github_bundle import verify_bundle, write_exclusive
from .ci_github_identity import GitHubControllerError, positive_int, resolve_main
from .ci_github_membership import select_latest_admission
from .release_closure import verify_archive, verify_release_lock, verify_wheelhouse
from .release_receipts import build_trusted_release_receipt, emit_release_receipt


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise GitHubControllerError(f"release input must be a regular file: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path, *, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise GitHubControllerError(f"{label} must be a regular file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GitHubControllerError(f"{label} is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise GitHubControllerError(f"{label} must contain an object")
    return payload


def _exact_assets(paths: Iterable[Path]) -> dict[str, str]:
    assets: dict[str, str] = {}
    for path in paths:
        if path.name in assets:
            raise GitHubControllerError("release asset inventory contains duplicates")
        assets[path.name] = _sha256(path)
    if not assets:
        raise GitHubControllerError("release asset inventory is empty")
    return dict(sorted(assets.items()))


def _verify_checksum_inventory(paths: tuple[Path, ...]) -> None:
    archives = tuple(
        path for path in paths if path.suffix == ".whl" or path.name.endswith(".tar.gz")
    )
    checksums = tuple(path for path in paths if path.name == "SHA256SUMS")
    if len(paths) != 3 or len(archives) != 2 or len(checksums) != 1 or not any(
        path.suffix == ".whl" for path in archives
    ) or not any(path.name.endswith(".tar.gz") for path in archives):
        raise GitHubControllerError(
            "release assets must be one wheel, one source archive, and SHA256SUMS"
        )
    declared: dict[str, str] = {}
    for line in checksums[0].read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(
            r"([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,254})", line
        )
        if match is None or match.group(2) in declared:
            raise GitHubControllerError("release checksum inventory is invalid")
        declared[match.group(2)] = match.group(1)
    expected = {path.name: _sha256(path) for path in archives}
    if declared != expected:
        raise GitHubControllerError("release checksum inventory is not exact")


def authorize_release(
    api: GitHubAPI,
    *,
    repository: str,
    bundle_dir: Path,
    run_id: object,
    run_attempt: object,
    certification_artifact: dict[str, str],
    controller: dict[str, str],
    controller_wheel_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Authorize a release from the newest exact-main v1.1 certification only."""

    root = bundle_dir.resolve()
    manifest = verify_bundle(root)
    certification_path = root / "ci-certification.json"
    session_path = root / "evidence-session.json"
    certification = _load_json(certification_path, label="CI certification")
    verification = verify_ci_certification(
        packaged_repo_root(),
        authority_path=root / "ci-authority.json",
        certification_path=certification_path,
        session_manifest_path=session_path,
    )
    if verification.status != "pass" or verification.computed_state != "certified":
        raise GitHubControllerError("release authorization requires certified exact main")
    if certification.get("authority_contract_version") != "1.1":
        raise GitHubControllerError("release authorization requires authority version 1.1")
    main = resolve_main(api, repository)
    subject = {
        "commit_sha": str(certification["subject"]["checkout_sha"]),
        "tree_sha": str(certification["subject"]["tree_sha"]),
    }
    if subject != {"commit_sha": main.checkout_sha, "tree_sha": main.tree_sha} or (
        manifest.get("subject") != subject
    ):
        raise GitHubControllerError("release authorization subject is not current exact main")
    authority = load_authority(api, repository, main, required_version="1.1")
    identity, _ = authenticate_role_job_inventory(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="release_authorizer",
        run_id=run_id,
        run_attempt=run_attempt,
        require_success=False,
        require_terminal=False,
    )
    required_certification = {
        "run_id", "run_attempt", "artifact_id", "artifact_name", "provider_digest"
    }
    if set(certification_artifact) != required_certification:
        raise GitHubControllerError("certification artifact identity is not exact")
    authenticated_certification = authenticate_role_artifact(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="finalizer",
        run_id=certification_artifact["run_id"],
        run_attempt=certification_artifact["run_attempt"],
        artifact_id=certification_artifact["artifact_id"],
        artifact_name=certification_artifact["artifact_name"],
        artifact_digest=certification_artifact["provider_digest"],
        require_success=True,
    )
    session = _load_json(session_path, label="evidence session")
    session_producer = session.get("producer")
    if not isinstance(session_producer, dict) or (
        str(session_producer.get("run_id")) != authenticated_certification.run_id
        or int(session_producer.get("run_attempt", 0))
        != authenticated_certification.run_attempt
    ):
        raise GitHubControllerError("certification session is not provider-bound")
    latest_run, latest_attempt = select_latest_admission(
        api, repository=repository, main=main, authority=authority
    )
    certification_admission = certification.get("admission")
    if not isinstance(certification_admission, dict) or (
        str(certification_admission.get("control_plane_run_id")) != latest_run
        or int(certification_admission.get("control_plane_run_attempt", 0))
        != latest_attempt
    ):
        raise GitHubControllerError("release authorization requires the newest admission")
    required_controller = {
        "run_id", "run_attempt", "artifact_id", "artifact_name", "provider_digest",
        "commit_sha", "tree_sha",
    }
    if set(controller) not in (required_controller, required_controller | {"wheel_sha256"}):
        raise GitHubControllerError("controller artifact identity is not exact")
    provider_digest(controller["provider_digest"])
    if controller["commit_sha"] != subject["commit_sha"] or (
        controller["tree_sha"] != subject["tree_sha"]
    ):
        raise GitHubControllerError("controller artifact is not bound to release subject")
    wheel, _ = verify_controller_inventory(controller_wheel_path.parent.resolve())
    if wheel.resolve() != controller_wheel_path.resolve():
        raise GitHubControllerError("controller wheel is not the authenticated inventory member")
    if controller_metadata(controller_wheel_path.parent / "CONTROL-METADATA.json") != {
        "schema_version": "1.0",
        "commit_sha": controller["commit_sha"],
        "tree_sha": controller["tree_sha"],
        "workflow_run_id": controller["run_id"],
        "workflow_run_attempt": str(controller["run_attempt"]),
    }:
        raise GitHubControllerError("controller metadata is not the release subject")
    wheel_sha256 = _sha256(wheel)
    caller_wheel_sha256 = controller.get("wheel_sha256")
    if caller_wheel_sha256 is not None and (
        not re.fullmatch(r"[a-f0-9]{64}", str(caller_wheel_sha256))
        or str(caller_wheel_sha256) != wheel_sha256
    ):
        raise GitHubControllerError("controller wheel bytes do not match release authority")
    authenticated_controller = authenticate_role_artifact(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="admission",
        run_id=controller["run_id"],
        run_attempt=controller["run_attempt"],
        artifact_id=controller["artifact_id"],
        artifact_name=controller["artifact_name"],
        artifact_digest=controller["provider_digest"],
        require_success=True,
    )
    if authenticated_controller.run_id != latest_run or (
        authenticated_controller.run_attempt != latest_attempt
    ):
        raise GitHubControllerError("controller artifact is not from newest exact main")
    payload = {
        "schema_version": "1.0",
        "authority_contract_version": "1.1",
        "subject": subject,
        "exact_main": {
            "admission_ordinal": str(certification["admission"]["admission_ordinal"]),
            "run_id": str(certification["admission"]["control_plane_run_id"]),
            "run_attempt": int(certification["admission"]["control_plane_run_attempt"]),
            "certification_sha256": _sha256(certification_path),
            "session_sha256": _sha256(session_path),
            "certification_artifact": authenticated_certification.as_dict(),
        },
        "authorizer": {
            "run_id": identity.run_id,
            "run_attempt": identity.run_attempt,
            "workflow": asdict(identity.workflow),
        },
        "controller": dict(sorted({**controller, "wheel_sha256": wheel_sha256}.items())),
        "authorized_at": _now(),
    }
    write_exclusive(output_path, payload)
    return payload


def record_release_build(
    *,
    authorization_path: Path,
    manifest_path: Path,
    lock_path: Path,
    release_artifacts: Iterable[Path],
    run_id: object,
    run_attempt: object,
    artifact_name: str,
    output_path: Path,
) -> dict[str, Any]:
    """Record untrusted build outputs without making a release claim."""

    authorization = _load_json(authorization_path, label="release authorization")
    closure = verify_release_lock(manifest_path, lock_path)
    attempt = positive_int(run_attempt, field="release build run attempt")
    expected_name = (
        f"bcf-release-build-{authorization['subject']['commit_sha']}-{attempt}"
    )
    if artifact_name != expected_name:
        raise GitHubControllerError("release build artifact name is not exact")
    payload = {
        "schema_version": "1.0",
        "authority_contract_version": "1.1",
        "subject": authorization["subject"],
        "authorization_sha256": _sha256(authorization_path),
        "run_id": str(positive_int(run_id, field="release build run ID")),
        "run_attempt": attempt,
        "artifact_name": artifact_name,
        "builder": {
            "run_id": str(positive_int(run_id, field="release build run ID")),
            "run_attempt": attempt,
        },
        "dependency_closure": closure.as_dict(),
        "started_at": _now(),
        "assets": _exact_assets(release_artifacts),
    }
    write_exclusive(output_path, payload)
    return payload


def verify_release_build(
    *,
    authorization_path: Path,
    build_manifest_path: Path,
    manifest_path: Path,
    lock_path: Path,
    wheelhouse: Path,
    release_artifacts: Iterable[Path],
    verifier_run_id: object,
    verifier_run_attempt: object,
    build_artifact_id: object,
    build_provider_digest: object,
    output_path: Path,
    verifier_workflow: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Recompute closed dependency, archive, and byte results on a fresh verifier."""

    authorization = _load_json(authorization_path, label="release authorization")
    build = _load_json(build_manifest_path, label="release build manifest")
    if build.get("subject") != authorization.get("subject") or (
        build.get("authorization_sha256") != _sha256(authorization_path)
    ):
        raise GitHubControllerError("release build is not bound to its authorization")
    closure = verify_wheelhouse(manifest_path, lock_path, wheelhouse)
    if build.get("dependency_closure") != closure.as_dict():
        raise GitHubControllerError("release build dependency closure is not exact")
    paths = tuple(release_artifacts)
    assets = _exact_assets(paths)
    _verify_checksum_inventory(paths)
    archives = [path for path in paths if path.suffix == ".whl" or path.name.endswith(".tar.gz")]
    for archive in archives:
        verify_archive(archive)
    declared = build.get("assets")
    if declared != assets:
        raise GitHubControllerError("release build manifest asset bytes are not exact")
    artifact_id = str(build_artifact_id)
    if not artifact_id.isdigit() or int(artifact_id) < 1:
        raise GitHubControllerError("release build artifact ID must be positive")
    digest = provider_digest(build_provider_digest)
    payload = {
        "schema_version": "1.0",
        "authority_contract_version": "1.1",
        "subject": authorization["subject"],
        "status": "passed",
        "build": {
            "manifest_sha256": _sha256(build_manifest_path),
            "run_id": str(build["run_id"]),
            "run_attempt": int(build["run_attempt"]),
            "artifact_id": artifact_id,
            "provider_digest": digest,
        },
        "verifier": {
            "run_id": str(verifier_run_id),
            "run_attempt": positive_int(
                verifier_run_attempt, field="release verifier run attempt"
            ),
            **({"workflow": verifier_workflow} if verifier_workflow is not None else {}),
        },
        "dependency_closure": closure.as_dict(),
        "assets": assets,
        "verified_at": _now(),
    }
    write_exclusive(output_path, payload)
    return payload


def verify_release_build_provider(
    api: GitHubAPI,
    *,
    repository: str,
    authorization_path: Path,
    build_manifest_path: Path,
    manifest_path: Path,
    lock_path: Path,
    wheelhouse: Path,
    release_artifacts: Iterable[Path],
    verifier_run_id: object,
    verifier_run_attempt: object,
    output_path: Path,
) -> dict[str, Any]:
    """Authenticate the triggering build and verifier before testing downloaded bytes."""

    authorization = _load_json(authorization_path, label="release authorization")
    build = _load_json(build_manifest_path, label="release build manifest")
    main = resolve_main(api, repository)
    subject = {"commit_sha": main.checkout_sha, "tree_sha": main.tree_sha}
    if authorization.get("subject") != subject or build.get("subject") != subject:
        raise GitHubControllerError("release verification subject is not current exact main")
    authority = load_authority(api, repository, main, required_version="1.1")
    authorizer = authorization.get("authorizer")
    builder = build.get("builder")
    if not isinstance(authorizer, dict) or not isinstance(builder, dict) or (
        str(authorizer.get("run_id")) != str(builder.get("run_id"))
        or int(authorizer.get("run_attempt", 0))
        != int(builder.get("run_attempt", 0))
    ):
        raise GitHubControllerError("release authorizer and build must share one attempt")
    authenticated_build = resolve_role_artifact(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="release_build",
        run_id=builder.get("run_id"),
        run_attempt=builder.get("run_attempt"),
        artifact_name=build.get("artifact_name"),
        require_success=True,
    )
    authenticate_role_job_inventory(
        api, repository=repository, main=main, authority=authority,
        role="release_build", run_id=builder.get("run_id"),
        run_attempt=builder.get("run_attempt"), require_success=True,
        require_terminal=True,
    )
    verifier, _ = authenticate_role_job_inventory(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="release_verifier",
        run_id=verifier_run_id,
        run_attempt=verifier_run_attempt,
        require_success=False,
        require_terminal=False,
    )
    return verify_release_build(
        authorization_path=authorization_path,
        build_manifest_path=build_manifest_path,
        manifest_path=manifest_path,
        lock_path=lock_path,
        wheelhouse=wheelhouse,
        release_artifacts=release_artifacts,
        verifier_run_id=verifier.run_id,
        verifier_run_attempt=verifier.run_attempt,
        build_artifact_id=authenticated_build.artifact_id,
        build_provider_digest=authenticated_build.provider_digest,
        output_path=output_path,
        verifier_workflow=asdict(verifier.workflow),
    )


def collect_release(
    api: GitHubAPI,
    *,
    repository: str,
    bundle_dir: Path,
    authorization_path: Path,
    build_manifest_path: Path,
    verification_path: Path,
    release_artifacts: Iterable[Path],
    collector_run_id: object,
    collector_run_attempt: object,
    verification_artifact_name: object,
    output_path: Path,
) -> dict[str, Any]:
    """Authenticate all release roles and emit the sole authoritative receipt."""

    root = bundle_dir.resolve()
    verify_bundle(root)
    certification_path = root / "ci-certification.json"
    session_path = root / "evidence-session.json"
    certification = _load_json(certification_path, label="CI certification")
    verification = _load_json(verification_path, label="release verification")
    authorization = _load_json(authorization_path, label="release authorization")
    build = _load_json(build_manifest_path, label="release build manifest")
    main = resolve_main(api, repository)
    authority = load_authority(api, repository, main, required_version="1.1")
    collector, _ = authenticate_role_job_inventory(
        api, repository=repository, main=main, authority=authority,
        role="release_collector", run_id=collector_run_id,
        run_attempt=collector_run_attempt, require_success=False,
        require_terminal=False,
    )
    release_workflow = authority_role_workflow(authority, "release_authorizer")
    admitted_release_runs = api.workflow_runs(
        repository,
        release_workflow["workflow_id"],
        head_sha=main.checkout_sha,
        event="workflow_dispatch",
    )
    if not admitted_release_runs:
        raise GitHubControllerError("no current-main release admission exists")
    newest_release = max(
        admitted_release_runs,
        key=lambda value: (int(value.get("id", 0)), int(value.get("run_attempt", 0))),
    )
    for role, payload, key in (
        ("release_authorizer", authorization, "authorizer"),
        ("release_build", build, "builder"),
        ("release_verifier", verification, "verifier"),
    ):
        identity = payload.get(key)
        if not isinstance(identity, dict):
            raise GitHubControllerError(f"{role} identity is missing")
        authenticate_role_job_inventory(
            api, repository=repository, main=main, authority=authority, role=role,
            run_id=identity.get("run_id"), run_attempt=identity.get("run_attempt"),
            require_success=True,
            require_terminal=True,
        )
    authorizer = authorization["authorizer"]
    builder = build["builder"]
    if (
        str(authorizer.get("run_id")) != str(builder.get("run_id"))
        or int(authorizer.get("run_attempt", 0)) != int(builder.get("run_attempt", 0))
        or str(authorizer.get("run_id")) != str(newest_release.get("id"))
        or int(authorizer.get("run_attempt", 0))
        != int(newest_release.get("run_attempt", 0))
    ):
        raise GitHubControllerError("release collection requires the newest same-run admission")
    verified_build = verification.get("build")
    if not isinstance(verified_build, dict):
        raise GitHubControllerError("verified build provider identity is missing")
    build_artifact = authenticate_role_artifact(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="release_build",
        run_id=build.get("run_id"),
        run_attempt=build.get("run_attempt"),
        artifact_id=verified_build.get("artifact_id"),
        artifact_name=build.get("artifact_name"),
        artifact_digest=verified_build.get("provider_digest"),
        require_success=True,
    )
    verifier_identity = verification.get("verifier")
    if not isinstance(verifier_identity, dict):
        raise GitHubControllerError("release verifier identity is missing")
    verification_artifact = resolve_role_artifact(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="release_verifier",
        run_id=verifier_identity.get("run_id"),
        run_attempt=verifier_identity.get("run_attempt"),
        artifact_name=verification_artifact_name,
        require_success=True,
    )
    exact_main = authorization.get("exact_main")
    certification_identity = (
        exact_main.get("certification_artifact") if isinstance(exact_main, dict) else None
    )
    if not isinstance(certification_identity, dict):
        raise GitHubControllerError("certification provider artifact identity is missing")
    certification_artifact = authenticate_role_artifact(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="finalizer",
        run_id=certification_identity.get("run_id"),
        run_attempt=certification_identity.get("run_attempt"),
        artifact_id=certification_identity.get("artifact_id"),
        artifact_name=certification_identity.get("artifact_name"),
        artifact_digest=certification_identity.get("provider_digest"),
        require_success=True,
    )
    session = _load_json(session_path, label="evidence session")
    session_producer = session.get("producer")
    if not isinstance(session_producer, dict) or (
        str(session_producer.get("run_id")) != certification_artifact.run_id
        or int(session_producer.get("run_attempt", 0))
        != certification_artifact.run_attempt
    ):
        raise GitHubControllerError("certification provider artifact is not session-bound")
    ci_verification = verify_ci_certification(
        packaged_repo_root(), authority_path=root / "ci-authority.json",
        certification_path=certification_path, session_manifest_path=session_path,
    )
    receipt = build_trusted_release_receipt(
        packaged_repo_root(), certification=certification,
        certification_path=certification_path,
        certification_verification=ci_verification.as_dict(),
        session_manifest_path=session_path, authorization_path=authorization_path,
        build_manifest_path=build_manifest_path, verification_path=verification_path,
        release_artifacts=release_artifacts,
        collector_identity={
            "workflow_path": collector.workflow.active_path,
            "run_id": collector.run_id,
            "run_attempt": str(collector.run_attempt),
        },
        build_provider_artifact=build_artifact.as_dict(),
        verification_provider_artifact=verification_artifact.as_dict(),
        certification_provider_artifact=certification_artifact.as_dict(),
        output_path=output_path,
    )
    emit_release_receipt(output_path, receipt)
    return receipt.payload


def inspect_release(
    api: GitHubAPI,
    *,
    repository: str,
    tag: str,
    expected_commit: str,
    expected_assets: dict[str, str],
) -> dict[str, Any]:
    """Fail closed unless a future release has exact immutable provider custody."""

    immutable = api.immutable_releases(repository)
    if immutable.get("enabled") is not True:
        raise GitHubControllerError("repository immutable releases are not enabled")
    reference = api.reference(repository, f"tags/{tag}")
    target = reference.get("object")
    if not isinstance(target, dict) or target.get("type") != "tag":
        raise GitHubControllerError("release tag must be annotated")
    tag_object = api.tag_object(repository, str(target.get("sha")))
    tag_target = tag_object.get("object")
    verification = tag_object.get("verification")
    if tag_object.get("tag") != tag or not isinstance(tag_target, dict) or (
        tag_target.get("type") != "commit" or tag_target.get("sha") != expected_commit
    ):
        raise GitHubControllerError("annotated release tag identity is not exact")
    if not isinstance(verification, dict) or verification.get("verified") is not False or (
        verification.get("reason") != "unsigned"
    ):
        raise GitHubControllerError("release tag does not match annotated unsigned policy")
    release = api.release_by_tag(repository, tag)
    if release.get("immutable") is not True or release.get("draft") is not False:
        raise GitHubControllerError("published release must be immutable and non-draft")
    observed: dict[str, str] = {}
    for asset in release.get("assets", []):
        if not isinstance(asset, dict) or asset.get("name") in observed:
            raise GitHubControllerError("release asset inventory is invalid")
        digest = provider_digest(asset.get("digest"))
        observed[str(asset["name"])] = digest.removeprefix("sha256:")
    if observed != expected_assets:
        raise GitHubControllerError("published release assets are not exact")
    for digest in observed.values():
        if not api.attestations(repository, f"sha256:{digest}"):
            raise GitHubControllerError("published release asset lacks attestation")
    return {
        "status": "verified",
        "tag": tag,
        "commit_sha": expected_commit,
        "immutable": True,
        "draft": False,
        "assets": dict(sorted(observed.items())),
    }


def publish_certified_release(
    api: GitHubAPI,
    *,
    repository: str,
    tag: str,
    expected_commit: str,
    release_artifacts: Iterable[Path],
    body: str,
    receipt_path: Path,
    receipt_artifact_id: object,
    receipt_artifact_name: object,
    receipt_provider_digest: object,
    publisher_run_id: object,
    publisher_run_attempt: object,
) -> dict[str, Any]:
    """Authenticate the collector receipt and publisher before mutating release state."""

    receipt = _load_json(receipt_path, label="release receipt")
    main = resolve_main(api, repository)
    if expected_commit != main.checkout_sha or receipt.get("subject") != {
        "commit_sha": main.checkout_sha,
        "tree_sha": main.tree_sha,
        "execution_tree_sha": main.tree_sha,
        "binding": "exact_tree",
        "tracked_clean": True,
        "untracked_clean": True,
        "status_porcelain_sha256": hashlib.sha256(b"").hexdigest(),
    }:
        raise GitHubControllerError("release receipt subject is not current exact main")
    if receipt.get("kind") != "release" or receipt.get("result") != "passed":
        raise GitHubControllerError("publication requires a passing release receipt")
    authority = load_authority(api, repository, main, required_version="1.1")
    authenticate_role_job_inventory(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="release_publisher",
        run_id=publisher_run_id,
        run_attempt=publisher_run_attempt,
        require_success=False,
        require_terminal=False,
    )
    workflow = receipt.get("invocation", {}).get("workflow")
    if not isinstance(workflow, dict):
        raise GitHubControllerError("release receipt collector identity is missing")
    authenticate_role_artifact(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="release_collector",
        run_id=workflow.get("run_id"),
        run_attempt=workflow.get("run_attempt"),
        artifact_id=receipt_artifact_id,
        artifact_name=receipt_artifact_name,
        artifact_digest=receipt_provider_digest,
        require_success=True,
    )
    paths = tuple(release_artifacts)
    expected_assets = _exact_assets(paths)
    receipt_assets = receipt.get("observations", {}).get("release_artifacts")
    if not isinstance(receipt_assets, list) or any(
        not isinstance(value, dict) for value in receipt_assets
    ):
        raise GitHubControllerError("release receipt does not bind exact publication assets")
    receipt_inventory = {
        str(value.get("path")): str(value.get("sha256")) for value in receipt_assets
    }
    if len(receipt_inventory) != len(receipt_assets) or receipt_inventory != expected_assets:
        raise GitHubControllerError("release receipt does not bind exact publication assets")
    return publish_release(
        api,
        repository=repository,
        tag=tag,
        expected_commit=expected_commit,
        release_artifacts=paths,
        body=body,
    )


def publish_release(
    api: GitHubAPI,
    *,
    repository: str,
    tag: str,
    expected_commit: str,
    release_artifacts: Iterable[Path],
    body: str,
) -> dict[str, Any]:
    """Create one immutable release from pre-certified bytes without rebuilding."""

    immutable = api.immutable_releases(repository)
    if immutable.get("enabled") is not True:
        raise GitHubControllerError("immutable releases must be enabled before publication")
    reference = api.reference(repository, f"tags/{tag}")
    target = reference.get("object")
    if not isinstance(target, dict) or target.get("type") != "tag":
        raise GitHubControllerError("release publication requires an annotated tag")
    tag_object = api.tag_object(repository, str(target.get("sha")))
    tag_target = tag_object.get("object")
    tag_verification = tag_object.get("verification")
    if tag_object.get("tag") != tag or not isinstance(tag_target, dict) or (
        tag_target.get("type") != "commit" or tag_target.get("sha") != expected_commit
    ):
        raise GitHubControllerError("release publication tag does not match certified commit")
    if not isinstance(tag_verification, dict) or tag_verification.get("verified") is not False or (
        tag_verification.get("reason") != "unsigned"
    ):
        raise GitHubControllerError("release publication requires the annotated unsigned tag policy")
    paths = tuple(release_artifacts)
    expected_assets = _exact_assets(paths)
    draft = api.create_draft_release(repository, tag=tag, name=tag, body=body)
    release_id = draft.get("id")
    upload_url = str(draft.get("upload_url", ""))
    uploaded: dict[str, str] = {}
    for path in paths:
        asset = api.upload_release_asset(
            upload_url=upload_url,
            repository=repository,
            release_id=release_id,
            name=path.name,
            payload=path.read_bytes(),
        )
        digest = provider_digest(asset.get("digest"))
        uploaded[path.name] = digest.removeprefix("sha256:")
    if uploaded != expected_assets:
        raise GitHubControllerError("provider release asset bytes differ before publication")
    for digest in uploaded.values():
        if not api.attestations(repository, f"sha256:{digest}"):
            raise GitHubControllerError("release assets must be attested before publication")
    api.publish_release(repository, release_id)
    return inspect_release(
        api,
        repository=repository,
        tag=tag,
        expected_commit=expected_commit,
        expected_assets=expected_assets,
    )

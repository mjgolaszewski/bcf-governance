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
from .ci_github_api import GitHubAPI
from .ci_github_authority import (
    authenticate_role_run,
    load_authority,
    packaged_repo_root,
)
from .ci_github_bundle import verify_bundle, write_exclusive
from .ci_github_identity import GitHubControllerError, positive_int, resolve_main
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


def _provider_digest(value: object) -> str:
    text = str(value)
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", text):
        raise GitHubControllerError("provider artifact digest must be SHA-256")
    return text


def _exact_assets(paths: Iterable[Path]) -> dict[str, str]:
    assets: dict[str, str] = {}
    for path in paths:
        if path.name in assets:
            raise GitHubControllerError("release asset inventory contains duplicates")
        assets[path.name] = _sha256(path)
    if not assets:
        raise GitHubControllerError("release asset inventory is empty")
    return dict(sorted(assets.items()))


def authorize_release(
    api: GitHubAPI,
    *,
    repository: str,
    bundle_dir: Path,
    run_id: object,
    run_attempt: object,
    controller: dict[str, str],
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
    identity = authenticate_role_run(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="release_authorizer",
        run_id=run_id,
        run_attempt=run_attempt,
        require_success=False,
    )
    required_controller = {
        "run_id", "run_attempt", "artifact_id", "artifact_name", "provider_digest",
        "wheel_sha256", "commit_sha", "tree_sha",
    }
    if set(controller) != required_controller:
        raise GitHubControllerError("controller artifact identity is not exact")
    _provider_digest(controller["provider_digest"])
    if controller["commit_sha"] != subject["commit_sha"] or (
        controller["tree_sha"] != subject["tree_sha"]
    ):
        raise GitHubControllerError("controller artifact is not bound to release subject")
    if not re.fullmatch(r"[a-f0-9]{64}", controller["wheel_sha256"]):
        raise GitHubControllerError("controller wheel digest must be SHA-256")
    controller_run = api.run(repository, controller["run_id"])
    if str(controller_run.get("head_sha")) != subject["commit_sha"] or int(
        controller_run.get("run_attempt", 0)
    ) != int(controller["run_attempt"]):
        raise GitHubControllerError("controller artifact run is not exact release subject")
    matching_controller = [
        value
        for value in api.artifacts(repository, controller["run_id"])
        if str(value.get("id")) == controller["artifact_id"]
        and value.get("name") == controller["artifact_name"]
        and value.get("expired") is False
    ]
    if len(matching_controller) != 1 or (
        matching_controller[0].get("digest") != controller["provider_digest"]
    ):
        raise GitHubControllerError("controller artifact provider identity is not exact")
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
        },
        "authorizer": {
            "run_id": identity.run_id,
            "run_attempt": identity.run_attempt,
            "workflow": asdict(identity.workflow),
        },
        "controller": dict(sorted(controller.items())),
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
    assets = _exact_assets(release_artifacts)
    archives = [path for path in release_artifacts if path.suffix == ".whl" or path.name.endswith(".tar.gz")]
    if len(archives) != 2 or not any(path.suffix == ".whl" for path in archives) or not any(
        path.name.endswith(".tar.gz") for path in archives
    ):
        raise GitHubControllerError("release requires exactly one wheel and one source archive")
    for archive in archives:
        verify_archive(archive)
    declared = build.get("assets")
    if declared != assets:
        raise GitHubControllerError("release build manifest asset bytes are not exact")
    artifact_id = str(build_artifact_id)
    if not artifact_id.isdigit() or int(artifact_id) < 1:
        raise GitHubControllerError("release build artifact ID must be positive")
    provider_digest = _provider_digest(build_provider_digest)
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
            "provider_digest": provider_digest,
        },
        "verifier": {
            "run_id": str(verifier_run_id),
            "run_attempt": positive_int(
                verifier_run_attempt, field="release verifier run attempt"
            ),
        },
        "dependency_closure": closure.as_dict(),
        "assets": assets,
        "verified_at": _now(),
    }
    write_exclusive(output_path, payload)
    return payload


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
    collector = authenticate_role_run(
        api, repository=repository, main=main, authority=authority,
        role="release_collector", run_id=collector_run_id,
        run_attempt=collector_run_attempt, require_success=False,
    )
    for role, payload, key in (
        ("release_authorizer", authorization, "authorizer"),
        ("release_build", build, "builder"),
        ("release_verifier", verification, "verifier"),
    ):
        identity = payload.get(key)
        if not isinstance(identity, dict):
            raise GitHubControllerError(f"{role} identity is missing")
        authenticate_role_run(
            api, repository=repository, main=main, authority=authority, role=role,
            run_id=identity.get("run_id"), run_attempt=identity.get("run_attempt"),
            require_success=True,
        )
    verified_build = verification.get("build")
    if not isinstance(verified_build, dict):
        raise GitHubControllerError("verified build provider identity is missing")
    provider_artifacts = [
        value
        for value in api.artifacts(repository, str(build.get("run_id")))
        if str(value.get("id")) == str(verified_build.get("artifact_id"))
        and value.get("name") == build.get("artifact_name")
        and value.get("expired") is False
    ]
    if len(provider_artifacts) != 1 or provider_artifacts[0].get("digest") != (
        verified_build.get("provider_digest")
    ):
        raise GitHubControllerError("release build artifact provider identity is not exact")
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
        }, output_path=output_path,
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
        digest = _provider_digest(asset.get("digest"))
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
        digest = _provider_digest(asset.get("digest"))
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

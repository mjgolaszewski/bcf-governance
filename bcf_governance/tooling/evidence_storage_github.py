"""Publish and cold-resolve durable evidence inputs through GitHub Releases."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import stat
import tempfile
from typing import Any
import zipfile

from .evidence_storage_archives import materialize_bundle
from .evidence_storage_contracts import (
    CONTRACT_PATH,
    EvidenceStorageError,
    StorageUsage,
    load_input_manifest,
    load_input_reference,
    load_storage_contract,
    load_storage_contract_path,
    validate_freshness,
    validate_storage_budget,
    write_canonical_json,
)
from .evidence_storage_github_api import GitHubEvidenceAPI
from .evidence_storage_github_releases import (
    durable_release_inventory,
    durable_release_records,
    provider_digest,
    publish_release_assets,
    verify_release,
)
from .evidence_storage_manifests import (
    CONTRACT_NAME,
    MANIFEST_NAME,
    manifest_digest,
    verify_input_bundle_contract,
)
from .evidence_storage_materialized import RESOLVED_MANIFEST


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expected_assets(bundle_dir: Path, manifest: dict[str, Any]) -> dict[str, Path]:
    paths = {MANIFEST_NAME: bundle_dir / MANIFEST_NAME}
    for item in manifest["objects"]:
        name = str(item["asset_name"])
        paths[name] = bundle_dir / "objects" / name
    return dict(sorted(paths.items()))


def provider_storage_usage(
    api: GitHubEvidenceAPI,
    *,
    contract: dict[str, Any],
    repository: str,
    run_id: str,
    artifact_name: str,
) -> StorageUsage:
    """Derive the complete budget observation from authenticated provider state."""

    repository_artifacts = api.repository_artifacts(repository)
    matches = [
        item
        for item in repository_artifacts
        if item.get("name") == artifact_name
        and isinstance(item.get("workflow_run"), dict)
        and str(item["workflow_run"].get("id")) == str(run_id)
        and item.get("expired") is not True
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("size_in_bytes"), int):
        raise EvidenceStorageError("storage budget cannot identify the exact handoff")
    durable_releases = durable_release_inventory(
        api, contract=contract, repository=repository
    )
    usage = StorageUsage(
        actions_bytes=sum(
            int(item.get("size_in_bytes", 0))
            for item in repository_artifacts
            if item.get("expired") is not True
        ),
        durable_unique_bytes=sum(durable_releases.values()),
        object_count=len(durable_releases),
        new_bytes=int(matches[0]["size_in_bytes"]),
    )
    validate_storage_budget(contract, usage)
    return usage


def _authenticate_source(
    api: GitHubEvidenceAPI,
    *,
    repository: str,
    manifest: dict[str, Any],
    handoff: dict[str, Any],
    bundle_dir: Path,
) -> None:
    repository_state = api.repository(repository)
    if repository_state.get("id") != manifest["subject"]["repository_id"]:
        raise EvidenceStorageError("evidence input repository identity mismatch")
    producer = manifest["producer"]
    if producer["kind"] != "workflow" or (
        str(producer["run_id"]) != str(handoff.get("run_id"))
        or producer["run_attempt"] != handoff.get("run_attempt")
    ):
        raise EvidenceStorageError("evidence input producer and handoff attempts differ")
    run = api.run(repository, producer["run_id"])
    run_repository = run.get("repository")
    if (
        run.get("id") != int(producer["run_id"])
        or run.get("run_attempt") != producer["run_attempt"]
        or run.get("head_sha") != manifest["subject"]["commit_sha"]
        or not isinstance(run_repository, dict)
        or run_repository.get("id") != manifest["subject"]["repository_id"]
    ):
        raise EvidenceStorageError("evidence input workflow run identity mismatch")
    commit = api.commit(repository, manifest["subject"]["commit_sha"])
    commit_tree = commit.get("tree")
    if (
        commit.get("sha") != manifest["subject"]["commit_sha"]
        or not isinstance(commit_tree, dict)
        or commit_tree.get("sha") != manifest["subject"]["tree_sha"]
    ):
        raise EvidenceStorageError("evidence input commit and tree identity mismatch")
    workflow_id = run.get("workflow_id")
    if not isinstance(workflow_id, (str, int)):
        raise EvidenceStorageError("evidence input workflow ID is missing")
    workflow = api.workflow(repository, workflow_id)
    if workflow.get("path") != producer["workflow_path"]:
        raise EvidenceStorageError("evidence input workflow path mismatch")
    content = api.content(
        repository,
        str(producer["workflow_path"]),
        ref=manifest["subject"]["commit_sha"],
    )
    if hashlib.sha256(content.content).hexdigest() != producer["workflow_sha256"]:
        raise EvidenceStorageError("evidence input workflow bytes mismatch")
    contract_content = api.content(
        repository,
        CONTRACT_PATH.as_posix(),
        ref=manifest["subject"]["commit_sha"],
    )
    bundled_contract = bundle_dir / CONTRACT_NAME
    if (
        not bundled_contract.is_file()
        or bundled_contract.is_symlink()
        or contract_content.content != bundled_contract.read_bytes()
    ):
        raise EvidenceStorageError("evidence input storage contract bytes mismatch")
    jobs = api.jobs(
        repository, int(producer["run_id"]), attempt=int(producer["run_attempt"])
    )
    matching_jobs = [item for item in jobs if item.get("name") == producer["job_name"]]
    if len(matching_jobs) != 1 or matching_jobs[0].get("conclusion") != "success":
        raise EvidenceStorageError("evidence input producer job is not uniquely successful")
    artifacts = api.artifacts(repository, producer["run_id"])
    matches = [item for item in artifacts if item.get("id") == handoff.get("artifact_id")]
    if len(matches) != 1:
        raise EvidenceStorageError("evidence input handoff artifact is not unique")
    artifact = matches[0]
    workflow_run = artifact.get("workflow_run")
    if (
        artifact.get("name") != handoff.get("artifact_name")
        or artifact.get("expired") is True
        or provider_digest(artifact.get("digest")) != handoff.get("provider_digest")
        or not isinstance(workflow_run, dict)
        or str(workflow_run.get("id")) != str(producer["run_id"])
    ):
        raise EvidenceStorageError("evidence input handoff artifact identity mismatch")


def _require_immutable_release_settings(
    api: GitHubEvidenceAPI, repository: str
) -> None:
    immutable = api.immutable_releases(repository)
    if immutable.get("enabled") is not True:
        raise EvidenceStorageError("GitHub immutable releases must be enabled")


def publish_input_bundle(
    api: GitHubEvidenceAPI,
    *,
    publication_api: GitHubEvidenceAPI | None = None,
    configuration_api: GitHubEvidenceAPI | None = None,
    schema_root: Path,
    bundle_dir: Path,
    handoff: dict[str, Any],
    output_path: Path,
) -> dict[str, Any]:
    """Authenticate, publish once, and emit the sole compact durable reference."""

    manifest, contract = verify_input_bundle_contract(
        schema_root, bundle_dir, bundle_dir / CONTRACT_NAME
    )
    repository = str(contract["provider"]["repository"])
    _require_immutable_release_settings(configuration_api or api, repository)
    return _publish_input_bundle(
        api,
        publication_api=publication_api,
        schema_root=schema_root,
        bundle_dir=bundle_dir,
        handoff=handoff,
        output_path=output_path,
        manifest=manifest,
        contract=contract,
    )


def _publish_input_bundle(
    api: GitHubEvidenceAPI,
    *,
    publication_api: GitHubEvidenceAPI | None,
    schema_root: Path,
    bundle_dir: Path,
    handoff: dict[str, Any],
    output_path: Path,
    manifest: dict[str, Any],
    contract: dict[str, Any],
) -> dict[str, Any]:
    """Publish a bundle after its repository settings were authenticated."""

    provider = contract["provider"]
    repository = str(provider["repository"])
    if contract["activation"] != "enabled":
        raise EvidenceStorageError("content-addressed evidence storage is not enabled")
    _authenticate_source(
        api,
        repository=repository,
        manifest=manifest,
        handoff=handoff,
        bundle_dir=bundle_dir,
    )
    digest = manifest_digest(manifest)
    manifest_tag = f"{provider['tag_prefix']}-manifest-{digest}"
    paths = _expected_assets(bundle_dir, manifest)
    expected_release_bytes = {
        (
            manifest_tag
            if name == MANIFEST_NAME
            else f"{provider['tag_prefix']}-object-{_file_sha256(path)}"
        ): path.stat().st_size
        for name, path in paths.items()
    }
    existing_releases = durable_release_records(
        api, contract=contract, repository=repository
    )
    new_bytes = sum(
        max(size - existing_releases.get(tag, (0, 0))[1], 0)
        for tag, size in expected_release_bytes.items()
    )
    validate_storage_budget(
        contract,
        StorageUsage(
            actions_bytes=0,
            durable_unique_bytes=sum(size for _, size in existing_releases.values())
            + new_bytes,
            object_count=len(existing_releases)
            + len(set(expected_release_bytes) - set(existing_releases)),
            new_bytes=new_bytes,
        ),
    )
    published_assets: list[dict[str, Any]] = []
    for name, path in sorted(paths.items()):
        if name == MANIFEST_NAME:
            continue
        object_digest = _file_sha256(path)
        object_tag = f"{provider['tag_prefix']}-object-{object_digest}"
        object_release, object_assets, object_target = publish_release_assets(
            api,
            publication_api=publication_api,
            repository=repository,
            contract=contract,
            tag=object_tag,
            target_commit=manifest["subject"]["commit_sha"],
            body=(
                "BCF content-addressed evidence input object. This is not a product "
                f"release.\n\nObject SHA-256: `{object_digest}`\n"
            ),
            paths={name: path},
            reusable=True,
        )
        asset = object_assets[name]
        published_assets.append(
            {
                "id": asset["id"],
                "name": name,
                "size": path.stat().st_size,
                "sha256": object_digest,
                "release_id": object_release["id"],
                "tag": object_tag,
                "target_commit": object_target,
            }
        )
    release, assets, manifest_target = publish_release_assets(
        api,
        publication_api=publication_api,
        repository=repository,
        contract=contract,
        tag=manifest_tag,
        target_commit=manifest["subject"]["commit_sha"],
        body=(
            "BCF durable evidence input manifest. This is not a product release.\n\n"
            f"Manifest SHA-256: `{digest}`\n"
        ),
        paths={MANIFEST_NAME: paths[MANIFEST_NAME]},
        reusable=False,
    )
    manifest_asset = assets[MANIFEST_NAME]
    published_assets.insert(
        0,
        {
            "id": manifest_asset["id"],
            "name": MANIFEST_NAME,
            "size": paths[MANIFEST_NAME].stat().st_size,
            "sha256": digest,
            "release_id": release["id"],
            "tag": manifest_tag,
            "target_commit": manifest_target,
        },
    )
    reference = {
        "schema_version": "1.0",
        "kind": "governance.evidence-input-reference.v1",
        "manifest_sha256": digest,
        "storage_contract_sha256": manifest["storage_contract_sha256"],
        "subject": manifest["subject"],
        "producer": manifest["producer"],
        "source_handoff": handoff,
        "provider": {
            "kind": "github_release",
            "repository": repository,
            "repository_id": provider["repository_id"],
            "release_id": release["id"],
            "tag": manifest_tag,
            "target_commit": manifest["subject"]["commit_sha"],
            "immutable": True,
            "draft": False,
            "published_at": release["published_at"],
        },
        "assets": published_assets,
    }
    write_canonical_json(output_path, reference)
    return load_input_reference(schema_root, output_path)


def _download_assets(
    api: GitHubEvidenceAPI,
    *,
    repository: str,
    reference: dict[str, Any],
    root: Path,
    maximum_bytes: int,
) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for item in reference["assets"]:
        path = root / item["name"]
        api.download_evidence_asset(
            repository,
            item["id"],
            destination=path,
            maximum_bytes=min(int(item["size"]), maximum_bytes),
        )
        if path.stat().st_size != item["size"] or _file_sha256(path) != item["sha256"]:
            raise EvidenceStorageError("downloaded evidence input asset identity mismatch")
        result[item["name"]] = path
    return result


def resolve_input_reference(
    api: GitHubEvidenceAPI,
    *,
    repo_root: Path,
    reference_path: Path,
    output_root: Path,
) -> tuple[Path, ...]:
    """Cold-resolve authenticated bytes before ordinary receipt validation."""

    root = repo_root.resolve()
    if (
        reference_path.is_symlink()
        or not reference_path.is_file()
        or not reference_path.resolve().is_relative_to(root)
    ):
        raise EvidenceStorageError("evidence input reference must remain inside the repository")
    contract = load_storage_contract(root)
    reference = load_input_reference(root, reference_path)
    provider = contract["provider"]
    if reference["provider"]["repository"] != provider["repository"] or (
        reference["provider"]["repository_id"] != provider["repository_id"]
    ):
        raise EvidenceStorageError("evidence input reference uses the wrong provider")
    expected_manifest_tag = (
        f"{provider['tag_prefix']}-manifest-{reference['manifest_sha256']}"
    )
    if reference["provider"]["tag"] != expected_manifest_tag:
        raise EvidenceStorageError("evidence input manifest tag is not canonical")
    for item in reference["assets"]:
        expected_tag = (
            expected_manifest_tag
            if item["name"] == MANIFEST_NAME
            else f"{provider['tag_prefix']}-object-{item['sha256']}"
        )
        if item["tag"] != expected_tag:
            raise EvidenceStorageError("evidence input asset tag is not canonical")
    contract_digest = _file_sha256(repo_root / CONTRACT_PATH)
    if reference["storage_contract_sha256"] != contract_digest:
        raise EvidenceStorageError("evidence input reference uses a different storage contract")
    repository = str(provider["repository"])
    releases: dict[int, dict[str, Any]] = {}
    for item in reference["assets"]:
        release, _, _ = verify_release(
            api,
            repository=repository,
            contract=contract,
            tag=item["tag"],
            expected_commit=item["target_commit"],
            expected={item["name"]: (int(item["size"]), str(item["sha256"]))},
        )
        if release.get("id") != item["release_id"]:
            raise EvidenceStorageError("evidence input asset release ID is stale")
        releases[int(release["id"])] = release
    manifest_release = releases.get(int(reference["provider"]["release_id"]))
    if manifest_release is None:
        raise EvidenceStorageError("evidence input manifest release is absent")
    if manifest_release.get("id") != reference["provider"]["release_id"]:
        raise EvidenceStorageError("evidence input reference release ID is stale")
    if output_root.exists() or output_root.is_symlink():
        raise EvidenceStorageError("evidence input output root must not already exist")
    output_root.parent.mkdir(parents=True, exist_ok=True)
    if output_root.parent.is_symlink() or not output_root.parent.resolve().is_relative_to(root):
        raise EvidenceStorageError("evidence input output parent must remain inside the repository")
    with tempfile.TemporaryDirectory(
        prefix="bcf-evidence-cold-", dir=output_root.parent
    ) as temporary_name:
        temporary = Path(temporary_name)
        assets = _download_assets(
            api,
            repository=str(provider["repository"]),
            reference=reference,
            root=temporary,
            maximum_bytes=int(provider["max_asset_bytes"]),
        )
        manifest_path = assets[MANIFEST_NAME]
        if _file_sha256(manifest_path) != reference["manifest_sha256"]:
            raise EvidenceStorageError("evidence input manifest digest mismatch")
        manifest = load_input_manifest(repo_root, manifest_path)
        if (
            manifest["subject"] != reference["subject"]
            or manifest["producer"] != reference["producer"]
            or manifest_digest(manifest) != reference["manifest_sha256"]
        ):
            raise EvidenceStorageError("evidence input manifest and reference identity differ")
        declared_assets = {
            MANIFEST_NAME,
            *{str(item["asset_name"]) for item in manifest["objects"]},
        }
        if set(assets) != declared_assets:
            raise EvidenceStorageError(
                "evidence input reference and manifest archive inventory differ"
            )
        validate_freshness(contract, manifest)
        archives = temporary / "objects"
        archives.mkdir()
        for item in manifest["objects"]:
            source = assets[item["asset_name"]]
            target = archives / item["asset_name"]
            if not target.exists():
                source.replace(target)
        staging = temporary / "materialized"
        materialized = materialize_bundle(
            manifest, archives, staging, contract["archive_safety"]
        )
        (staging / RESOLVED_MANIFEST).write_bytes(manifest_path.read_bytes())
        (staging / RESOLVED_MANIFEST).chmod(0o400)
        staging.replace(output_root)
        return tuple(
            output_root / path.relative_to(staging) for path in materialized
        )


def extract_handoff_zip(
    archive: Path,
    destination: Path,
    *,
    maximum_members: int,
    maximum_bytes: int,
    maximum_expansion_ratio: int,
) -> None:
    """Extract one Actions handoff without path traversal or decompression abuse."""

    if destination.exists() or archive.is_symlink() or not archive.is_file():
        raise EvidenceStorageError("evidence handoff extraction paths are unsafe")
    destination.mkdir(parents=True, mode=0o700)
    total = 0
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        if len(members) > maximum_members:
            raise EvidenceStorageError("evidence handoff exceeds the member limit")
        names: set[str] = set()
        for member in members:
            path = PurePosixPath(member.filename)
            mode = member.external_attr >> 16
            if (
                path.is_absolute()
                or ".." in path.parts
                or not path.parts
                or any(part in {"", "."} for part in path.parts)
                or member.filename in names
                or stat.S_ISLNK(mode)
                or stat.S_ISCHR(mode)
                or stat.S_ISBLK(mode)
                or stat.S_ISFIFO(mode)
            ):
                raise EvidenceStorageError("evidence handoff contains an unsafe member")
            names.add(member.filename)
            total += member.file_size
            if total > maximum_bytes:
                raise EvidenceStorageError("evidence handoff exceeds the expanded-byte limit")
            if member.file_size > max(member.compress_size, 1) * maximum_expansion_ratio:
                raise EvidenceStorageError("evidence handoff expansion ratio is unsafe")
            target = destination.joinpath(*path.parts)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.open(member) as input_stream, target.open("xb") as output_stream:
                remaining = member.file_size
                while remaining:
                    chunk = input_stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise EvidenceStorageError("evidence handoff member is truncated")
                    output_stream.write(chunk)
                    remaining -= len(chunk)
                if input_stream.read(1):
                    raise EvidenceStorageError(
                        "evidence handoff member exceeds its declared size"
                    )


def publish_action_handoff(
    api: GitHubEvidenceAPI,
    *,
    publication_api: GitHubEvidenceAPI | None = None,
    configuration_api: GitHubEvidenceAPI | None = None,
    schema_root: Path,
    repository: str,
    run_id: str,
    run_attempt: int,
    artifact_name: str,
    output_path: Path,
) -> dict[str, Any]:
    """Resolve one authenticated Actions handoff without caller-supplied identity."""

    settings_api = configuration_api or api
    _require_immutable_release_settings(settings_api, repository)
    run = api.run(repository, run_id)
    if (
        run.get("id") != int(run_id)
        or run.get("run_attempt") != run_attempt
        or not isinstance(run.get("head_sha"), str)
    ):
        raise EvidenceStorageError("evidence handoff run identity mismatch")
    contract_content = api.content(
        repository, CONTRACT_PATH.as_posix(), ref=str(run["head_sha"])
    )
    artifacts = api.artifacts(repository, run_id)
    matches = [item for item in artifacts if item.get("name") == artifact_name]
    if len(matches) != 1:
        raise EvidenceStorageError("evidence handoff name is not unique in the run")
    artifact = matches[0]
    handoff_provider_digest = provider_digest(artifact.get("digest"))
    if artifact.get("expired") is True:
        raise EvidenceStorageError("evidence handoff artifact has expired")
    with tempfile.TemporaryDirectory(prefix="bcf-evidence-handoff-") as temporary_name:
        temporary = Path(temporary_name)
        contract_path = temporary / CONTRACT_NAME
        contract_path.write_bytes(contract_content.content)
        contract = load_storage_contract_path(schema_root, contract_path)
        provider = contract["provider"]
        if provider["repository"] != repository:
            raise EvidenceStorageError("evidence handoff contract uses the wrong repository")
        provider_storage_usage(
            api,
            contract=contract,
            repository=repository,
            run_id=str(run_id),
            artifact_name=artifact_name,
        )
        archive = temporary / "handoff.zip"
        maximum = min(
            int(provider["max_asset_bytes"]),
            int(contract["budgets"]["maximum_new_bytes_per_run"]),
        )
        api.download_action_artifact(
            repository,
            artifact.get("id"),
            destination=archive,
            maximum_bytes=maximum,
        )
        if _file_sha256(archive) != handoff_provider_digest.removeprefix("sha256:"):
            raise EvidenceStorageError("evidence handoff ZIP differs from provider digest")
        bundle = temporary / "bundle"
        extract_handoff_zip(
            archive,
            bundle,
            maximum_members=int(contract["archive_safety"]["maximum_members"]) + 3,
            maximum_bytes=int(contract["archive_safety"]["maximum_expanded_bytes"])
            + int(contract["budgets"]["maximum_new_bytes_per_run"]),
            maximum_expansion_ratio=int(
                contract["archive_safety"]["maximum_expansion_ratio"]
            ),
        )
        if (bundle / CONTRACT_NAME).read_bytes() != contract_content.content:
            raise EvidenceStorageError("evidence handoff contract differs from exact source")
        handoff = {
            "artifact_id": artifact["id"],
            "artifact_name": artifact_name,
            "provider_digest": handoff_provider_digest,
            "run_id": str(run_id),
            "run_attempt": run_attempt,
        }
        manifest, verified_contract = verify_input_bundle_contract(
            schema_root, bundle, bundle / CONTRACT_NAME
        )
        return _publish_input_bundle(
            api,
            publication_api=publication_api,
            schema_root=schema_root,
            bundle_dir=bundle,
            handoff=handoff,
            output_path=output_path,
            manifest=manifest,
            contract=verified_contract,
        )

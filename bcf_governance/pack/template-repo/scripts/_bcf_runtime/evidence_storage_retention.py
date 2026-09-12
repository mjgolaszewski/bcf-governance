"""Reachability planning and exact transient-handoff retention application."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import tempfile
from typing import Any, cast

from jsonschema import Draft202012Validator

from .evidence_storage_contracts import (
    EvidenceStorageError,
    StorageUsage,
    load_input_reference,
    load_storage_contract,
    parse_utc,
)
from .evidence_storage_github import resolve_input_reference
from .evidence_storage_github_api import GitHubEvidenceAPI
from .evidence_storage_github_releases import durable_release_inventory


SNAPSHOT_SCHEMA = Path("schemas/evidence-retention-snapshot.schema.json")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_snapshot(repo_root: Path, path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise EvidenceStorageError("retention snapshot must be one regular nonsymlink file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        schema = json.loads((repo_root / SNAPSHOT_SCHEMA).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceStorageError(f"cannot decode evidence retention snapshot: {exc}") from exc
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise EvidenceStorageError(
            f"evidence retention snapshot schema violation at {location}: {error.message}"
        )
    return cast(dict[str, Any], payload)


def _budget(contract: dict[str, Any], usage: StorageUsage) -> tuple[bool, list[str]]:
    policy = contract["budgets"]
    values = {
        "actions_bytes": (usage.actions_bytes, policy["maximum_actions_bytes"]),
        "durable_unique_bytes": (
            usage.durable_unique_bytes,
            policy["maximum_durable_unique_bytes"],
        ),
        "object_count": (usage.object_count, policy["maximum_objects"]),
        "new_bytes": (usage.new_bytes, policy["maximum_new_bytes_per_run"]),
    }
    exceeded = [
        f"{name}:{actual}>{maximum}"
        for name, (actual, maximum) in values.items()
        if actual > maximum
    ]
    return not exceeded, exceeded


def plan_retention(
    repo_root: Path,
    snapshot_path: Path,
    *,
    api: GitHubEvidenceAPI,
    publication_api: GitHubEvidenceAPI | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Plan retention; publication_api (or api) must see unpublished releases."""

    root = repo_root.resolve()
    contract = load_storage_contract(root)
    snapshot = _load_snapshot(root, snapshot_path)
    provider = contract["provider"]
    if (
        snapshot["repository"] != provider["repository"]
        or snapshot["repository_id"] != provider["repository_id"]
    ):
        raise EvidenceStorageError("retention snapshot uses the wrong repository identity")
    repository = str(provider["repository"])
    repository_state = api.repository(repository)
    if repository_state.get("id") != provider["repository_id"]:
        raise EvidenceStorageError("retention provider repository identity differs")
    observed_now = (now or datetime.now(UTC)).astimezone(UTC)
    observed = parse_utc(snapshot["observed_at_utc"], label="retention observed_at_utc")
    if observed > observed_now:
        raise EvidenceStorageError("retention snapshot is from the future")
    references = snapshot["durable_references"]
    identity_sets = (
        [item["manifest_sha256"] for item in references],
        [item["release_id"] for item in references],
        [item["tag"] for item in references],
    )
    if any(len(set(values)) != len(values) for values in identity_sets):
        raise EvidenceStorageError("retention snapshot contains ambiguous durable references")
    handoff_ids = [item["artifact_id"] for item in snapshot["actions_handoffs"]]
    if len(set(handoff_ids)) != len(handoff_ids):
        raise EvidenceStorageError("retention snapshot contains ambiguous Actions handoffs")
    allowed_roots = set(contract["retention"]["protected_roots"])
    for item in references:
        roots = {value.split(":", 1)[0] for value in item["protected_roots"]}
        if not roots.issubset(allowed_roots):
            raise EvidenceStorageError("retention snapshot uses an undeclared protected root")
    provider_artifact_rows = [
        item
        for item in api.repository_artifacts(repository)
        if item.get("expired") is not True
    ]
    if any(
        not isinstance(item.get("id"), int)
        or int(item["id"]) < 1
        or not isinstance(item.get("size_in_bytes"), int)
        or int(item["size_in_bytes"]) < 0
        for item in provider_artifact_rows
    ):
        raise EvidenceStorageError("retention provider artifact inventory is malformed")
    provider_artifacts = {
        item.get("id"): item
        for item in provider_artifact_rows
    }
    if len(provider_artifacts) != len(provider_artifact_rows):
        raise EvidenceStorageError("retention provider artifact identities are ambiguous")
    missing_handoff_ids: set[int] = set()
    for handoff in snapshot["actions_handoffs"]:
        artifact = provider_artifacts.get(handoff["artifact_id"])
        if artifact is None:
            missing_handoff_ids.add(int(handoff["artifact_id"]))
            continue
        workflow_run = artifact.get("workflow_run") if isinstance(artifact, dict) else None
        if (
            not isinstance(artifact, dict)
            or artifact.get("name") != handoff["artifact_name"]
            or artifact.get("size_in_bytes") != handoff["size"]
            or artifact.get("digest") != handoff["provider_digest"]
            or not isinstance(workflow_run, dict)
            or str(workflow_run.get("id")) != handoff["run_id"]
        ):
            raise EvidenceStorageError("retention Actions handoff differs from provider state")
        run = api.run(repository, handoff["run_id"])
        if (
            run.get("id") != int(handoff["run_id"])
            or run.get("run_attempt") != handoff["run_attempt"]
        ):
            raise EvidenceStorageError("retention Actions handoff attempt is stale")
    by_manifest: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    with tempfile.TemporaryDirectory(prefix=".bcf-retention-", dir=root) as temporary:
        temporary_root = Path(temporary)
        for index, item in enumerate(references, start=1):
            relative = PurePosixPath(item["reference_path"])
            if relative.as_posix() != item["reference_path"]:
                raise EvidenceStorageError("retention durable reference path is not canonical")
            reference_path = root.joinpath(*relative.parts)
            if (
                reference_path.is_symlink()
                or not reference_path.is_file()
                or not reference_path.resolve().is_relative_to(root)
                or _sha256(reference_path) != item["reference_sha256"]
            ):
                raise EvidenceStorageError("retention durable reference bytes differ")
            reference = load_input_reference(root, reference_path)
            if (
                reference["manifest_sha256"] != item["manifest_sha256"]
                or reference["provider"]["release_id"] != item["release_id"]
                or reference["provider"]["tag"] != item["tag"]
            ):
                raise EvidenceStorageError("retention durable reference identity differs")
            resolve_input_reference(
                api,
                repo_root=root,
                reference_path=reference_path,
                output_root=temporary_root / f"resolved-{index}",
            )
            by_manifest[item["manifest_sha256"]] = (item, reference)
    active_leases: set[str] = set()
    for lease in snapshot["leases"]:
        manifest = lease["manifest_sha256"]
        if manifest not in by_manifest:
            raise EvidenceStorageError("retention lease references an unknown durable manifest")
        if parse_utc(lease["expires_at_utc"], label="retention lease expiry") > observed_now:
            active_leases.add(manifest)
    deletable_handoffs: list[int] = []
    retained_handoffs: list[int] = []
    absent_handoffs: list[int] = []
    for handoff in snapshot["actions_handoffs"]:
        manifest = handoff["published_manifest_sha256"]
        selected = by_manifest.get(manifest) if manifest is not None else None
        reference = selected[1] if selected is not None else None
        source = reference["source_handoff"] if reference is not None else None
        authenticated_reference = (
            isinstance(source, dict)
            and source["artifact_id"] == handoff["artifact_id"]
            and source["artifact_name"] == handoff["artifact_name"]
            and source["provider_digest"] == handoff["provider_digest"]
            and source["run_id"] == handoff["run_id"]
            and source["run_attempt"] == handoff["run_attempt"]
        )
        artifact_id = int(handoff["artifact_id"])
        if artifact_id in missing_handoff_ids:
            if not authenticated_reference:
                raise EvidenceStorageError(
                    "missing Actions handoff lacks an authenticated durable reference"
                )
            destination = absent_handoffs
        else:
            destination = (
                deletable_handoffs
                if authenticated_reference and manifest not in active_leases
                else retained_handoffs
            )
        destination.append(artifact_id)
    protected_release_ids: set[int] = set()
    for manifest_sha256, (item, reference) in by_manifest.items():
        if item["protected_roots"] or manifest_sha256 in active_leases:
            protected_release_ids.update(
                int(asset["release_id"]) for asset in reference["assets"]
            )
    durable_releases = durable_release_inventory(
        publication_api or api, contract=contract, repository=repository
    )
    unreachable = set(durable_releases) - protected_release_ids
    usage = StorageUsage(
        actions_bytes=sum(
            int(item.get("size_in_bytes", 0)) for item in provider_artifacts.values()
        ),
        durable_unique_bytes=sum(durable_releases.values()),
        object_count=len(durable_releases),
        new_bytes=0,
    )
    within_budget, exceeded = _budget(contract, usage)
    return {
        "schema_version": "1.0",
        "kind": "governance.evidence-retention-plan.v1",
        "snapshot_sha256": hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
        "observed_at_utc": snapshot["observed_at_utc"],
        "actions_handoff_delete_ids": sorted(deletable_handoffs),
        "actions_handoff_retain_ids": sorted(retained_handoffs),
        "actions_handoff_already_absent_ids": sorted(absent_handoffs),
        "durable_release_review_ids": sorted(unreachable),
        "automatic_durable_deletion": False,
        "active_lease_manifests": sorted(active_leases),
        "usage": usage.as_dict(),
        "within_budget": within_budget,
        "budget_exceeded": exceeded,
    }


def apply_actions_retention(
    repo_root: Path,
    snapshot_path: Path,
    *,
    api: GitHubEvidenceAPI,
    publication_api: GitHubEvidenceAPI | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Delete only exact transient handoffs admitted by a fresh retention plan."""

    plan = plan_retention(
        repo_root, snapshot_path, api=api, publication_api=publication_api, now=now
    )
    contract = load_storage_contract(repo_root.resolve())
    repository = str(contract["provider"]["repository"])
    deleted: list[int] = []
    for artifact_id in plan["actions_handoff_delete_ids"]:
        api.delete_action_artifact(repository, artifact_id)
        deleted.append(int(artifact_id))
    remaining = {
        int(item["id"])
        for item in api.repository_artifacts(repository)
        if item.get("expired") is not True and isinstance(item.get("id"), int)
    }
    if remaining.intersection(deleted):
        raise EvidenceStorageError("provider retained an Actions artifact after deletion")
    return {
        "schema_version": "1.0",
        "kind": "governance.evidence-actions-retention-result.v1",
        "snapshot_sha256": plan["snapshot_sha256"],
        "deleted_artifact_ids": deleted,
        "already_absent_artifact_ids": plan["actions_handoff_already_absent_ids"],
        "durable_release_deletion_attempted": False,
    }

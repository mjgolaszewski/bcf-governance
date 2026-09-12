"""Decode durable evidence contracts and enforce closed storage budgets."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
from typing import Any

from jsonschema import Draft202012Validator
import yaml


CONTRACT_PATH = Path("governance/evidence-storage.yml")
CONTRACT_SCHEMA = Path("schemas/evidence-storage.schema.json")
MANIFEST_SCHEMA = Path("schemas/evidence-input-manifest.schema.json")
REFERENCE_SCHEMA = Path("schemas/evidence-input-reference.schema.json")


class EvidenceStorageError(ValueError):
    """Raised when durable evidence inputs are unsafe or unverifiable."""


@dataclass(frozen=True)
class EvidenceInputReference:
    """Closed identity used before any durable evidence byte is trusted."""

    manifest_sha256: str
    storage_contract_sha256: str
    repository_id: int
    subject_commit: str
    subject_tree: str
    producer_run_id: str
    producer_run_attempt: int
    release_id: int


@dataclass(frozen=True)
class StorageUsage:
    actions_bytes: int
    durable_unique_bytes: int
    object_count: int
    new_bytes: int

    def as_dict(self) -> dict[str, int]:
        return {
            "actions_bytes": self.actions_bytes,
            "durable_unique_bytes": self.durable_unique_bytes,
            "object_count": self.object_count,
            "new_bytes": self.new_bytes,
        }


def _mapping(path: Path, *, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise EvidenceStorageError(f"{label} must be one regular nonsymlink file")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise EvidenceStorageError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceStorageError(f"{label} must decode to an object")
    return value


def _json_mapping(path: Path, *, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise EvidenceStorageError(f"{label} must be one regular nonsymlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceStorageError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceStorageError(f"{label} must decode to an object")
    return value


def _schema(repo_root: Path, relative: Path) -> dict[str, Any]:
    return _json_mapping(repo_root / relative, label=relative.as_posix())


def _validate(
    payload: dict[str, Any], schema: dict[str, Any], *, label: str
) -> None:
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise EvidenceStorageError(
            f"{label} schema violation at {location}: {error.message}"
        )


def canonical_json(payload: dict[str, Any]) -> bytes:
    """Return the sole digest representation for manifests and references."""

    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_relative_path(value: object, *, label: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise EvidenceStorageError(f"{label} must be a canonical relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or ".." in path.parts
        or any(part in {"", "."} for part in path.parts)
    ):
        raise EvidenceStorageError(f"{label} must be a canonical relative path")
    return path


def load_storage_contract(repo_root: Path) -> dict[str, Any]:
    root = repo_root.resolve()
    return load_storage_contract_path(root, root / CONTRACT_PATH)


def load_storage_contract_path(schema_root: Path, path: Path) -> dict[str, Any]:
    payload = _mapping(path, label=CONTRACT_PATH.as_posix())
    _validate(
        payload,
        _schema(schema_root.resolve(), CONTRACT_SCHEMA),
        label=CONTRACT_PATH.as_posix(),
    )
    if payload["activation"] == "enabled":
        provider = payload["provider"]
        if (
            provider["repository"] is None
            or provider["repository_id"] is None
            or provider["protected_environment"] is None
            or provider["credential_kind"] != "github_app"
            or provider["app_id_variable"] is None
            or provider["private_key_secret"] is None
        ):
            raise EvidenceStorageError(
                "enabled evidence storage requires repository identity and protected GitHub App authority"
            )
    return payload


def load_input_manifest(repo_root: Path, path: Path) -> dict[str, Any]:
    payload = _json_mapping(path, label="evidence input manifest")
    _validate(payload, _schema(repo_root.resolve(), MANIFEST_SCHEMA), label="evidence input manifest")
    parse_utc(payload["created_at_utc"], label="evidence input created_at_utc")
    object_ids = [str(item["id"]) for item in payload["objects"]]
    target_parts = [
        _canonical_relative_path(
            item["target_path"], label="evidence input target path"
        ).parts
        for item in payload["objects"]
    ]
    targets = [PurePosixPath(*parts).as_posix() for parts in target_parts]
    if len(set(object_ids)) != len(object_ids):
        raise EvidenceStorageError("evidence input object IDs must be unique")
    if len(set(targets)) != len(targets):
        raise EvidenceStorageError("evidence input target paths must be unique")
    if any(
        left == right[: len(left)] or right == left[: len(right)]
        for index, left in enumerate(target_parts)
        for right in target_parts[index + 1 :]
    ):
        raise EvidenceStorageError("evidence input target paths must not overlap")
    unique_archives: dict[str, tuple[int, int, str, str]] = {}
    for item in payload["objects"]:
        name = str(item["asset_name"])
        digest = str(item["archive_sha256"])
        size = int(item["archive_size"])
        if name != f"sha256-{digest}.tar.gz":
            raise EvidenceStorageError(
                "evidence input archive filename must encode its SHA-256 digest"
            )
        member_paths = [
            _canonical_relative_path(
                member["path"], label="evidence input member path"
            ).as_posix()
            for member in item["members"]
        ]
        if (
            len(set(member_paths)) != len(member_paths)
            or "root" not in member_paths
            or any(
                path != "root" and not path.startswith("root/")
                for path in member_paths
            )
        ):
            raise EvidenceStorageError(
                "evidence input member paths must be unique beneath root"
            )
        member_path_set = set(member_paths)
        if any(
            parent.as_posix() not in member_path_set
            for member_path in member_paths
            for parent in PurePosixPath(member_path).parents
            if parent.as_posix() != "."
        ):
            raise EvidenceStorageError(
                "evidence input member paths must declare every parent directory"
            )
        root_member = item["members"][member_paths.index("root")]
        if root_member["kind"] != item["root_kind"]:
            raise EvidenceStorageError("evidence input root member kind is inconsistent")
        if item["root_kind"] == "file" and len(member_paths) != 1:
            raise EvidenceStorageError("file evidence inputs cannot contain child members")
        member_bytes = sum(
            int(member["size"])
            for member in item["members"]
            if member["kind"] == "file"
        )
        if member_bytes != int(item["expanded_size"]):
            raise EvidenceStorageError(
                "evidence input expanded size differs from its members"
            )
        archive_identity = (
            size,
            int(item["expanded_size"]),
            str(item["root_kind"]),
            json.dumps(item["members"], sort_keys=True, separators=(",", ":")),
        )
        previous_identity = unique_archives.setdefault(name, archive_identity)
        if previous_identity != archive_identity:
            raise EvidenceStorageError(
                "evidence input archive identity has contradictory metadata"
            )
    if sum(identity[0] for identity in unique_archives.values()) != payload[
        "total_archive_bytes"
    ] or sum(
        int(item["expanded_size"]) for item in payload["objects"]
    ) != payload["total_expanded_bytes"]:
        raise EvidenceStorageError("evidence input manifest byte totals are inconsistent")
    return payload


def load_input_reference(repo_root: Path, path: Path) -> dict[str, Any]:
    payload = _json_mapping(path, label="evidence input reference")
    _validate(payload, _schema(repo_root.resolve(), REFERENCE_SCHEMA), label="evidence input reference")
    names = [str(item["name"]) for item in payload["assets"]]
    ids = [int(item["id"]) for item in payload["assets"]]
    if len(set(names)) != len(names) or len(set(ids)) != len(ids):
        raise EvidenceStorageError("evidence input reference asset identities must be unique")
    manifest_assets = [
        item
        for item in payload["assets"]
        if item["name"] == "evidence-input-manifest.json"
    ]
    if len(manifest_assets) != 1:
        raise EvidenceStorageError("evidence input reference requires one manifest asset")
    manifest_asset = manifest_assets[0]
    subject = payload["subject"]
    producer = payload["producer"]
    provider = payload["provider"]
    handoff = payload["source_handoff"]
    parse_utc(provider["published_at"], label="evidence input published_at")
    if provider["repository_id"] != subject["repository_id"]:
        raise EvidenceStorageError(
            "evidence input provider and subject repository identities differ"
        )
    if provider["target_commit"] != subject["commit_sha"]:
        raise EvidenceStorageError(
            "evidence input provider target and subject commit differ"
        )
    if (
        handoff["run_id"] != producer["run_id"]
        or handoff["run_attempt"] != producer["run_attempt"]
    ):
        raise EvidenceStorageError(
            "evidence input handoff and producer execution identities differ"
        )
    for item in payload["assets"]:
        if item["name"] != "evidence-input-manifest.json" and (
            item["name"] != f"sha256-{item['sha256']}.tar.gz"
        ):
            raise EvidenceStorageError(
                "evidence input asset filename must encode its SHA-256 digest"
            )
    if (
        manifest_asset["sha256"] != payload["manifest_sha256"]
        or manifest_asset["release_id"] != provider["release_id"]
        or manifest_asset["tag"] != provider["tag"]
        or manifest_asset["target_commit"] != provider["target_commit"]
    ):
        raise EvidenceStorageError("evidence input manifest provider identity differs")
    evidence_input_reference_identity(payload)
    return payload


def evidence_input_reference_identity(
    payload: dict[str, Any],
) -> EvidenceInputReference:
    """Decode the sole cross-provider identity from a validated reference."""

    return EvidenceInputReference(
        manifest_sha256=str(payload["manifest_sha256"]),
        storage_contract_sha256=str(payload["storage_contract_sha256"]),
        repository_id=int(payload["subject"]["repository_id"]),
        subject_commit=str(payload["subject"]["commit_sha"]),
        subject_tree=str(payload["subject"]["tree_sha"]),
        producer_run_id=str(payload["producer"]["run_id"]),
        producer_run_attempt=int(payload["producer"]["run_attempt"]),
        release_id=int(payload["provider"]["release_id"]),
    )


def write_canonical_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or path.is_symlink():
        raise EvidenceStorageError("evidence manifest output must not use symlinks")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_json(payload))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def parse_utc(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceStorageError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceStorageError(f"{label} must be a UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise EvidenceStorageError(f"{label} must be a UTC timestamp")
    return parsed.astimezone(UTC)


def validate_freshness(
    contract: dict[str, Any], manifest: dict[str, Any], *, now: datetime | None = None
) -> None:
    observed_now = (now or datetime.now(UTC)).astimezone(UTC)
    classes = contract["freshness_classes"]
    for item in manifest["objects"]:
        freshness = item["freshness"]
        class_id = freshness["class"]
        if class_id not in classes:
            raise EvidenceStorageError(
                f"evidence input {item['id']} uses unknown freshness class {class_id}"
            )
        policy = classes[class_id]
        observed = freshness["observed_at_utc"]
        if policy["required"] and observed is None:
            raise EvidenceStorageError(
                f"evidence input {item['id']} requires freshness observation"
            )
        maximum = policy["maximum_age_hours"]
        if observed is not None and maximum is not None:
            age = observed_now - parse_utc(observed, label="freshness observation")
            if age.total_seconds() < 0 or age.total_seconds() > maximum * 3600:
                raise EvidenceStorageError(
                    f"evidence input {item['id']} freshness has expired"
                )


def validate_storage_budget(
    contract: dict[str, Any], usage: StorageUsage
) -> None:
    budgets = contract["budgets"]
    comparisons = {
        "Actions bytes": (usage.actions_bytes, budgets["maximum_actions_bytes"]),
        "durable unique bytes": (
            usage.durable_unique_bytes,
            budgets["maximum_durable_unique_bytes"],
        ),
        "durable object count": (usage.object_count, budgets["maximum_objects"]),
        "new bytes for run": (usage.new_bytes, budgets["maximum_new_bytes_per_run"]),
    }
    exceeded = [
        f"{label} {actual}>{maximum}"
        for label, (actual, maximum) in comparisons.items()
        if actual > maximum
    ]
    if exceeded:
        raise EvidenceStorageError("evidence storage budget exceeded: " + ", ".join(exceeded))

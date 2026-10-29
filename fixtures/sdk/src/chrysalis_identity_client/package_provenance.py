from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


PACKAGE_PROVENANCE_SCHEMA = "chrysalis.identity_client.package_provenance.v1"
PACKAGE_PROVENANCE_PREDICATE_TYPE = (
    "https://chrysalis.security/slsa/package-provenance/v1"
)

_PROVENANCE_FIELDS = frozenset(
    {
        "schema",
        "predicate_type",
        "package_name",
        "version",
        "producer",
        "build_type",
        "source_ref",
        "commit_sha",
        "workflow",
        "run_id",
        "run_attempt",
        "produced_at",
        "artifacts",
    }
)
_ARTIFACT_FIELDS = frozenset({"sha256", "byte_size", "media_type"})
_SHA256SUMS = "SHA256SUMS"
_UNSAFE_SOURCE_REF_MARKERS = (
    "token=",
    "secret=",
    "password=",
    "api_key=",
    "apikey=",
    "bearer ",
)


@dataclass(frozen=True, slots=True)
class PackageProvenanceArtifact:
    name: str
    sha256: str
    byte_size: int
    media_type: str


@dataclass(frozen=True, slots=True)
class PackageProvenanceVerification:
    statement_path: Path
    artifact_root: Path
    package_name: str
    version: str
    producer: str
    build_type: str
    source_ref: str
    commit_sha: str
    workflow: str
    run_id: str
    run_attempt: str
    produced_at: str
    artifacts: dict[str, PackageProvenanceArtifact]


class PackageProvenanceRejected(RuntimeError):
    def __init__(self, failures: Sequence[str]) -> None:
        super().__init__("package provenance statement was rejected")
        self.failures = list(failures)


def build_package_provenance_statement(
    *,
    artifact_root: Path,
    package_name: str,
    version: str,
    producer: str,
    build_type: str,
    source_ref: str,
    commit_sha: str,
    workflow: str,
    run_id: str,
    run_attempt: str,
    produced_at: str,
) -> dict[str, Any]:
    artifacts = {
        path.name: _artifact_entry(path)
        for path in sorted(artifact_root.iterdir())
        if path.is_file() and (path.name == _SHA256SUMS or path.name.endswith((".whl", ".tar.gz")))
    }
    return {
        "schema": PACKAGE_PROVENANCE_SCHEMA,
        "predicate_type": PACKAGE_PROVENANCE_PREDICATE_TYPE,
        "package_name": package_name,
        "version": version,
        "producer": producer,
        "build_type": build_type,
        "source_ref": source_ref,
        "commit_sha": commit_sha,
        "workflow": workflow,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "produced_at": produced_at,
        "artifacts": artifacts,
    }


def verify_package_provenance_statement(
    *,
    statement_path: Path,
    artifact_root: Path,
) -> PackageProvenanceVerification:
    statement = _load_json(statement_path, "package_provenance_statement")
    failures = _provenance_failures(statement)
    artifacts, artifact_failures = _load_artifacts(
        statement.get("artifacts"),
        artifact_root=artifact_root,
    )
    failures.extend(artifact_failures)
    if failures:
        raise PackageProvenanceRejected(failures)
    return PackageProvenanceVerification(
        statement_path=statement_path.resolve(),
        artifact_root=artifact_root.resolve(),
        package_name=str(statement["package_name"]),
        version=str(statement["version"]),
        producer=str(statement["producer"]),
        build_type=str(statement["build_type"]),
        source_ref=str(statement["source_ref"]),
        commit_sha=str(statement["commit_sha"]),
        workflow=str(statement["workflow"]),
        run_id=str(statement["run_id"]),
        run_attempt=str(statement["run_attempt"]),
        produced_at=str(statement["produced_at"]),
        artifacts=artifacts,
    )


def _artifact_entry(path: Path) -> dict[str, Any]:
    content = path.read_bytes()
    return {
        "sha256": hashlib.sha256(content).hexdigest(),
        "byte_size": len(content),
        "media_type": _media_type(path.name),
    }


def _provenance_failures(statement: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    failures.extend(
        f"package_provenance_unknown_field:{field}"
        for field in sorted(set(statement) - _PROVENANCE_FIELDS)
    )
    if statement.get("schema") != PACKAGE_PROVENANCE_SCHEMA:
        failures.append("package_provenance_schema_unsupported")
    if statement.get("predicate_type") != PACKAGE_PROVENANCE_PREDICATE_TYPE:
        failures.append("package_provenance_predicate_type_unsupported")
    for field in (
        "package_name",
        "version",
        "producer",
        "build_type",
        "source_ref",
        "workflow",
        "run_id",
        "run_attempt",
        "produced_at",
    ):
        if not str(statement.get(field) or "").strip():
            failures.append(f"package_provenance_{field}_missing")
    if not _safe_source_ref(str(statement.get("source_ref") or "")):
        failures.append("package_provenance_source_ref_not_safe")
    if not _valid_commit_sha(str(statement.get("commit_sha") or "")):
        failures.append("package_provenance_commit_sha_invalid")
    if not _valid_timestamp(str(statement.get("produced_at") or "")):
        failures.append("package_provenance_produced_at_invalid")
    if not isinstance(statement.get("artifacts"), Mapping):
        failures.append("package_provenance_artifacts_missing")
    return failures


def _load_artifacts(
    raw_artifacts: Any,
    *,
    artifact_root: Path,
) -> tuple[dict[str, PackageProvenanceArtifact], list[str]]:
    if not isinstance(raw_artifacts, Mapping):
        return {}, ["package_provenance_artifacts_missing"]
    artifacts: dict[str, PackageProvenanceArtifact] = {}
    failures: list[str] = []
    for raw_name, raw_entry in sorted(raw_artifacts.items()):
        name = str(raw_name)
        if Path(name).name != name or "/" in name or "\\" in name:
            failures.append(f"package_provenance_artifact_name_unsafe:{name}")
            continue
        if not isinstance(raw_entry, Mapping):
            failures.append(f"package_provenance_artifact_not_object:{name}")
            continue
        artifact = _artifact_from_statement(name, raw_entry, failures=failures)
        if artifact is None:
            continue
        _verify_artifact_file(artifact, artifact_root=artifact_root, failures=failures)
        artifacts[name] = artifact
    if _SHA256SUMS not in artifacts:
        failures.append("package_provenance_sha256sums_missing")
    if not any(name.endswith(".whl") for name in artifacts):
        failures.append("package_provenance_wheel_missing")
    if not any(name.endswith(".tar.gz") for name in artifacts):
        failures.append("package_provenance_sdist_missing")
    if _SHA256SUMS in artifacts:
        failures.extend(_sha256sums_failures(artifact_root / _SHA256SUMS, artifacts))
    return artifacts, failures


def _artifact_from_statement(
    name: str,
    raw_entry: Mapping[str, Any],
    *,
    failures: list[str],
) -> PackageProvenanceArtifact | None:
    failures.extend(
        f"package_provenance_artifact_unknown_field:{name}:{field}"
        for field in sorted(set(raw_entry) - _ARTIFACT_FIELDS)
    )
    sha256 = str(raw_entry.get("sha256") or "").lower()
    byte_size = _positive_int(raw_entry.get("byte_size"))
    media_type = str(raw_entry.get("media_type") or "")
    if len(sha256) != 64 or any(char not in "0123456789abcdef" for char in sha256):
        failures.append(f"package_provenance_artifact_digest_invalid:{name}")
    if byte_size is None:
        failures.append(f"package_provenance_artifact_size_invalid:{name}")
    if media_type != _media_type(name):
        failures.append(f"package_provenance_artifact_media_type_mismatch:{name}")
    if failures and any(failure.endswith(f":{name}") for failure in failures):
        return None
    return PackageProvenanceArtifact(
        name=name,
        sha256=sha256,
        byte_size=byte_size if byte_size is not None else -1,
        media_type=media_type,
    )


def _verify_artifact_file(
    artifact: PackageProvenanceArtifact,
    *,
    artifact_root: Path,
    failures: list[str],
) -> None:
    path = (artifact_root.resolve() / artifact.name).resolve()
    if not path.is_relative_to(artifact_root.resolve()):
        failures.append(f"package_provenance_artifact_path_escape:{artifact.name}")
        return
    try:
        content = path.read_bytes()
    except OSError:
        failures.append(f"package_provenance_artifact_missing:{artifact.name}")
        return
    if hashlib.sha256(content).hexdigest() != artifact.sha256:
        failures.append(f"package_provenance_artifact_digest_mismatch:{artifact.name}")
    if len(content) != artifact.byte_size:
        failures.append(f"package_provenance_artifact_size_mismatch:{artifact.name}")


def _sha256sums_failures(
    sha256sums_path: Path,
    artifacts: Mapping[str, PackageProvenanceArtifact],
) -> list[str]:
    try:
        lines = sha256sums_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ["package_provenance_sha256sums_missing"]
    manifest: dict[str, str] = {}
    failures: list[str] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            failures.append(f"package_provenance_sha256sums_line_invalid:{line_number}")
            continue
        digest, name = parts[0].lower(), parts[1].strip()
        manifest[name] = digest
    for name, artifact in sorted(artifacts.items()):
        if name == _SHA256SUMS:
            continue
        if name not in manifest:
            failures.append(f"package_provenance_sha256sums_entry_missing:{name}")
        elif manifest[name] != artifact.sha256:
            failures.append(f"package_provenance_sha256sums_digest_mismatch:{name}")
    return failures


def _load_json(path: Path, prefix: str) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PackageProvenanceRejected([f"{prefix}_read_failed:{exc.__class__.__name__}"]) from exc
    except json.JSONDecodeError as exc:
        raise PackageProvenanceRejected([f"{prefix}_json_invalid:{exc.msg}"]) from exc
    if not isinstance(payload, Mapping):
        raise PackageProvenanceRejected([f"{prefix}_not_object"])
    return payload


def _media_type(name: str) -> str:
    if name == _SHA256SUMS:
        return "text/plain"
    if name.endswith(".whl"):
        return "application/zip"
    if name.endswith(".tar.gz"):
        return "application/gzip"
    return "application/octet-stream"


def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    return None


def _valid_commit_sha(value: str) -> bool:
    return len(value) == 40 and all(char in "0123456789abcdef" for char in value.lower())


def _valid_timestamp(value: str) -> bool:
    if not value.endswith("Z"):
        return False
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return False
    return True


def _safe_source_ref(value: str) -> bool:
    stripped = value.strip()
    if not stripped or any(char in stripped for char in "\r\n\0"):
        return False
    lowered = stripped.lower()
    if any(marker in lowered for marker in _UNSAFE_SOURCE_REF_MARKERS):
        return False
    parsed = urlparse(stripped)
    if parsed.scheme and (parsed.username or parsed.password or parsed.query or parsed.fragment):
        return False
    return True

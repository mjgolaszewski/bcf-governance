from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PACKAGE_PROMOTION_RECEIPT_SCHEMA = "chrysalis.identity_client.package_promotion.v1"
PACKAGE_SIGNING_POLICY_SCHEMA = "chrysalis.identity_client.package_signing_policy.v1"

_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "package_name",
        "version",
        "producer",
        "produced_at",
        "provenance_ref",
        "artifacts",
    }
)
_ARTIFACT_FIELDS = frozenset({"sha256", "byte_size", "media_type"})
_POLICY_FIELDS = frozenset({"schema", "authorizations"})
_AUTHORIZATION_FIELDS = frozenset(
    {"key_fingerprint", "package_name", "producer", "status"}
)
_SAFE_PROVENANCE_SCHEMES = frozenset({"artifact", "oci", "provenance", "slsa"})
_SHA256SUMS = "SHA256SUMS"


@dataclass(frozen=True, slots=True)
class PackagePromotionArtifact:
    name: str
    sha256: str
    byte_size: int
    media_type: str


@dataclass(frozen=True, slots=True)
class PackageSigningAuthorization:
    key_fingerprint: str
    package_name: str
    producer: str
    status: str


@dataclass(frozen=True, slots=True)
class PackagePromotionVerification:
    receipt_path: Path
    artifact_root: Path
    package_name: str
    version: str
    producer: str
    produced_at: str
    provenance_ref: str
    artifacts: dict[str, PackagePromotionArtifact]
    signing_key_fingerprint: str | None
    signature_authorized: bool | None


class PackagePromotionReceiptRejected(RuntimeError):
    def __init__(self, failures: Sequence[str]) -> None:
        super().__init__("package promotion receipt was rejected")
        self.failures = list(failures)


def build_package_promotion_receipt(
    *,
    artifact_root: Path,
    package_name: str,
    version: str,
    producer: str,
    produced_at: str,
    provenance_ref: str,
) -> dict[str, Any]:
    artifacts = {
        path.name: _artifact_entry(path)
        for path in sorted(artifact_root.iterdir())
        if path.is_file() and (path.name == _SHA256SUMS or path.name.endswith((".whl", ".tar.gz")))
    }
    return {
        "schema": PACKAGE_PROMOTION_RECEIPT_SCHEMA,
        "package_name": package_name,
        "version": version,
        "producer": producer,
        "produced_at": produced_at,
        "provenance_ref": provenance_ref,
        "artifacts": artifacts,
    }


def verify_package_promotion_receipt(
    *,
    receipt_path: Path,
    artifact_root: Path,
    signature_file: Path | None = None,
    signing_public_key_file: Path | None = None,
    signing_key_authorizations: Sequence[PackageSigningAuthorization] | None = None,
) -> PackagePromotionVerification:
    receipt_bytes = _read_bytes(receipt_path, "package_promotion_receipt")
    receipt = _load_json_bytes(receipt_bytes, "package_promotion_receipt")
    failures = _receipt_failures(receipt)
    artifacts, artifact_failures = _load_artifacts(
        receipt.get("artifacts"),
        artifact_root=artifact_root,
    )
    failures.extend(artifact_failures)

    signing_key_fingerprint: str | None = None
    signature_authorized: bool | None = None
    if (
        signature_file is not None
        or signing_public_key_file is not None
        or signing_key_authorizations is not None
    ):
        signing_key_fingerprint, signature_authorized, signature_failures = (
            _verify_signature_and_authorization(
                receipt_bytes,
                receipt=receipt,
                signature_file=signature_file,
                signing_public_key_file=signing_public_key_file,
                signing_key_authorizations=signing_key_authorizations,
            )
        )
        failures.extend(signature_failures)

    if failures:
        raise PackagePromotionReceiptRejected(failures)

    return PackagePromotionVerification(
        receipt_path=receipt_path.resolve(),
        artifact_root=artifact_root.resolve(),
        package_name=str(receipt["package_name"]),
        version=str(receipt["version"]),
        producer=str(receipt["producer"]),
        produced_at=str(receipt["produced_at"]),
        provenance_ref=str(receipt["provenance_ref"]),
        artifacts=artifacts,
        signing_key_fingerprint=signing_key_fingerprint,
        signature_authorized=signature_authorized,
    )


def load_package_signing_key_authorizations(
    payload: Mapping[str, Any],
) -> list[PackageSigningAuthorization]:
    failures: list[str] = []
    failures.extend(
        f"signing_policy_unknown_field:{field}"
        for field in sorted(set(payload) - _POLICY_FIELDS)
    )
    if payload.get("schema") != PACKAGE_SIGNING_POLICY_SCHEMA:
        failures.append("signing_policy_schema_unsupported")
    raw_authorizations = payload.get("authorizations")
    if not isinstance(raw_authorizations, list):
        failures.append("signing_policy_authorizations_missing")
        raw_authorizations = []
    authorizations: list[PackageSigningAuthorization] = []
    for index, raw_authorization in enumerate(raw_authorizations):
        if not isinstance(raw_authorization, Mapping):
            failures.append(f"signing_policy_authorization_not_object:{index}")
            continue
        failures.extend(
            f"signing_policy_authorization_unknown_field:{index}:{field}"
            for field in sorted(set(raw_authorization) - _AUTHORIZATION_FIELDS)
        )
        key_fingerprint = str(raw_authorization.get("key_fingerprint") or "")
        package_name = str(raw_authorization.get("package_name") or "")
        producer = str(raw_authorization.get("producer") or "")
        status = str(raw_authorization.get("status") or "")
        if not key_fingerprint:
            failures.append(f"signing_policy_key_fingerprint_missing:{index}")
        if not package_name:
            failures.append(f"signing_policy_package_name_missing:{index}")
        if not producer:
            failures.append(f"signing_policy_producer_missing:{index}")
        if status not in {"active", "retired"}:
            failures.append(f"signing_policy_status_invalid:{index}")
        if key_fingerprint and package_name and producer and status in {"active", "retired"}:
            authorizations.append(
                PackageSigningAuthorization(
                    key_fingerprint=key_fingerprint,
                    package_name=package_name,
                    producer=producer,
                    status=status,
                )
            )
    if failures:
        raise PackagePromotionReceiptRejected(failures)
    return authorizations


def _artifact_entry(path: Path) -> dict[str, Any]:
    content = path.read_bytes()
    return {
        "sha256": hashlib.sha256(content).hexdigest(),
        "byte_size": len(content),
        "media_type": _media_type(path.name),
    }


def _receipt_failures(receipt: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    failures.extend(
        f"package_promotion_receipt_unknown_field:{field}"
        for field in sorted(set(receipt) - _RECEIPT_FIELDS)
    )
    if receipt.get("schema") != PACKAGE_PROMOTION_RECEIPT_SCHEMA:
        failures.append("package_promotion_receipt_schema_unsupported")
    for field in ("package_name", "version", "producer", "produced_at", "provenance_ref"):
        if not str(receipt.get(field) or "").strip():
            failures.append(f"package_{field}_missing")
    if not _safe_provenance_ref(str(receipt.get("provenance_ref") or "")):
        failures.append("package_provenance_ref_not_safe")
    if not isinstance(receipt.get("artifacts"), Mapping):
        failures.append("package_artifacts_missing")
    return failures


def _load_artifacts(
    raw_artifacts: Any,
    *,
    artifact_root: Path,
) -> tuple[dict[str, PackagePromotionArtifact], list[str]]:
    if not isinstance(raw_artifacts, Mapping):
        return {}, ["package_artifacts_missing"]
    artifacts: dict[str, PackagePromotionArtifact] = {}
    failures: list[str] = []
    for raw_name, raw_entry in sorted(raw_artifacts.items()):
        name = str(raw_name)
        if Path(name).name != name or "/" in name or "\\" in name:
            failures.append(f"package_artifact_name_unsafe:{name}")
            continue
        if not isinstance(raw_entry, Mapping):
            failures.append(f"package_artifact_not_object:{name}")
            continue
        artifact = _artifact_from_receipt(name, raw_entry, failures=failures)
        if artifact is None:
            continue
        _verify_artifact_file(artifact, artifact_root=artifact_root, failures=failures)
        artifacts[name] = artifact
    if _SHA256SUMS not in artifacts:
        failures.append("package_sha256sums_missing")
    if not any(name.endswith(".whl") for name in artifacts):
        failures.append("package_wheel_missing")
    if not any(name.endswith(".tar.gz") for name in artifacts):
        failures.append("package_sdist_missing")
    if _SHA256SUMS in artifacts:
        failures.extend(_sha256sums_failures(artifact_root / _SHA256SUMS, artifacts))
    return artifacts, failures


def _artifact_from_receipt(
    name: str,
    raw_entry: Mapping[str, Any],
    *,
    failures: list[str],
) -> PackagePromotionArtifact | None:
    failures.extend(
        f"package_artifact_unknown_field:{name}:{field}"
        for field in sorted(set(raw_entry) - _ARTIFACT_FIELDS)
    )
    sha256 = str(raw_entry.get("sha256") or "").lower()
    byte_size = _positive_int(raw_entry.get("byte_size"))
    media_type = str(raw_entry.get("media_type") or "")
    if len(sha256) != 64 or any(char not in "0123456789abcdef" for char in sha256):
        failures.append(f"package_artifact_digest_invalid:{name}")
    if byte_size is None:
        failures.append(f"package_artifact_size_invalid:{name}")
    if media_type != _media_type(name):
        failures.append(f"package_artifact_media_type_mismatch:{name}")
    if failures and any(failure.endswith(f":{name}") for failure in failures):
        return None
    return PackagePromotionArtifact(
        name=name,
        sha256=sha256,
        byte_size=byte_size if byte_size is not None else -1,
        media_type=media_type,
    )


def _verify_artifact_file(
    artifact: PackagePromotionArtifact,
    *,
    artifact_root: Path,
    failures: list[str],
) -> None:
    path = (artifact_root.resolve() / artifact.name).resolve()
    if not path.is_relative_to(artifact_root.resolve()):
        failures.append(f"package_artifact_path_escape:{artifact.name}")
        return
    try:
        content = path.read_bytes()
    except OSError:
        failures.append(f"package_artifact_missing:{artifact.name}")
        return
    if hashlib.sha256(content).hexdigest() != artifact.sha256:
        failures.append(f"package_artifact_digest_mismatch:{artifact.name}")
    if len(content) != artifact.byte_size:
        failures.append(f"package_artifact_size_mismatch:{artifact.name}")


def _sha256sums_failures(
    sha256sums_path: Path,
    artifacts: Mapping[str, PackagePromotionArtifact],
) -> list[str]:
    try:
        lines = sha256sums_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ["package_sha256sums_missing"]
    manifest: dict[str, str] = {}
    failures: list[str] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            failures.append(f"package_sha256sums_line_invalid:{line_number}")
            continue
        digest, name = parts[0].lower(), parts[1].strip()
        manifest[name] = digest
    for name, artifact in sorted(artifacts.items()):
        if name == _SHA256SUMS:
            continue
        if name not in manifest:
            failures.append(f"package_sha256sums_entry_missing:{name}")
        elif manifest[name] != artifact.sha256:
            failures.append(f"package_sha256sums_digest_mismatch:{name}")
    return failures


def _verify_signature_and_authorization(
    receipt_bytes: bytes,
    *,
    receipt: Mapping[str, Any],
    signature_file: Path | None,
    signing_public_key_file: Path | None,
    signing_key_authorizations: Sequence[PackageSigningAuthorization] | None,
) -> tuple[str | None, bool | None, list[str]]:
    failures: list[str] = []
    if signature_file is None:
        failures.append("package_signature_file_required")
    if signing_public_key_file is None:
        failures.append("package_signing_public_key_required")
    if failures:
        return None, None, failures
    assert signature_file is not None
    assert signing_public_key_file is not None
    signature = _load_signature(signature_file)
    public_key_bytes = _read_bytes(signing_public_key_file, "package_signing_public_key")
    try:
        public_key = _load_ed25519_public_key(public_key_bytes)
    except ValueError:
        signing_key_fingerprint = hashlib.sha256(public_key_bytes).hexdigest()
        failures.append("package_signature_invalid")
    else:
        signing_key_fingerprint = _signing_key_fingerprint(public_key_bytes, public_key)
        try:
            public_key.verify(signature, receipt_bytes)
        except InvalidSignature:
            failures.append("package_signature_invalid")
    authorized: bool | None = None
    if signing_key_authorizations is not None:
        authorized = any(
            authorization.status == "active"
            and authorization.key_fingerprint == signing_key_fingerprint
            and authorization.package_name == str(receipt.get("package_name") or "")
            and authorization.producer == str(receipt.get("producer") or "")
            for authorization in signing_key_authorizations
        )
        if not authorized:
            failures.append("signing_key_unauthorized")
    return signing_key_fingerprint, authorized, failures


def _load_signature(signature_file: Path) -> bytes:
    try:
        signature_text = signature_file.read_text(encoding="utf-8").strip()
        return base64.b64decode(signature_text, validate=True)
    except (OSError, ValueError, binascii.Error) as exc:
        raise PackagePromotionReceiptRejected(
            [f"package_signature_read_failed:{exc.__class__.__name__}"]
        ) from exc


def _load_ed25519_public_key(public_key_bytes: bytes) -> Ed25519PublicKey:
    if public_key_bytes.startswith(b"-----BEGIN"):
        loaded_key = serialization.load_pem_public_key(public_key_bytes)
        if not isinstance(loaded_key, Ed25519PublicKey):
            raise ValueError("public key is not Ed25519")
        return loaded_key
    return Ed25519PublicKey.from_public_bytes(public_key_bytes)


def _signing_key_fingerprint(public_key_bytes: bytes, public_key: Ed25519PublicKey) -> str:
    if not public_key_bytes.startswith(b"-----BEGIN"):
        return hashlib.sha256(public_key_bytes).hexdigest()
    try:
        canonical_public_key = public_key.public_bytes_raw()
    except AttributeError:
        canonical_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    return hashlib.sha256(canonical_public_key).hexdigest()


def _load_json_bytes(content: bytes, prefix: str) -> Mapping[str, Any]:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise PackagePromotionReceiptRejected([f"{prefix}_json_invalid:{exc.msg}"]) from exc
    if not isinstance(payload, Mapping):
        raise PackagePromotionReceiptRejected([f"{prefix}_not_object"])
    return payload


def _read_bytes(path: Path, prefix: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise PackagePromotionReceiptRejected(
            [f"{prefix}_read_failed:{exc.__class__.__name__}"]
        ) from exc


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


def _safe_provenance_ref(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.scheme not in _SAFE_PROVENANCE_SCHEMES or not parsed.netloc:
        return False
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return False
    return True

"""Content-addressed evidence bundle digests and detached DSSE attestations."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path


DSSE_PAYLOAD_TYPE = "application/vnd.bcf.evidence-bundle.v1+json"


def bundle_digest(bundle_dir: Path, *, exclude_names: set[str] | None = None) -> str:
    excluded = exclude_names or set()
    digest = hashlib.sha256()
    for path in sorted(bundle_dir.rglob("*")):
        if not path.is_file() or path.name in excluded:
            continue
        relative = path.relative_to(bundle_dir).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        data = path.read_bytes()
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _dsse_pae(payload_type: str, payload: bytes) -> bytes:
    return (
        b"DSSEv1 "
        + str(len(payload_type.encode("utf-8"))).encode("ascii")
        + b" "
        + payload_type.encode("utf-8")
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def attest_bundle(
    repo_root: Path,
    bundle_dir: Path,
    private_key: Path,
    key_id: str,
    actor_id: str,
    output: Path,
    actor_kind: str = "service",
) -> Path:
    if actor_kind not in {"human", "model", "service", "workflow"}:
        raise ValueError(
            "attestation actor kind must be human, model, service, or workflow"
        )
    statement = {
        "bundle_sha256": bundle_digest(bundle_dir, exclude_names={output.name}),
        "commit_sha": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "tree_sha": subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "verifier": {"kind": actor_kind, "id": actor_id},
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    payload = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    signed_payload = _dsse_pae(DSSE_PAYLOAD_TYPE, payload)
    with tempfile.NamedTemporaryFile() as payload_file, tempfile.NamedTemporaryFile() as signature_file:
        payload_file.write(signed_payload)
        payload_file.flush()
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_key),
                "-in",
                payload_file.name,
                "-out",
                signature_file.name,
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ValueError(result.stderr.strip() or "unable to sign evidence bundle")
        signature = Path(signature_file.name).read_bytes()
    envelope = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {"keyid": key_id, "sig": base64.b64encode(signature).decode("ascii")}
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return output

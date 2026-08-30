"""Allocate and bind immutable evidence sessions without changing receipt schema 2.0."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

import yaml  # type: ignore[import-untyped]

from .evidence_execution import EvidenceError


SESSION_FILENAME = "evidence-session.json"
SESSION_ID_BYTES = 16
SESSION_CREATE_RETRIES = 8


@dataclass(frozen=True)
class EvidenceSession:
    """Validated immutable session material."""

    root: Path
    manifest_path: Path
    payload: dict[str, Any]
    digest: str


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo_root, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise EvidenceError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def _absolute_lexical(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _reject_symlink_components(path: Path) -> None:
    absolute = _absolute_lexical(path)
    current = Path(absolute.anchor)
    for token in absolute.parts[1:]:
        current /= token
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise EvidenceError(f"evidence session path contains a symlink: {current.name}")


def _assert_owned_private_directory(path: Path) -> None:
    metadata = path.stat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceError("evidence session root is not a directory")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise EvidenceError("evidence session root has unsafe ownership")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise EvidenceError("evidence session root must have mode 0700")


def _assert_artifact_root(repo_root: Path, artifact_root: Path) -> Path:
    root = _absolute_lexical(repo_root)
    lexical = _absolute_lexical(artifact_root)
    _reject_symlink_components(lexical)
    if lexical == root:
        raise EvidenceError("evidence artifact root cannot be the governed repository root")
    resolved = lexical.resolve()
    if resolved.is_relative_to(root.resolve()):
        relative = resolved.relative_to(root.resolve()).as_posix()
        ignored = subprocess.run(
            ["git", "check-ignore", "--no-index", "--quiet", relative],
            cwd=root,
            check=False,
        )
        if ignored.returncode != 0:
            raise EvidenceError("in-repository evidence session root must be ignored by Git")
    lexical.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(lexical)
    return lexical


def _profile(repo_root: Path) -> tuple[str, str]:
    path = repo_root / "governance-profile.yml"
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise EvidenceError("governance-profile.yml must deserialize to a mapping")
    profile = payload.get("profile")
    selected = profile.get("selected") if isinstance(profile, dict) else None
    if selected not in {"lite", "standard", "regulated"}:
        raise EvidenceError("governance-profile.yml must select a known profile")
    contract_version = payload.get("profile_contract_version", "1.0")
    if contract_version not in {"1.0", "2.0"}:
        raise EvidenceError("profile_contract_version must be 1.0 or 2.0")
    return str(selected), str(contract_version)


def _producer_identity(repo_root: Path) -> dict[str, str]:
    workflow = os.environ.get("GITHUB_ACTIONS") == "true"
    return {
        "kind": "workflow" if workflow else "local",
        "provider": "github-actions" if workflow else "local",
        "repository": os.environ.get("GITHUB_REPOSITORY", repo_root.name),
        "repository_id": os.environ.get("GITHUB_REPOSITORY_ID", "local"),
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
    }


def _closed_inventory(values: Iterable[str], *, field: str) -> list[str]:
    inventory = sorted({str(value) for value in values if str(value)})
    if not inventory:
        raise EvidenceError(f"evidence session {field} cannot be empty")
    return inventory


def _manifest_payload(
    repo_root: Path,
    session_id: str,
    expected_gates: Iterable[str],
    expected_producers: Iterable[str],
    *,
    root_kind: str,
) -> dict[str, Any]:
    profile, contract_version = _profile(repo_root)
    return {
        "schema_version": "1.0",
        "session_id": session_id,
        "subject": {
            "commit_sha": _git(repo_root, "rev-parse", "HEAD"),
            "tree_sha": _git(repo_root, "rev-parse", "HEAD^{tree}"),
        },
        "profile": profile,
        "profile_contract_version": contract_version,
        "producer": _producer_identity(repo_root),
        "expected_gate_inventory": _closed_inventory(
            expected_gates, field="gate inventory"
        ),
        "expected_producer_inventory": _closed_inventory(
            expected_producers, field="producer inventory"
        ),
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "session_root_policy": {
            "mode": "0700",
            "root_kind": root_kind,
            "immutable_manifest": True,
        },
    }


def allocate_session(
    repo_root: Path,
    artifact_root: Path,
    expected_gates: Iterable[str],
    *,
    expected_producers: Iterable[str] | None = None,
) -> EvidenceSession:
    """Create one fresh private session and atomically publish its manifest."""
    repo_root = _absolute_lexical(repo_root)
    status = _git(
        repo_root, "status", "--porcelain=v1", "--untracked-files=all", "--ignored=no"
    )
    if status:
        raise EvidenceError("evidence session requires a clean committed HEAD")
    artifact_root = _assert_artifact_root(repo_root, artifact_root)
    sessions_root = artifact_root / "sessions"
    _reject_symlink_components(sessions_root)
    sessions_root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(sessions_root, 0o700)
    root_kind = (
        "ignored_repository"
        if artifact_root.resolve().is_relative_to(repo_root.resolve())
        else "external"
    )
    producers = expected_producers or [os.environ.get("GITHUB_JOB", "local")]
    for _ in range(SESSION_CREATE_RETRIES):
        session_id = secrets.token_hex(SESSION_ID_BYTES)
        session_root = sessions_root / session_id
        try:
            os.mkdir(session_root, mode=0o700)
        except FileExistsError:
            continue
        _assert_owned_private_directory(session_root)
        payload = _manifest_payload(
            repo_root,
            session_id,
            expected_gates,
            producers,
            root_kind=root_kind,
        )
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        temporary = session_root / f".{SESSION_FILENAME}.{secrets.token_hex(8)}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            manifest_path = session_root / SESSION_FILENAME
            os.replace(temporary, manifest_path)
            os.chmod(manifest_path, 0o400)
        finally:
            if temporary.exists():
                temporary.unlink()
        return EvidenceSession(
            root=session_root,
            manifest_path=manifest_path,
            payload=payload,
            digest=_sha256_bytes(encoded),
        )
    raise EvidenceError("unable to allocate a collision-free evidence session")


def load_session(manifest_path: Path) -> EvidenceSession:
    """Load immutable session material after checking ownership and lexical safety."""
    manifest_path = _absolute_lexical(manifest_path)
    _reject_symlink_components(manifest_path)
    if not manifest_path.is_file() or manifest_path.name != SESSION_FILENAME:
        raise EvidenceError("evidence session manifest is missing or misnamed")
    root = manifest_path.parent
    _assert_owned_private_directory(root)
    metadata = manifest_path.stat()
    if stat.S_IMODE(metadata.st_mode) & 0o222:
        raise EvidenceError("evidence session manifest must be immutable")
    encoded = manifest_path.read_bytes()
    try:
        payload = json.loads(encoded)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise EvidenceError(f"evidence session manifest is invalid: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0":
        raise EvidenceError("evidence session manifest schema_version must be 1.0")
    session_id = payload.get("session_id")
    if (
        not isinstance(session_id, str)
        or len(session_id) < 32
        or any(value not in "0123456789abcdef" for value in session_id)
        or root.name != session_id
    ):
        raise EvidenceError("evidence session identity is invalid")
    return EvidenceSession(
        root=root,
        manifest_path=manifest_path,
        payload=payload,
        digest=_sha256_bytes(encoded),
    )


def bind_session(
    repo_root: Path,
    target: str,
    output_dir: Path,
    manifest_path: Path | None,
    *,
    required: bool,
) -> tuple[EvidenceSession | None, dict[str, str] | None]:
    """Validate a session and copy its immutable manifest beside one receipt."""
    if manifest_path is None:
        if required:
            raise EvidenceError("profile contract 2.0 evidence requires --session-manifest")
        return None, None
    session = load_session(manifest_path)
    output_dir = _absolute_lexical(output_dir)
    if not output_dir.resolve().is_relative_to(session.root.resolve()):
        raise EvidenceError("evidence output must stay inside its session root")
    subject = session.payload.get("subject")
    expected = {
        "commit_sha": _git(repo_root, "rev-parse", "HEAD"),
        "tree_sha": _git(repo_root, "rev-parse", "HEAD^{tree}"),
    }
    if subject != expected:
        raise EvidenceError("evidence session subject does not match current HEAD and tree")
    inventory = session.payload.get("expected_gate_inventory")
    if not isinstance(inventory, list) or target not in inventory:
        raise EvidenceError(f"gate {target} is not admitted by the evidence session")
    output_dir.mkdir(parents=True, exist_ok=True)
    copied = output_dir / SESSION_FILENAME
    source = session.manifest_path.read_bytes()
    if copied.exists() and copied.read_bytes() != source:
        raise EvidenceError("evidence output contains a different session manifest")
    if not copied.exists():
        descriptor = os.open(copied, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(source)
            stream.flush()
            os.fsync(stream.fileno())
    os.chmod(copied, 0o400)
    return session, {
        "path": SESSION_FILENAME,
        "media_type": "application/vnd.bcf.evidence-session+json",
        "sha256": session.digest,
    }

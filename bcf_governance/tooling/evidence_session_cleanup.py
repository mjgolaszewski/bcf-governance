"""Retention-bound cleanup for private BCF evidence-session directories."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import yaml

from .evidence_sessions import load_session


class SessionCleanupError(ValueError):
    """Raised before a session cleanup can escape or exceed declared policy."""


@dataclass(frozen=True)
class SessionCleanupAction:
    session_id: str
    path: str
    created_at: str
    manifest_sha256: str
    device: int
    inode: int


@dataclass(frozen=True)
class SessionCleanupReport:
    status: str
    applied: bool
    retention_hours: int
    actions: tuple[SessionCleanupAction, ...]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def _retention_hours(repo_root: Path) -> int:
    path = repo_root / "governance/artifact-manifest.yml"
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    ephemeral = payload.get("ephemeral_evidence") if isinstance(payload, dict) else None
    value = ephemeral.get("session_retention_hours") if isinstance(ephemeral, dict) else None
    if not isinstance(value, int) or value < 1:
        raise SessionCleanupError(
            "artifact manifest must declare positive ephemeral_evidence.session_retention_hours"
        )
    return value


def _sessions_root(repo_root: Path) -> Path:
    root = repo_root / ".artifacts/bcf/sessions"
    if root.is_symlink():
        raise SessionCleanupError("evidence sessions root must not be a symlink")
    ignored = subprocess.run(
        ["git", "check-ignore", "-q", "--", ".artifacts/bcf/sessions"],
        cwd=repo_root,
        check=False,
    )
    if ignored.returncode != 0:
        raise SessionCleanupError("evidence sessions root must be ignored by Git")
    return root


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise SessionCleanupError("evidence session created_at must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SessionCleanupError("evidence session created_at is invalid") from exc
    if parsed.tzinfo is None:
        raise SessionCleanupError("evidence session created_at must include a timezone")
    return parsed.astimezone(UTC)


def plan_session_cleanup(
    repo_root: Path, *, evaluated_at: datetime | None = None
) -> SessionCleanupReport:
    """Select only valid sessions older than the repository's declared retention."""

    repo_root = repo_root.resolve()
    retention = _retention_hours(repo_root)
    root = _sessions_root(repo_root)
    if not root.exists():
        return SessionCleanupReport("clean", False, retention, ())
    if not root.is_dir():
        raise SessionCleanupError("evidence sessions root must be a directory")
    instant = evaluated_at or datetime.now(UTC)
    if instant.tzinfo is None:
        raise SessionCleanupError("evaluated_at must include a timezone")
    cutoff = instant.astimezone(UTC) - timedelta(hours=retention)
    actions: list[SessionCleanupAction] = []
    for child in sorted(root.iterdir()):
        if child.is_symlink() or not child.is_dir():
            raise SessionCleanupError("evidence sessions root contains an unsafe entry")
        session = load_session(child / "evidence-session.json")
        created = _timestamp(session.payload.get("created_at"))
        if created > cutoff:
            continue
        metadata = child.stat(follow_symlinks=False)
        actions.append(
            SessionCleanupAction(
                session_id=child.name,
                path=child.relative_to(repo_root).as_posix(),
                created_at=created.isoformat().replace("+00:00", "Z"),
                manifest_sha256=hashlib.sha256(
                    session.manifest_path.read_bytes()
                ).hexdigest(),
                device=metadata.st_dev,
                inode=metadata.st_ino,
            )
        )
    return SessionCleanupReport(
        "actionable" if actions else "clean", False, retention, tuple(actions)
    )


def apply_session_cleanup(
    repo_root: Path, *, evaluated_at: datetime | None = None
) -> SessionCleanupReport:
    """Revalidate the exact planned session identity immediately before removal."""

    repo_root = repo_root.resolve()
    plan = plan_session_cleanup(repo_root, evaluated_at=evaluated_at)
    for action in plan.actions:
        path = repo_root / action.path
        if path.is_symlink() or not path.is_dir():
            raise SessionCleanupError("evidence session identity changed before cleanup")
        metadata = path.stat(follow_symlinks=False)
        session = load_session(path / "evidence-session.json")
        if (
            (metadata.st_dev, metadata.st_ino) != (action.device, action.inode)
            or session.payload.get("session_id") != action.session_id
            or session.digest != action.manifest_sha256
        ):
            raise SessionCleanupError("evidence session identity changed before cleanup")
        shutil.rmtree(path)
    return SessionCleanupReport(
        "changed" if plan.actions else "clean",
        True,
        plan.retention_hours,
        plan.actions,
    )

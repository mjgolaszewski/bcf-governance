"""Non-authoritative cache for canonical reconciliation stage checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import time
from typing import Any, Iterable

from jsonschema import Draft202012Validator


class ReconcileError(ValueError):
    """Governed projections cannot be checked or converged safely."""


def _ledger_path(repo_root: Path) -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--git-path", "bcf/reconcile-ledger-v1.json"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode or not result.stdout.strip():
        raise ReconcileError("cannot resolve local reconcile ledger path")
    path = Path(result.stdout.strip())
    return path if path.is_absolute() else repo_root / path


def _watched_digest(repo_root: Path, step: Any) -> str | None:
    watch_paths = getattr(step, "watch_paths", None)
    if watch_paths is None:
        return None
    digest = hashlib.sha256()
    digest.update(b"bcf-reconcile-stage-v1\0" + step.step_id.encode() + b"\0")
    digest.update(hashlib.sha256(Path(__file__).read_bytes()).digest())
    for declared in watch_paths:
        digest.update(declared.encode() + b"\0")
        declared_path = repo_root / declared
        candidates = (
            declared_path.rglob("*") if declared_path.is_dir() else repo_root.glob(declared)
        )
        matches = sorted(
            path
            for path in candidates
            if path.is_file() and ".git" not in path.parts and "__pycache__" not in path.parts
        )
        if not matches and declared_path.is_file():
            matches = [declared_path]
        if not matches:
            digest.update(b"absent\0")
        for path in matches:
            digest.update(path.relative_to(repo_root).as_posix().encode() + b"\0")
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _load(repo_root: Path) -> dict[str, Any]:
    try:
        path = _ledger_path(repo_root)
    except ReconcileError:
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0":
        return {}
    schema_path = repo_root / "schemas/reconcile-ledger.schema.json"
    if not schema_path.is_file() or list(
        Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8"))).iter_errors(
            payload
        )
    ):
        return {}
    stages = payload.get("stages")
    return stages if isinstance(stages, dict) else {}


def _write(
    repo_root: Path,
    stages: dict[str, Any],
    convergence: str,
    observations: list[dict[str, Any]],
) -> None:
    try:
        path = _ledger_path(repo_root)
    except ReconcileError:
        return
    payload = {
        "schema_version": "1.0",
        "authority": False,
        "stages": stages,
        "last_run": observations,
        "convergence_token": convergence,
    }
    schema = json.loads(
        (repo_root / "schemas/reconcile-ledger.schema.json").read_text(encoding="utf-8")
    )
    errors = list(Draft202012Validator(schema).iter_errors(payload))
    if errors:
        raise ReconcileError("reconcile ledger is invalid: " + errors[0].message)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _convergence(rows: list[dict[str, Any]]) -> str:
    return hashlib.sha256(
        json.dumps(
            [{"stage": row["stage"], "digest": row["digest"]} for row in rows],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def check_reconcile_steps(
    repo_root: Path, steps: Iterable[Any], *, force: bool = False
) -> dict[str, Any]:
    """Check only invalidated canonical owners and record a non-authoritative ledger."""

    previous = {} if force else _load(repo_root)
    rows: list[dict[str, Any]] = []
    next_stages: dict[str, Any] = {}
    for index, step in enumerate(tuple(steps)):
        step_id = str(getattr(step, "step_id", f"step-{index}"))
        before = _watched_digest(repo_root, step)
        cached = before is not None and previous.get(step_id, {}).get("digest") == before
        started = time.monotonic_ns()
        if not cached:
            step.check()
        duration_ms = max(0, (time.monotonic_ns() - started) // 1_000_000)
        after = _watched_digest(repo_root, step)
        if before is not None and after != before:
            raise ReconcileError(f"{step_id} check mutated governed bytes")
        if after is not None:
            next_stages[step_id] = {"digest": after}
        rows.append(
            {
                "stage": step_id,
                "state": "skipped_clean" if cached else "checked",
                "duration_ms": duration_ms,
                "digest": after or "uncacheable",
            }
        )
    convergence = _convergence(rows)
    _write(repo_root, next_stages, convergence, rows)
    return {"stages": rows, "convergence_token": convergence}


def record_reconcile_steps(repo_root: Path, steps: Iterable[Any]) -> dict[str, Any]:
    """Record a completed canonical apply without re-executing its owners."""

    rows: list[dict[str, Any]] = []
    stages: dict[str, Any] = {}
    for step in steps:
        digest = _watched_digest(repo_root, step)
        rows.append(
            {
                "stage": step.step_id,
                "state": "applied",
                "duration_ms": 0,
                "digest": digest or "uncacheable",
            }
        )
        if digest is not None:
            stages[step.step_id] = {"digest": digest}
    convergence = _convergence(rows)
    _write(repo_root, stages, convergence, rows)
    return {"stages": rows, "convergence_token": convergence}

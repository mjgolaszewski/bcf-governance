"""Emit a causal terminal observation when governance truth cannot run."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


CONCLUSIONS = frozenset(
    {"cancelled", "failure", "neutral", "skipped", "success", "timed_out"}
)


def _conclusion(name: str, value: str) -> str:
    if value not in CONCLUSIONS:
        raise ValueError(f"{name} conclusion is invalid")
    return value


def _safe_output(repo_root: Path, value: Path) -> Path:
    root = repo_root.resolve()
    path = value if value.is_absolute() else root / value
    if path.is_symlink() or not path.parent.resolve().is_relative_to(root):
        raise ValueError("terminal observation path is unsafe")
    return path


def ensure_terminal_observation(
    repo_root: Path,
    output: Path,
    *,
    preflight_result: str,
    evidence_result: str,
    repository: str,
    commit_sha: str,
    run_id: str,
    run_attempt: str,
) -> bool:
    """Preserve truth output or atomically record why it could not be produced."""

    path = _safe_output(repo_root, output)
    if path.is_file():
        json.loads(path.read_text(encoding="utf-8"))
        return True
    preflight = _conclusion("preflight", preflight_result)
    evidence = _conclusion("evidence", evidence_result)
    reasons = [
        f"{name}:{value}"
        for name, value in (("preflight", preflight), ("evidence", evidence))
        if value != "success"
    ]
    if not reasons:
        reasons.append("truth:report-not-produced")
    payload = {
        "document": {
            "kind": "governance_terminal_observation",
            "version": "1.0",
        },
        "computed_state": "failed",
        "reasons": reasons,
        "subject": {
            "commit_sha": commit_sha,
            "repository": repository,
            "run_attempt": run_attempt,
            "run_id": run_id,
        },
        "upstream": {"evidence": evidence, "preflight": preflight},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return False


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--preflight-result", required=True)
    parser.add_argument("--evidence-result", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    args = parser.parse_args(argv)
    ready = ensure_terminal_observation(
        args.repo_root,
        args.output,
        preflight_result=args.preflight_result,
        evidence_result=args.evidence_result,
        repository=args.repository,
        commit_sha=args.commit_sha,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
    )
    if not ready:
        raise SystemExit("governance truth could not run; terminal observation recorded")


if __name__ == "__main__":
    main()

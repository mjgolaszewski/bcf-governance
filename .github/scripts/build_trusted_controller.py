"""Build one exact-main trusted-controller bundle from governed source."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _run(argv: list[str], *, environment: dict[str, str] | None = None) -> None:
    subprocess.run(
        argv,
        cwd=REPO_ROOT,
        env=environment,
        check=True,
    )


def build(output: Path, *, run_id: str, run_attempt: str) -> dict[str, object]:
    destination = output if output.is_absolute() else REPO_ROOT / output
    if destination.is_symlink() or not destination.resolve().is_relative_to(REPO_ROOT):
        raise ValueError("trusted-controller output must be a nonsymlink repository path")
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError("trusted-controller output must begin empty")
    environment = dict(os.environ)
    environment["SOURCE_DATE_EPOCH"] = _git("show", "-s", "--format=%ct", "HEAD")
    _run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(destination)],
        environment=environment,
    )
    _run(
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--only-binary=:all:",
            "--dest",
            str(destination),
            "PyYAML>=6.0,<7",
            "jsonschema>=4.21,<5",
        ]
    )
    _run(
        [
            sys.executable,
            "-I",
            ".github/scripts/test_release_artifacts.py",
            "--controller-wheel-dir",
            str(destination),
        ]
    )
    metadata = {
        "schema_version": "1.0",
        "commit_sha": _git("rev-parse", "HEAD"),
        "tree_sha": _git("rev-parse", "HEAD^{tree}"),
        "workflow_run_id": run_id,
        "workflow_run_attempt": run_attempt,
    }
    metadata_path = destination / "CONTROL-METADATA.json"
    metadata_path.write_text(
        json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    admitted = sorted(destination.glob("*.whl")) + [metadata_path]
    checksums = "".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        for path in admitted
    )
    (destination / "SHA256SUMS").write_text(checksums, encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            build(args.output, run_id=args.run_id, run_attempt=args.run_attempt),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

"""Build one exact-main trusted-controller bundle from governed source."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import tomllib

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement


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


def _runtime_requirements() -> tuple[str, ...]:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    values = project.get("project", {}).get("dependencies")
    if not isinstance(values, list) or not values:
        raise ValueError("project runtime dependency inventory is missing")
    requirements: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError("project runtime dependency inventory is invalid")
        try:
            requirement = Requirement(value)
        except InvalidRequirement as exc:
            raise ValueError("project runtime dependency inventory is invalid") from exc
        if requirement.url is not None:
            raise ValueError("controller runtime dependencies may not use direct URLs")
        requirements.append(value)
    return tuple(requirements)


def _require_clean_head() -> None:
    if _git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("trusted-controller source must be a clean committed HEAD")


def _verify_offline_install(destination: Path, wheel: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="bcf-controller-install-") as name:
        root = Path(name)
        _run([sys.executable, "-m", "venv", str(root)])
        _run(
            [
                str(root / "bin/python"),
                "-m",
                "pip",
                "install",
                "--no-index",
                "--find-links",
                str(destination),
                str(wheel),
            ]
        )
        _run([str(root / "bin/bcf"), "ci-github", "--help"])


def build(output: Path, *, run_id: str, run_attempt: str) -> dict[str, object]:
    destination = output if output.is_absolute() else REPO_ROOT / output
    if destination.is_symlink() or not destination.resolve().is_relative_to(REPO_ROOT):
        raise ValueError("trusted-controller output must be a nonsymlink repository path")
    _require_clean_head()
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError("trusted-controller output must begin empty")
    environment = dict(os.environ)
    environment["SOURCE_DATE_EPOCH"] = _git("show", "-s", "--format=%ct", "HEAD")
    _run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(destination)],
        environment=environment,
    )
    runtime_requirements = _runtime_requirements()
    _run(
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--only-binary=:all:",
            "--dest",
            str(destination),
            *runtime_requirements,
        ]
    )
    marker_environment = default_environment()
    marker_environment["extra"] = ""
    metadata = {
        "schema_version": "1.1",
        "commit_sha": _git("rev-parse", "HEAD"),
        "tree_sha": _git("rev-parse", "HEAD^{tree}"),
        "workflow_run_id": run_id,
        "workflow_run_attempt": run_attempt,
        **marker_environment,
    }
    metadata_path = destination / "CONTROL-METADATA.json"
    metadata_path.write_text(
        json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    controller_wheels = sorted(destination.glob("bcf_governance-*.whl"))
    if len(controller_wheels) != 1:
        raise ValueError("trusted-controller build must produce exactly one project wheel")
    admitted = sorted(destination.glob("*.whl")) + [metadata_path]
    checksums = "".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        for path in admitted
    )
    (destination / "SHA256SUMS").write_text(checksums, encoding="utf-8")
    _run(
        [
            sys.executable,
            "-I",
            ".github/scripts/test_release_artifacts.py",
            "--controller-wheel-dir",
            str(destination),
        ]
    )
    _verify_offline_install(destination, controller_wheels[0])
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

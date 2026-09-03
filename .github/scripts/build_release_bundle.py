"""Build one hash-closed, untrusted release bundle from an authorized checkout."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
from release_source_inventory import validate_sdist_source_inventory


def _run(
    argv: list[str],
    *,
    stdout: Path | None = None,
    stderr: Path | None = None,
    environment: dict[str, str] | None = None,
) -> None:
    stdout_handle = stdout.open("wb") if stdout is not None else None
    stderr_handle = stderr.open("wb") if stderr is not None else None
    try:
        subprocess.run(
            argv,
            cwd=REPO_ROOT,
            env=environment,
            stdout=stdout_handle,
            stderr=stderr_handle,
            check=True,
        )
    finally:
        if stdout_handle is not None:
            stdout_handle.close()
        if stderr_handle is not None:
            stderr_handle.close()


def build(output: Path, *, authorization: Path, artifact_name: str) -> list[Path]:
    root = output if output.is_absolute() else REPO_ROOT / output
    if root.is_symlink() or not root.resolve().is_relative_to(REPO_ROOT):
        raise ValueError("release build root must be a nonsymlink repository path")
    if root.exists() and {
        path.name for path in root.iterdir()
    } - {"release-input"}:
        raise ValueError("release build root contains undeclared inputs")
    assets = root / "assets"
    evidence = root / "evidence"
    wheelhouse = root / "wheelhouse"
    release_inputs = root / "release"
    for path in (assets, evidence, wheelhouse, release_inputs):
        path.mkdir(parents=True, exist_ok=True)
    lock = REPO_ROOT / "release/requirements-cp312-linux-x86_64.lock"
    manifest = REPO_ROOT / "release/wheelhouse-manifest.yml"
    _run(
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--only-binary=:all:",
            "--require-hashes",
            "--dest",
            str(wheelhouse),
            "-r",
            str(lock),
        ]
    )
    _run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--require-hashes",
            "--find-links",
            str(wheelhouse),
            "-r",
            str(lock),
        ]
    )
    _run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests",
            f"--junitxml={evidence / 'source-tests.xml'}",
        ],
        stdout=evidence / "source-tests.stdout",
        stderr=evidence / "source-tests.stderr",
    )
    environment = dict(os.environ)
    environment["SOURCE_DATE_EPOCH"] = subprocess.run(
        ["git", "show", "-s", "--format=%ct", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    _run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--wheel",
            "--sdist",
            "--outdir",
            str(assets),
        ],
        stdout=evidence / "build.stdout",
        stderr=evidence / "build.stderr",
        environment=environment,
    )
    built = sorted(assets.iterdir())
    wheels = [path for path in built if path.suffix == ".whl"]
    sdists = [path for path in built if path.name.endswith(".tar.gz")]
    if len(wheels) != 1 or len(sdists) != 1 or len(built) != 2:
        raise ValueError("release build did not produce exactly one wheel and one sdist")
    validate_sdist_source_inventory(REPO_ROOT, sdists[0])
    (assets / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in wheels + sdists
        ),
        encoding="utf-8",
    )
    _run(
        [
            sys.executable,
            "-m",
            "bcf_governance.cli",
            "ci-github",
            "release",
            "build",
            "--authorization",
            str(authorization),
            "--wheelhouse-manifest",
            str(manifest),
            "--lock",
            str(lock),
            "--release-artifact-dir",
            str(assets),
            "--artifact-name",
            artifact_name,
            "--output",
            str(root / "release-build-manifest.json"),
        ]
    )
    shutil.copy2(manifest, release_inputs / manifest.name)
    shutil.copy2(lock, release_inputs / lock.name)
    return wheels + sdists


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--artifact-name", required=True)
    args = parser.parse_args()
    for path in build(
        args.output,
        authorization=args.authorization,
        artifact_name=args.artifact_name,
    ):
        print(path)


if __name__ == "__main__":
    main()

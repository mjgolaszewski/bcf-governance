"""Verify clean wheel and sdist artifacts before release publication."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

import yaml


REQUIRED_SDIST_PATHS = (
    ".github/scripts",
    ".github/workflows",
    "audits",
    "bcf_governance/pack/template-repo",
    "contracts",
    "docs",
    "examples",
    "governance",
    "governance/archive/phase-artifacts",
    "governance/test-manifests",
    "phases",
    "plans",
    "schemas",
    "template-repo",
    "template-repo/schemas",
    "tests",
    "tests/fixtures",
)
REQUIRED_SDIST_FILES = (
    "AGENTS.yml",
    "CHANGELOG.md",
    "docs/ARCHITECTURE.md",
    "docs/CI_AUTHORITY.md",
    "docs/EDITORIAL_CHECKLIST.md",
    "docs/MAINTAINING.md",
    "docs/USAGE.md",
    "LICENSE",
    "MEMORY.yml",
    "README.md",
    "architecture-boundaries.yml",
    "governance-profile.yml",
    "governance/artifact-manifest.yml",
    "governance/gate-contracts.yml",
    "governance/self-governance-policy.yml",
    "manifest.yml",
)


def run(*argv: str, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    subprocess.run(argv, cwd=cwd, env=env, check=True)


def venv_environment(root: Path) -> tuple[Path, dict[str, str]]:
    run(sys.executable, "-m", "venv", str(root))
    bindir = root / ("Scripts" if os.name == "nt" else "bin")
    python = bindir / ("python.exe" if os.name == "nt" else "python")
    env = dict(os.environ)
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
    env["VIRTUAL_ENV"] = str(root)
    return python, env


def validate_sdist_payload(source_root: Path) -> None:
    missing_directories = [
        relative
        for relative in REQUIRED_SDIST_PATHS
        if not (source_root / relative).is_dir()
    ]
    missing_files = [
        relative
        for relative in REQUIRED_SDIST_FILES
        if not (source_root / relative).is_file()
    ]
    missing = [*missing_directories, *missing_files]
    if missing:
        raise RuntimeError("sdist payload missing: " + ", ".join(missing))


def complete_lite_phase(repo: Path) -> None:
    log_path = repo / "phases/phase-01-log.yml"
    log = yaml.safe_load(log_path.read_text(encoding="utf-8"))
    log["document"]["status"] = "completed"
    for workitem in log["workitems"]:
        workitem["status"] = "DONE"
    log_path.write_text(yaml.safe_dump(log, sort_keys=False), encoding="utf-8")

    workitems_path = repo / "plans/phase-01-workitems.yml"
    workitems = yaml.safe_load(workitems_path.read_text(encoding="utf-8"))
    workitems["document"]["status"] = "completed"
    for workitem in workitems["workitems"]:
        workitem["status"] = "DONE"
    workitems_path.write_text(yaml.safe_dump(workitems, sort_keys=False), encoding="utf-8")

    ledger_path = repo / "plans/phase-ledger.yml"
    ledger = yaml.safe_load(ledger_path.read_text(encoding="utf-8"))
    ledger["active_phase"]["lifecycle_status"] = "completed"
    ledger_path.write_text(yaml.safe_dump(ledger, sort_keys=False), encoding="utf-8")


def verify_wheel(wheel: Path, temporary: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        generic_scripts = [
            name for name in archive.namelist() if name.startswith("scripts/")
        ]
    if generic_scripts:
        raise RuntimeError(
            "wheel must not package the generic top-level scripts namespace: "
            + ", ".join(generic_scripts)
        )
    python, env = venv_environment(temporary / "wheel-venv")
    run(str(python), "-m", "pip", "install", str(wheel), env=env)
    run(
        str(python),
        "-m",
        "bcf_governance.cli",
        "--version",
        cwd=temporary,
        env=env,
    )
    repo = temporary / "wheel-repo"
    repo.mkdir()
    run("git", "init", "--quiet", cwd=repo, env=env)
    run("git", "config", "user.email", "release-artifact@example.invalid", cwd=repo, env=env)
    run("git", "config", "user.name", "BCF Artifact Test", cwd=repo, env=env)
    bcf = [str(python), "-m", "bcf_governance.cli"]
    run(
        *bcf,
        "install",
        "--target",
        str(repo),
        "--profile",
        "lite",
        "--project-id",
        "artifact-smoke",
        "--project-name",
        "Artifact Smoke",
        "--product-name",
        "Artifact Smoke",
        "--require-strict-validation",
        cwd=temporary,
        env=env,
    )
    complete_lite_phase(repo)
    run("git", "add", ".", cwd=repo, env=env)
    run("git", "commit", "--quiet", "-m", "governed fixture", cwd=repo, env=env)
    run(*bcf, "validate", "--repo-root", str(repo), cwd=repo, env=env)
    run(*bcf, "doctor", "--repo-root", str(repo), cwd=repo, env=env)
    evidence = repo / ".artifacts/bcf"
    for gate in ("governance-validate", "governance-exposure-scan"):
        run(
            *bcf,
            "evidence",
            "--repo-root",
            str(repo),
            "run",
            "--gate",
            gate,
            "--output",
            str(evidence / gate),
            cwd=repo,
            env=env,
        )
    run(
        *bcf,
        "truth",
        "--repo-root",
        str(repo),
        "--evidence-dir",
        str(evidence),
        cwd=repo,
        env=env,
    )
    standalone_evidence = repo / ".artifacts/bcf-standalone"
    for gate in ("governance-validate", "governance-exposure-scan"):
        run(
            str(python),
            str(repo / "scripts/governance_evidence.py"),
            "--repo-root",
            str(repo),
            "run",
            "--gate",
            gate,
            "--output",
            str(standalone_evidence / gate),
            cwd=repo,
            env=env,
        )
    run(
        str(python),
        str(repo / "scripts/governance_truth.py"),
        "--repo-root",
        str(repo),
        "--evidence-dir",
        str(standalone_evidence),
        cwd=repo,
        env=env,
    )


def verify_sdist(sdist: Path, temporary: Path) -> None:
    source = temporary / "sdist-source"
    source.mkdir()
    with tarfile.open(sdist, "r:gz") as archive:
        archive.extractall(source, filter="data")
    roots = [path for path in source.iterdir() if path.is_dir()]
    if len(roots) != 1:
        raise RuntimeError("sdist must contain exactly one source root")
    validate_sdist_payload(roots[0])
    initialize_source_custody(roots[0])
    python, env = venv_environment(temporary / "sdist-venv")
    run(str(python), "-m", "pip", "install", f"{roots[0]}[dev]", env=env)
    run(str(python), "-m", "pytest", "-q", "tests", cwd=roots[0], env=env)


def initialize_source_custody(source_root: Path) -> None:
    """Give extracted source deterministic tracked-file semantics for its tests."""

    run("git", "init", "--quiet", cwd=source_root)
    run("git", "config", "user.email", "release-artifact@example.invalid", cwd=source_root)
    run("git", "config", "user.name", "BCF Artifact Test", cwd=source_root)
    run("git", "add", ".", cwd=source_root)
    run("git", "commit", "--quiet", "-m", "exact extracted source distribution", cwd=source_root)
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=source_root,
        check=True,
        capture_output=True,
        text=True,
    )
    if result.stdout:
        raise RuntimeError("initialized sdist custody is not clean")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    args = parser.parse_args()
    wheels = sorted(args.dist_dir.glob("bcf_governance-*.whl"))
    sdists = sorted(args.dist_dir.glob("bcf_governance-*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("expected exactly one wheel and one sdist")
    with tempfile.TemporaryDirectory(prefix="bcf-artifact-test-") as name:
        temporary = Path(name)
        verify_wheel(wheels[0].resolve(), temporary)
        verify_sdist(sdists[0].resolve(), temporary)


if __name__ == "__main__":
    main()

"""Build an exact-commit trusted controller from source or an installed BCF pack."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement

from .ci_github_bootstrap import verify_controller_inventory


RUNTIME_REQUIREMENTS = ("PyYAML>=6.0,<7", "jsonschema>=4.21,<5", "packaging>=24,<27")


class TrustedControllerBuildError(ValueError):
    """Raised when exact installed runtime cannot become one closed controller."""


def _git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo_root, check=False, capture_output=True, text=True
    )
    if result.returncode:
        raise TrustedControllerBuildError("trusted-controller Git identity is unavailable")
    return result.stdout.strip()


def _run(repo_root: Path, argv: list[str], *, environment: dict[str, str] | None = None) -> None:
    subprocess.run(argv, cwd=repo_root, env=environment, check=True)


def _require_clean_head(repo_root: Path) -> None:
    if _git(repo_root, "status", "--porcelain", "--untracked-files=all"):
        raise TrustedControllerBuildError("trusted-controller source must be a clean committed HEAD")


def _source_requirements(repo_root: Path) -> tuple[str, ...]:
    project = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    values = project.get("project", {}).get("dependencies")
    if not isinstance(values, list) or not values:
        raise TrustedControllerBuildError("project runtime dependency inventory is missing")
    result: list[str] = []
    for value in values:
        try:
            requirement = Requirement(value)
        except (InvalidRequirement, TypeError) as exc:
            raise TrustedControllerBuildError(
                "project runtime dependency inventory is invalid"
            ) from exc
        if requirement.url is not None:
            raise TrustedControllerBuildError(
                "controller runtime dependencies may not use direct URLs"
            )
        result.append(str(value))
    return tuple(result)


def _materialize_installed_source(repo_root: Path, destination: Path) -> Path:
    runtime = repo_root / "scripts/_bcf_runtime"
    schemas = repo_root / "schemas"
    if not runtime.is_dir() or runtime.is_symlink() or not schemas.is_dir():
        raise TrustedControllerBuildError("installed controller runtime is incomplete")
    source = destination / "source"
    tooling = source / "bcf_governance/tooling"
    pack_schemas = source / "bcf_governance/pack/template-repo/schemas"
    shutil.copytree(runtime, tooling)
    shutil.copytree(schemas, pack_schemas)
    (source / "bcf_governance/__init__.py").write_text(
        "from .tooling._version import __version__\n", encoding="utf-8"
    )
    (source / "bcf_governance/cli.py").write_text(
        """from __future__ import annotations
import sys
from .tooling import ci_commands, ci_github_commands

COMMANDS = {"ci": ci_commands.main, "ci-github": ci_github_commands.main}

def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in COMMANDS:
        print("usage: bcf {ci,ci-github} ...", file=sys.stderr)
        raise SystemExit(2)
    COMMANDS[args[0]](args[1:])
""",
        encoding="utf-8",
    )
    (source / "pyproject.toml").write_text(
        """[build-system]
requires = ["setuptools>=75", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "bcf-governance"
version = "0.0.0"
requires-python = ">=3.11"
dependencies = ["PyYAML>=6.0,<7", "jsonschema>=4.21,<5", "packaging>=24,<27"]

[project.scripts]
bcf = "bcf_governance.cli:main"

[tool.setuptools.packages.find]
include = ["bcf_governance*"]

[tool.setuptools.package-data]
bcf_governance = ["pack/template-repo/schemas/*.json", "tooling/*.mjs"]
""",
        encoding="utf-8",
    )
    return source


def _verify_offline_install(repo_root: Path, destination: Path, wheel: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="bcf-controller-install-") as name:
        root = Path(name)
        _run(repo_root, [sys.executable, "-m", "venv", str(root)])
        _run(
            repo_root,
            [
                str(root / "bin/python"), "-m", "pip", "install", "--no-index",
                "--find-links", str(destination), str(wheel),
            ],
        )
        _run(repo_root, [str(root / "bin/bcf"), "ci-github", "--help"])


def build(
    repo_root: Path, output: Path, *, run_id: str, run_attempt: str
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    destination = output if output.is_absolute() else repo_root / output
    if destination.is_symlink() or not destination.resolve().is_relative_to(repo_root):
        raise TrustedControllerBuildError(
            "trusted-controller output must be a nonsymlink repository path"
        )
    _require_clean_head(repo_root)
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise TrustedControllerBuildError("trusted-controller output must begin empty")
    temporary: tempfile.TemporaryDirectory[str] | None = None
    if (repo_root / "bcf_governance/cli.py").is_file():
        source_root = repo_root
        requirements = _source_requirements(repo_root)
    else:
        temporary = tempfile.TemporaryDirectory(prefix="bcf-installed-controller-")
        source_root = _materialize_installed_source(repo_root, Path(temporary.name))
        requirements = RUNTIME_REQUIREMENTS
    try:
        environment = dict(os.environ)
        environment["SOURCE_DATE_EPOCH"] = _git(repo_root, "show", "-s", "--format=%ct", "HEAD")
        _run(
            source_root,
            [sys.executable, "-m", "build", "--wheel", "--outdir", str(destination)],
            environment=environment,
        )
        _run(
            repo_root,
            [sys.executable, "-m", "pip", "download", "--only-binary=:all:", "--dest", str(destination), *requirements],
        )
        metadata = {
            "schema_version": "1.1",
            "commit_sha": _git(repo_root, "rev-parse", "HEAD"),
            "tree_sha": _git(repo_root, "rev-parse", "HEAD^{tree}"),
            "workflow_run_id": run_id,
            "workflow_run_attempt": run_attempt,
            **default_environment(),
        }
        metadata["extra"] = ""
        metadata_path = destination / "CONTROL-METADATA.json"
        metadata_path.write_text(
            json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        admitted = sorted(destination.glob("*.whl")) + [metadata_path]
        (destination / "SHA256SUMS").write_text(
            "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                for path in admitted
            ),
            encoding="utf-8",
        )
        wheel, _ = verify_controller_inventory(destination.resolve())
        _verify_offline_install(repo_root, destination, wheel)
        return metadata
    finally:
        if temporary is not None:
            temporary.cleanup()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(build(args.repo_root, args.output, run_id=args.run_id, run_attempt=args.run_attempt), sort_keys=True))


if __name__ == "__main__":
    main()

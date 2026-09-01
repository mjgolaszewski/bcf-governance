"""Run closed, offline wheel and sdist verification on a disposable worker."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import tempfile
from typing import Any, Iterable

from .ci_github_bundle import write_exclusive
from .ci_github_identity import GitHubControllerError
from .release_closure import verify_archive, verify_wheelhouse


EXPECTED_PYTHON = "3.12.14"
EXPECTED_PLATFORM = "linux_x86_64"
_SAFE_HOST_ENVIRONMENT = ("LANG", "LC_ALL", "TMPDIR")
_PORTABLE_TEST_ENVIRONMENT = "BCF_RELEASE_SDIST_PORTABLE_TEST"


def is_release_sdist_test_context(repo_root: Path) -> bool:
    """Recognize only the synthetic Git custody created for an extracted sdist."""

    marker = os.environ.get(_PORTABLE_TEST_ENVIRONMENT)
    if marker is None:
        return False
    if marker != "1":
        raise GitHubControllerError("release sdist test-context marker is invalid")
    root = repo_root.resolve()
    package_metadata = root / "PKG-INFO"
    if package_metadata.is_symlink() or not package_metadata.is_file():
        raise GitHubControllerError("release sdist test context lacks package metadata")
    checks = (
        (["git", "rev-list", "--count", "HEAD"], b"1"),
        (["git", "log", "-1", "--format=%s"], b"exact sdist"),
        (["git", "show", "HEAD:PKG-INFO"], package_metadata.read_bytes().rstrip(b"\n")),
    )
    for argv, expected in checks:
        result = subprocess.run(argv, cwd=root, capture_output=True, check=False)
        if result.returncode or result.stdout.rstrip(b"\n") != expected:
            raise GitHubControllerError("release sdist test context lacks exact custody")
    return True


def runtime_environment(*, home: Path) -> dict[str, str]:
    """Return the closed environment inherited by candidate package processes."""

    environment = {
        "HOME": str(home.resolve()),
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONNOUSERSITE": "1",
    }
    environment.update(
        {name: os.environ[name] for name in _SAFE_HOST_ENVIRONMENT if os.environ.get(name)}
    )
    return environment


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular(path: Path, label: str) -> Path:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_file():
        raise GitHubControllerError(f"{label} must be a regular file")
    return resolved


def _executable(path: Path, label: str) -> Path:
    lexical = Path(os.path.abspath(path))
    if not lexical.exists() or not lexical.resolve().is_file() or not os.access(lexical, os.X_OK):
        raise GitHubControllerError(f"{label} must be an executable file")
    return lexical


def _run(
    label: str,
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    output_dir: Path,
) -> dict[str, Any]:
    result = subprocess.run(
        argv, cwd=cwd, env=env, capture_output=True, text=False, check=False
    )
    stdout = output_dir / f"{label}.stdout"
    stderr = output_dir / f"{label}.stderr"
    stdout.write_bytes(result.stdout)
    stderr.write_bytes(result.stderr)
    if result.returncode:
        raise GitHubControllerError(
            f"release runtime command failed: {label} ({result.returncode})"
        )
    return {
        "label": label,
        "argv": argv,
        "exit_code": result.returncode,
        "stdout": stdout.name,
        "stderr": stderr.name,
    }


def _environment(
    selected_python: Path,
    root: Path,
    *,
    wheelhouse: Path,
    lock_path: Path,
    output_dir: Path,
    label: str,
) -> tuple[Path, dict[str, str], list[dict[str, Any]]]:
    commands: list[dict[str, Any]] = []
    host_environment = runtime_environment(home=root.parent)
    commands.append(
        _run(
            f"{label}-venv",
            [str(selected_python), "-m", "venv", str(root)],
            cwd=root.parent,
            env=host_environment,
            output_dir=output_dir,
        )
    )
    bindir = root / "bin"
    python = _executable(bindir / "python", f"{label} Python")
    env = dict(host_environment)
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
    env["VIRTUAL_ENV"] = str(root)
    commands.append(
        _run(
            f"{label}-closure-install",
            [
                str(python), "-m", "pip", "install", "--no-index",
                "--find-links", str(wheelhouse), "--require-hashes", "-r",
                str(lock_path),
            ],
            cwd=root.parent,
            env=env,
            output_dir=output_dir,
        )
    )
    return python, env, commands


def _extract_sdist(sdist: Path, destination: Path) -> Path:
    verify_archive(sdist)
    destination.mkdir(mode=0o700)
    with tarfile.open(sdist, "r:gz") as archive:
        archive.extractall(destination, filter="data")
    roots = [path for path in destination.iterdir() if path.is_dir()]
    if len(roots) != 1:
        raise GitHubControllerError("sdist must contain exactly one source root")
    return roots[0]


def _git_custody(source: Path, output_dir: Path) -> list[dict[str, Any]]:
    env = runtime_environment(home=output_dir)
    commands: list[dict[str, Any]] = []
    for label, argv in (
        ("sdist-git-init", ["git", "init", "--quiet"]),
        ("sdist-git-email", ["git", "config", "user.email", "release@example.invalid"]),
        ("sdist-git-name", ["git", "config", "user.name", "BCF Release Verifier"]),
        ("sdist-git-add", ["git", "add", "."]),
        ("sdist-git-commit", ["git", "commit", "--quiet", "-m", "exact sdist"]),
    ):
        commands.append(
            _run(label, argv, cwd=source, env=env, output_dir=output_dir)
        )
    return commands


def _evidence(output_dir: Path, excluded: Iterable[str] = ()) -> dict[str, str]:
    omitted = set(excluded)
    values = {
        path.name: _sha256(path)
        for path in output_dir.iterdir()
        if path.is_file() and not path.is_symlink() and path.name not in omitted
    }
    if not values:
        raise GitHubControllerError("release runtime evidence is empty")
    return dict(sorted(values.items()))


def run_release_runtime_verification(
    *,
    selected_python: Path,
    manifest_path: Path,
    lock_path: Path,
    wheelhouse: Path,
    wheel: Path,
    sdist: Path,
    output_dir: Path,
) -> dict[str, Any]:
    """Test exact release bytes with a hash-closed dependency set and no network."""

    selected = _executable(selected_python, "selected release Python")
    manifest = _regular(manifest_path, "wheelhouse manifest")
    lock = _regular(lock_path, "release lock")
    exact_wheel = _regular(wheel, "release wheel")
    exact_sdist = _regular(sdist, "release sdist")
    closure = verify_wheelhouse(manifest, lock, wheelhouse.resolve())
    identity = subprocess.run(
        [str(selected), "-c", "import platform;print(platform.python_version())"],
        capture_output=True,
        text=True,
        check=False,
    )
    machine = platform.machine().lower()
    observed_platform = "linux_x86_64" if machine in {"x86_64", "amd64"} else machine
    if identity.returncode or identity.stdout.strip() != EXPECTED_PYTHON or (
        observed_platform != EXPECTED_PLATFORM
    ):
        raise GitHubControllerError("release runtime interpreter or platform is not exact")
    if output_dir.exists() or output_dir.is_symlink():
        raise GitHubControllerError("release runtime output directory must be fresh")
    output_dir.mkdir(mode=0o700, parents=True)
    commands: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="bcf-release-verify-") as temporary:
        root = Path(temporary)
        wheel_python, wheel_env, created = _environment(
            selected, root / "wheel-env", wheelhouse=wheelhouse.resolve(),
            lock_path=lock, output_dir=output_dir, label="wheel",
        )
        commands.extend(created)
        commands.append(
            _run(
                "wheel-install",
                [str(wheel_python), "-m", "pip", "install", "--no-index", "--no-deps", str(exact_wheel)],
                cwd=root, env=wheel_env, output_dir=output_dir,
            )
        )
        commands.append(
            _run(
                "wheel-smoke",
                [str(wheel_python), "-m", "bcf_governance.cli", "--version"],
                cwd=root, env=wheel_env, output_dir=output_dir,
            )
        )
        commands.append(
            _run(
                "twine-check",
                [str(wheel_python), "-m", "twine", "check", "--strict", str(exact_wheel), str(exact_sdist)],
                cwd=root, env=wheel_env, output_dir=output_dir,
            )
        )
        source = _extract_sdist(exact_sdist, root / "source")
        commands.extend(_git_custody(source, output_dir))
        sdist_python, sdist_env, created = _environment(
            selected, root / "sdist-env", wheelhouse=wheelhouse.resolve(),
            lock_path=lock, output_dir=output_dir, label="sdist",
        )
        commands.extend(created)
        commands.append(
            _run(
                "sdist-install",
                [
                    str(sdist_python), "-m", "pip", "install", "--no-index",
                    "--no-deps", "--no-build-isolation", str(exact_sdist),
                ],
                cwd=root, env=sdist_env, output_dir=output_dir,
            )
        )
        sdist_env["BCF_RELEASE_SDIST_PORTABLE_TEST"] = "1"
        junit = output_dir / "sdist-tests.xml"
        commands.append(
            _run(
                "sdist-tests",
                [str(sdist_python), "-m", "pytest", "-q", "tests", f"--junitxml={junit}"],
                cwd=source, env=sdist_env, output_dir=output_dir,
            )
        )
    report_path = output_dir / "runtime-verification.json"
    payload = {
        "schema_version": "1.0",
        "status": "passed",
        "environment": {
            "python_executable": str(selected),
            "python_version": EXPECTED_PYTHON,
            "platform": EXPECTED_PLATFORM,
        },
        "dependency_closure": closure.as_dict(),
        "release_artifacts": {
            exact_wheel.name: _sha256(exact_wheel),
            exact_sdist.name: _sha256(exact_sdist),
        },
        "commands": commands,
        "evidence": _evidence(output_dir, {report_path.name}),
    }
    write_exclusive(report_path, payload)
    return payload


def verify_runtime_evidence(
    report_path: Path,
    evidence_paths: Iterable[Path],
    *,
    wheel: Path,
    sdist: Path,
) -> dict[str, Any]:
    """Recompute the runtime report's exact raw-evidence and artifact bindings."""

    try:
        report = json.loads(_regular(report_path, "runtime report").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise GitHubControllerError("release runtime report is invalid") from exc
    if not isinstance(report, dict) or report.get("schema_version") != "1.0" or (
        report.get("status") != "passed"
    ):
        raise GitHubControllerError("release runtime report did not pass")
    environment = report.get("environment")
    if not isinstance(environment, dict) or (
        environment.get("python_version") != EXPECTED_PYTHON
        or environment.get("platform") != EXPECTED_PLATFORM
    ):
        raise GitHubControllerError("release runtime report environment is not exact")
    expected_artifacts = {
        wheel.name: _sha256(wheel),
        sdist.name: _sha256(sdist),
    }
    if report.get("release_artifacts") != expected_artifacts:
        raise GitHubControllerError("release runtime report does not bind release bytes")
    paths = tuple(evidence_paths)
    actual = {path.name: _sha256(_regular(path, "runtime evidence")) for path in paths}
    if len(actual) != len(paths) or report.get("evidence") != dict(sorted(actual.items())):
        raise GitHubControllerError("release runtime evidence inventory is not exact")
    return report


def runtime_evidence_paths(report_path: Path, evidence_dir: Path) -> tuple[Path, ...]:
    """Select exactly the report-owned raw evidence from one safe directory."""

    root = evidence_dir.resolve()
    if evidence_dir.is_symlink() or not root.is_dir():
        raise GitHubControllerError("release runtime evidence directory is unsafe")
    try:
        report = json.loads(_regular(report_path, "runtime report").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise GitHubControllerError("release runtime report is invalid") from exc
    declared = report.get("evidence") if isinstance(report, dict) else None
    if not isinstance(declared, dict) or not declared:
        raise GitHubControllerError("release runtime evidence inventory is missing")
    names = tuple(sorted(str(name) for name in declared))
    if any(
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", name)
        or Path(name).name != name
        for name in names
    ):
        raise GitHubControllerError("release runtime evidence name is unsafe")
    paths = tuple(root / name for name in names)
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise GitHubControllerError("release runtime evidence member is missing or unsafe")
    actual = {
        path.name
        for path in root.iterdir()
        if path.name != report_path.name
    }
    if actual != set(names) or any(
        path.is_symlink() or not path.is_file()
        for path in root.iterdir()
        if path.name != report_path.name
    ):
        raise GitHubControllerError("release runtime evidence directory is not exact")
    return paths

"""Select one authenticated Python runtime for project environment materialization."""

from __future__ import annotations

import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


class PythonRuntimeSelectionError(ValueError):
    """Raised when no exact runtime satisfies the authenticated contract."""


def interpreter_subprocess_environment(python: Path) -> dict[str, str]:
    """Remove controller-only Python custody from project interpreter work."""

    environment = dict(os.environ)
    for name in ("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"):
        environment.pop(name, None)
    bin_directory = python.absolute().parent
    environment["PATH"] = str(bin_directory) + (
        os.pathsep + environment["PATH"] if environment.get("PATH") else ""
    )
    prefix = bin_directory.parent
    if bin_directory.name == "bin" and (prefix / "pyvenv.cfg").is_file():
        environment["VIRTUAL_ENV"] = str(prefix)
    return environment


def _python_runtime_version(python: Path) -> Version:
    """Authenticate one executable's Python version without ambient imports."""

    try:
        executable = python.resolve(strict=True)
    except OSError as exc:
        raise PythonRuntimeSelectionError(
            "project interpreter base runtime is unavailable"
        ) from exc
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise PythonRuntimeSelectionError(
            "project interpreter base runtime is unavailable"
        )
    if executable == Path(sys.executable).resolve(strict=True):
        raw = platform.python_version()
    else:
        try:
            result = subprocess.run(
                [
                    str(executable),
                    "-I",
                    "-c",
                    "import platform;print(platform.python_version())",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env=interpreter_subprocess_environment(executable),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PythonRuntimeSelectionError(
                "project interpreter base runtime probe failed"
            ) from exc
        if result.returncode:
            raise PythonRuntimeSelectionError(
                "project interpreter base runtime probe failed"
            )
        raw = result.stdout.strip()
    try:
        version = Version(raw)
    except InvalidVersion as exc:
        raise PythonRuntimeSelectionError(
            "project interpreter base runtime version is invalid"
        ) from exc
    if len(version.release) < 2:
        raise PythonRuntimeSelectionError(
            "project interpreter base runtime version is invalid"
        )
    return version


def select_materialization_base(
    requires_python: str | None, controller_python: Path
) -> Path:
    """Derive the base runtime solely from the authenticated Python contract."""

    if requires_python is None:
        raise PythonRuntimeSelectionError(
            "project interpreter cannot be materialized without an authenticated Python runtime source"
        )
    try:
        required = SpecifierSet(requires_python)
    except InvalidSpecifier as exc:
        raise PythonRuntimeSelectionError(
            "authenticated Python runtime contract is invalid"
        ) from exc
    try:
        controller = controller_python.resolve(strict=True)
    except OSError as exc:
        raise PythonRuntimeSelectionError(
            "project interpreter base runtime is unavailable"
        ) from exc
    if required.contains(_python_runtime_version(controller), prereleases=True):
        return controller
    exact_minor = re.fullmatch(r"==([0-9]+\.[0-9]+)\.\*", requires_python)
    if exact_minor is None:
        raise PythonRuntimeSelectionError(
            "controller Python is incompatible and the runtime contract does not declare one exact fallback minor"
        )
    selected_raw = shutil.which(f"python{exact_minor.group(1)}")
    if selected_raw is None:
        raise PythonRuntimeSelectionError(
            f"authenticated project Python {exact_minor.group(1)} is unavailable"
        )
    try:
        selected = Path(selected_raw).resolve(strict=True)
    except OSError as exc:
        raise PythonRuntimeSelectionError(
            f"authenticated project Python {exact_minor.group(1)} is unavailable"
        ) from exc
    observed = _python_runtime_version(selected)
    observed_minor = ".".join(str(value) for value in observed.release[:2])
    if observed_minor != exact_minor.group(1) or not required.contains(
        observed, prereleases=True
    ):
        raise PythonRuntimeSelectionError(
            "versioned project Python does not match the authenticated runtime contract"
        )
    return selected

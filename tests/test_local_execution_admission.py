from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import sys

import pytest

from bcf_governance.tooling.local_execution_admission import (
    LocalExecutionAdmissionError,
    local_gate_lease,
    project_python_environment,
    resolve_local_project_python,
)


def test_competing_local_gate_fails_busy_before_work() -> None:
    first = "a" * 40
    second = "b" * 40
    with ExitStack() as stack:
        stack.enter_context(local_gate_lease(first))
        with pytest.raises(LocalExecutionAdmissionError, match="busy_deferred"):
            stack.enter_context(local_gate_lease(second))


def test_local_gate_requires_exact_execution_identity() -> None:
    with pytest.raises(LocalExecutionAdmissionError, match="identity"):
        with local_gate_lease("branch-name"):
            pass


def test_project_python_is_distinct_from_controller_python(tmp_path: Path) -> None:
    project = tmp_path / ".venv/bin/python"
    project.parent.mkdir(parents=True)
    project.write_text("#!/bin/sh\n", encoding="utf-8")
    project.chmod(0o755)

    assert resolve_local_project_python(tmp_path, Path(sys.executable)) == project


def test_broken_repository_project_python_never_falls_back(tmp_path: Path) -> None:
    project = tmp_path / ".venv/bin/python"
    project.parent.mkdir(parents=True)
    project.symlink_to("missing-python")

    with pytest.raises(LocalExecutionAdmissionError, match="unavailable"):
        resolve_local_project_python(tmp_path, Path(sys.executable))


def test_project_python_environment_removes_controller_paths(tmp_path: Path) -> None:
    project = tmp_path / ".venv/bin/python"
    environment = project_python_environment(
        tmp_path,
        project,
        {
            "PATH": "/controller/bin:/usr/bin",
            "PYTHONPATH": "/controller/source",
            "PYTHONHOME": "/controller/home",
            "VIRTUAL_ENV": "/controller/.venv",
            "KEPT": "exact",
        },
    )

    assert environment == {
        "PATH": f"{project.parent}:/controller/bin:/usr/bin",
        "VIRTUAL_ENV": str(tmp_path / ".venv"),
        "KEPT": "exact",
    }

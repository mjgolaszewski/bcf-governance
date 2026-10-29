"""Missing or unsupported ownership refuses before an actual project probe."""
from __future__ import annotations

import multiprocessing
import os
import shlex
import shutil
import socket
import sys
import time
from collections.abc import Iterator
from dataclasses import replace
from multiprocessing.connection import Connection
from multiprocessing.process import BaseProcess
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest

from bcf_governance.tooling.evidence_execution import EvidenceError, _run_with_execution_state
from bcf_governance.tooling.evidence_execution_owner import (
    OwnerAdmissionError,
    OwnerRegistration,
    ProcessIdentity,
)
from bcf_governance.tooling.evidence_owner_registration import (
    InstalledOwnerBinding,
    OwnerInvocationRoute,
    RequiredOwnerScope,
    bind_installed_execution_owner,
)


@pytest.fixture
def job(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, Any]]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "governance").mkdir()
    shutil.copyfile(Path(__file__).resolve().parents[1] / "governance/ci-runtime.yml",
                    repo / "governance/ci-runtime.yml")
    marker = tmp_path / "project-interpreter-executed"
    interpreter = tmp_path / "project-python"
    interpreter.write_text("#!/bin/sh\nprintf probe > " + shlex.quote(str(marker)) + "\nprintf '3.12.12\\n'\n")
    interpreter.chmod(0o700)
    contract = {"target": "runtime-smoke", "execution_timeout_seconds": 30,
                "invocation": {"argv": ["python3", "probe.py"], "cwd": ".",
                               "env": {"BCF_EXECUTION_PROFILE": "production"}, "required_env": []}}
    return repo, interpreter, marker, contract


def run_job(job: tuple[Path, Path, Path, dict[str, Any]], *, state: bool,
            required: bool = False, execution_id: str = "positive") -> None:
    repo, interpreter, _marker, contract = job
    result, _env, _metadata, report = _run_with_execution_state(repo, repo, contract,
        [sys.executable, "-I", "-S", "-c", "print('ordinary')"], interpreter,
        session_id="owner-admission-source-control", execution_id=execution_id,
        require_state=state, require_execution_owner=required)
    assert result.returncode == 0 and result.stdout == "ordinary\n"
    assert report is None if not state else report is not None and report["retired"] is True


@pytest.mark.parametrize("state", [False, True], ids=["stateless", "stateful"])
def test_missing_required_owner_refuses_before_real_project_probe(job: tuple[Path, Path, Path, dict[str, Any]], state: bool) -> None:
    repo, _python, marker, _contract = job
    with pytest.raises(EvidenceError, match="owner is unconfigured"):
        run_job(job, state=state, required=True)
    assert not marker.exists()
    assert not (repo / ".artifacts/runtime").exists()


@pytest.mark.parametrize("state", [False, True], ids=["stateless", "stateful"])
def test_ordinary_route_still_executes_the_same_real_project_probe(job: tuple[Path, Path, Path, dict[str, Any]], state: bool) -> None:
    run_job(job, state=state)
    assert job[2].read_text() == "probe"


def idle_owner(path: str, ready: Connection) -> None:
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(path)
        os.chmod(path, 0o600)
        listener.listen(1)
        ready.send(os.getpid())
        with listener.accept()[0] as connection:
            connection.recv(1)


@pytest.fixture
def installed(job: tuple[Path, Path, Path, dict[str, Any]]) -> Iterator[InstalledOwnerBinding]:
    children: list[BaseProcess] = []
    registrations = []
    with TemporaryDirectory(prefix="bcf239-owner-", dir="/tmp") as directory:
        try:
            for role in ("issuer", "custody"):
                endpoint = Path(directory) / (role + ".sock")
                parent, child = multiprocessing.Pipe(False)
                process = multiprocessing.Process(target=idle_owner, args=(str(endpoint), child))
                process.start()
                children.append(process)
                try:
                    assert parent.poll(5)
                    pid = parent.recv()
                finally:
                    parent.close()
                    child.close()
                registrations.append(OwnerRegistration(endpoint, ProcessIdentity.observe(pid)))
            scope = RequiredOwnerScope(job[0], frozenset({"runtime-smoke"}),
                                       frozenset({"production"}), frozenset({"positive"}),
                                       (OwnerInvocationRoute("runtime-smoke", "production", "positive"),) * 4)
            yield InstalledOwnerBinding(ProcessIdentity.observe(os.getpid()), scope,
                registrations[0], registrations[1], time.monotonic() + 30, 4, 5)
        finally:
            for child_process in children:
                if child_process.is_alive():
                    child_process.terminate()
                child_process.join(5)
                assert not child_process.is_alive()


@pytest.mark.parametrize("state", [False, True], ids=["stateless", "stateful"])
def test_installed_scope_cannot_fall_back_through_optional_requirement_bit(job: tuple[Path, Path, Path, dict[str, Any]], installed: InstalledOwnerBinding, state: bool) -> None:
    job[3]["invocation"]["requires_execution_owner"] = False
    with bind_installed_execution_owner(installed):
        with pytest.raises(EvidenceError, match="backend is not installed"):
            run_job(job, state=state, required=False)
    assert not job[2].exists()
    assert not (job[0] / ".artifacts/runtime").exists()


@pytest.mark.parametrize("change", ["repository", "producer", "profile", "control"])
def test_unadmitted_identity_cannot_select_legacy_execution(job: tuple[Path, Path, Path, dict[str, Any]], installed: InstalledOwnerBinding, change: str) -> None:
    original_repo, interpreter, marker, contract = job
    modified = dict(contract)
    execution_id = "positive"
    repo = original_repo
    if change == "repository":
        repo = original_repo.parent / "other"
        repo.mkdir()
    elif change == "producer":
        modified["target"] = "renamed-unadmitted-producer"
    elif change == "profile":
        modified["invocation"] = {**contract["invocation"], "env": {"BCF_EXECUTION_PROFILE": "other"}}
    else:
        execution_id = "negative-control:unadmitted"
    expected = "outside installed owner scope" if change in {"repository", "producer"} else "profile or control"
    with bind_installed_execution_owner(installed):
        with pytest.raises(EvidenceError, match=expected):
            run_job((repo, interpreter, marker, modified), state=False, execution_id=execution_id)
    assert not marker.exists()


@pytest.mark.parametrize("version", [True, 2], ids=["boolean", "unsupported"])
def test_registration_api_version_is_not_caller_coercible(installed: InstalledOwnerBinding, version: int) -> None:
    with pytest.raises(OwnerAdmissionError, match="API version"):
        with bind_installed_execution_owner(replace(installed, api_version=version)):
            raise AssertionError("unsupported owner registration was installed")


@pytest.mark.parametrize("state", [False, True], ids=["stateless", "stateful"])
def test_contract_requirement_reaches_native_entry_before_real_probe(job: tuple[Path, Path, Path, dict[str, Any]], state: bool) -> None:
    job[3]["invocation"]["requires_execution_owner"] = True
    with pytest.raises(EvidenceError, match="owner is unconfigured"):
        run_job(job, state=state, required=False)
    assert not job[2].exists()
    assert not (job[0] / ".artifacts/runtime").exists()


@pytest.mark.parametrize("value", [None, 1, "true", {"endpoint": "candidate-selected"}], ids=["null", "integer", "string", "endpoint"])
def test_requirement_cannot_nominate_an_owner_or_coerce_its_type(job: tuple[Path, Path, Path, dict[str, Any]], value: Any) -> None:
    job[3]["invocation"]["requires_execution_owner"] = value
    with pytest.raises(EvidenceError, match="requirement must be a boolean"):
        run_job(job, state=False)
    assert not job[2].exists()


def test_cartesian_route_refuses_before_project_probe(job: tuple[Path, Path, Path, dict[str, Any]], installed: InstalledOwnerBinding) -> None:
    routes = (OwnerInvocationRoute("runtime-smoke", "production", "positive"),
              OwnerInvocationRoute("runtime-revoke", "revoke-profile", "negative-control"))
    scope = replace(installed.scope, producers=frozenset(r.producer for r in routes),
                    profiles=frozenset(r.profile for r in routes),
                    controls=frozenset(r.control for r in routes), allocation=routes)
    binding = replace(installed, scope=scope, maximum_invocations=2)
    contract = {**job[3], "invocation": {**job[3]["invocation"],
                "env": {"BCF_EXECUTION_PROFILE": "revoke-profile"}}}
    with bind_installed_execution_owner(binding):
        with pytest.raises(EvidenceError, match="next exact allocation ordinal"):
            run_job((job[0], job[1], job[2], contract), state=False)
    assert not job[2].exists()
    assert not (job[0] / ".artifacts/runtime").exists()

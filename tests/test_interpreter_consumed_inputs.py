"""Causal source movement controls with simulated environment commands only."""
import fcntl
from pathlib import Path
import subprocess
import sys
from typing import BinaryIO

import pytest
import yaml

from bcf_governance.tooling import interpreter_environment as owner
from bcf_governance.tooling.runtime_capacity import EXECUTION_STATE_POLICY


def _fixture(root: Path) -> Path:
    (root / "governance").mkdir()
    (root / "governance/gate-contracts.yml").write_text(
        "interpreter_contract: {project_dependencies: true, optional_dependency_groups: [], "
        "gate_requirements: {}, requirements_projection: requirements-governance.txt}\ngates: {}\n"
    )
    (root / "pyproject.toml").write_text(
        "[project]\nname='fixture'\nversion='1.0'\nrequires-python='>=3.12'\n"
        "dependencies=['PyYAML>=6,<7', 'pip>=26.2.2,<27']\n"
    )
    (root / "governance/ci-runtime.yml").write_text(yaml.safe_dump({
        "schema_version": "1.1", "runtime_root": ".artifacts/runtime",
        "minimum_free_bytes": 1, "maximum_owned_containers": 1,
        "database": {"storage": "repository_bind_mount", "relative_path": ".artifacts/runtime/database"},
        "cleanup": {"caller_globs": False, "daemon_global_prune": False,
                    "exact_owner_revalidation": True, "remove_anonymous_volumes": True},
        "execution_state": EXECUTION_STATE_POLICY,
    }))
    plan = owner.derive_interpreter_environment(root)
    assert plan is not None
    return owner.apply_interpreter_environment_projection(plan)


def _venv(argv: list[str]) -> None:
    root = Path(argv[-1])
    (root / "bin").mkdir(parents=True)
    (root / "bin/python").symlink_to(sys.executable)
    (root / "pyvenv.cfg").write_text("home = fixture\n")


@pytest.mark.parametrize("moving", ["projection", "metadata", "registry"])
def test_source_movement_during_setup_blocks_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, moving: str,
) -> None:
    projection = _fixture(tmp_path)
    source = {"projection": projection, "metadata": tmp_path / "pyproject.toml",
              "registry": tmp_path / "governance/gate-contracts.yml"}[moving]
    monkeypatch.setattr(owner, "select_materialization_base", lambda *_: Path(sys.executable))

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[1:3] == ["-m", "venv"]:
            _venv(argv)
            source.write_text(source.read_text() + "\n# source moved\n")
            return subprocess.CompletedProcess(argv, 0, "", "")
        pytest.fail("moving source reached dependency installation")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(owner.InterpreterEnvironmentError, match="changed after derivation|projection drift"):
        owner.materialize_interpreter_environment(tmp_path, Path(sys.executable))
    assert not list(tmp_path.rglob("*.building-*"))


def test_pip_consumes_closed_tuple_when_projection_moves_at_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection = _fixture(tmp_path)
    plan = owner.derive_interpreter_environment(tmp_path)
    assert plan is not None
    seen: list[tuple[str, ...]] = []
    monkeypatch.setattr(owner, "select_materialization_base", lambda *_: Path(sys.executable))
    monkeypatch.setattr(owner, "_installed_inventory", lambda *_: "pip==26.2.2\nPyYAML==6.0.3\n")

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[1:3] == ["-m", "venv"]:
            _venv(argv)
        elif argv[1:4] == ["-m", "pip", "install"]:
            projection.write_text("unbound-dependency==99\n")
            seen.append(tuple(argv[argv.index("--disable-pip-version-check") + 1:]))
            assert seen[-1] == plan.requirements
        else:
            pytest.fail("unexpected simulated command")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(owner.InterpreterEnvironmentError, match="projection drift"):
        owner.materialize_interpreter_environment(tmp_path, Path(sys.executable))
    assert seen == [plan.requirements]
    assert not list(tmp_path.rglob("environment.json"))
    assert not list(tmp_path.rglob("*.building-*"))


def test_source_movement_at_lock_blocks_cache_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fixture(tmp_path)
    metadata = tmp_path / "pyproject.toml"
    original = fcntl.flock
    moved: list[Path] = []

    def flock(lock: int | BinaryIO, operation: int) -> None:
        path = Path("/proc/self/fd", str(lock)).readlink() if isinstance(lock, int) else Path(lock.name)
        original(lock, operation)
        if path.name == ".materialize.lock" and path.is_relative_to(tmp_path) and operation == fcntl.LOCK_EX:
            metadata.write_text(metadata.read_text() + "\n# moved at lock\n")
            moved.append(metadata)

    def forbidden(*args: object, **kwargs: object) -> None:
        assert moved, "causal lock-source injection did not occur"
        pytest.fail("source movement reached cache lookup or native work")

    monkeypatch.setattr(owner, "select_materialization_base", lambda *_: Path(sys.executable))
    monkeypatch.setattr(fcntl, "flock", flock)
    monkeypatch.setattr(owner, "_matching_cached_environment", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    with pytest.raises(owner.InterpreterEnvironmentError, match="changed after derivation"):
        owner.materialize_interpreter_environment(tmp_path, Path(sys.executable))
    assert moved == [metadata]


def test_cached_inventory_source_movement_blocks_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fixture(tmp_path)
    metadata = tmp_path / "pyproject.toml"
    calls: list[list[str]] = []
    inventories = 0
    monkeypatch.setattr(owner, "select_materialization_base", lambda *_: Path(sys.executable))

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[1:3] == ["-m", "venv"]:
            _venv(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    def inventory(*args: object) -> str:
        nonlocal inventories
        inventories += 1
        if inventories == 2:
            metadata.write_text(metadata.read_text() + "\n# moved during inventory\n")
        return "pip==26.2.2\nPyYAML==6.0.3\n"

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(owner, "_installed_inventory", inventory)
    first = owner.materialize_interpreter_environment(tmp_path, Path(sys.executable))
    original_calls = len(calls)
    with pytest.raises(owner.InterpreterEnvironmentError, match="changed after derivation"):
        owner.materialize_interpreter_environment(tmp_path, Path(sys.executable))
    assert inventories == 2
    assert len(calls) == original_calls
    assert first.is_file()


@pytest.mark.parametrize("boundary", ["post-pip", "post-inventory"])
def test_late_metadata_movement_blocks_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str,
) -> None:
    _fixture(tmp_path)
    metadata = tmp_path / "pyproject.toml"
    reached: list[str] = []
    monkeypatch.setattr(owner, "select_materialization_base", lambda *_: Path(sys.executable))

    def move() -> None:
        metadata.write_text(metadata.read_text() + "\n# late source movement\n")
        reached.append(boundary)

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[1:3] == ["-m", "venv"]:
            _venv(argv)
        elif argv[1:4] == ["-m", "pip", "install"]:
            if boundary == "post-pip":
                move()
        else:
            pytest.fail("unexpected simulated command")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def inventory(*args: object) -> str:
        if boundary == "post-inventory":
            move()
        return "pip==26.2.2\nPyYAML==6.0.3\n"

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(owner, "_installed_inventory", inventory)
    with pytest.raises(owner.InterpreterEnvironmentError, match="changed after derivation"):
        owner.materialize_interpreter_environment(tmp_path, Path(sys.executable))
    assert reached == [boundary]
    assert not list(tmp_path.rglob("environment.json"))
    assert not list(tmp_path.rglob("*.building-*"))

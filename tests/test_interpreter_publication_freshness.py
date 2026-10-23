"""Source freshness remains necessary at installation and publication consumers."""
from pathlib import Path
import subprocess
import sys

import pytest

from bcf_governance.tooling import interpreter_environment as owner
from tests.test_interpreter_environment import _fixture, _simulate_owned_venv


@pytest.mark.parametrize("boundary", ["post-pip", "post-inventory"])
@pytest.mark.parametrize("moving", ["metadata", "projection", "registry"])
def test_changed_source_never_reaches_environment_publication(tmp_path, monkeypatch, boundary, moving):
    _fixture(tmp_path)
    plan = owner.derive_interpreter_environment(tmp_path)
    assert plan is not None
    projection = owner.apply_interpreter_environment_projection(plan)
    source = {"metadata": tmp_path / "pyproject.toml", "projection": projection,
              "registry": tmp_path / "governance/gate-contracts.yml"}[moving]
    reached = []
    inventory_calls = []
    monkeypatch.setattr(owner, "select_materialization_base", lambda *_: Path(sys.executable))

    def move():
        source.write_text(source.read_text() + "\n# changed at consuming boundary\n")
        reached.append(boundary)

    def run(argv, **kwargs):
        if argv[1:3] == ["-m", "venv"]:
            _simulate_owned_venv(argv)
        elif argv[1:4] == ["-m", "pip", "install"]:
            if boundary == "post-pip":
                move()
        else:
            pytest.fail("unexpected command in source-freshness control")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def inventory(*args):
        inventory_calls.append(True)
        if boundary == "post-inventory":
            move()
        return "PyYAML==6.0.3\n"

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(owner, "_installed_inventory", inventory)
    try:
        published = owner.materialize_interpreter_environment(tmp_path, Path(sys.executable))
    except owner.InterpreterEnvironmentError as exc:
        assert "changed after derivation" in str(exc) or "projection drift" in str(exc)
    else:
        assert reached == [boundary]
        assert published.is_file()
        assert list(tmp_path.rglob("environment.json"))
        pytest.fail("changed source reached environment publication")
    assert reached == [boundary]
    assert len(inventory_calls) == (0 if boundary == "post-pip" else 1)
    assert not list(tmp_path.rglob("environment.json"))
    assert not list(tmp_path.rglob("*.building-*"))

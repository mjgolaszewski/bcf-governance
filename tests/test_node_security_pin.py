"""Current approved patch pin and causal stale-runtime refusal."""
import importlib.util
from pathlib import Path
import subprocess
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("security_bootstrap", ROOT / ".github/scripts/bootstrap_test_toolchain.py")
assert SPEC is not None and SPEC.loader is not None
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)


def test_bootstrap_uses_approved_security_patch():
    assert BOOTSTRAP.NODE_VERSION == "v22.23.5"


def test_graph_uses_same_approved_security_patch():
    graph = yaml.safe_load((ROOT / "governance/ci-graph.yml").read_text())
    assert graph["step_components"]["setup-test-node"]["with"]["node-version"] == "22.23.5"


def test_old_patch_is_refused_before_toolchain_install(tmp_path, monkeypatch):
    executable = tmp_path / "bin/node"
    executable.parent.mkdir()
    executable.write_bytes(b"old runtime fixture")
    monkeypatch.setattr(BOOTSTRAP.shutil, "which", lambda _name: str(executable))
    monkeypatch.setattr(BOOTSTRAP.subprocess, "run", lambda command, **_kwargs:
                        subprocess.CompletedProcess(command, 0, stdout="v22.23.2\n", stderr=""))
    with pytest.raises(ValueError, match="requires Node v22.23.5"):
        BOOTSTRAP._node_executable()
    assert not (tmp_path / "node_modules").exists()

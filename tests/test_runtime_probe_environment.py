"""The first selected interpreter child must share the closed process policy."""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from bcf_governance.tooling import release_runtime_verification as owner
from test_native_abi_admission import ReachedAllocation, inputs


EXCLUDED = (
    "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "AWS_SECRET_ACCESS_KEY",
    "SSH_AUTH_SOCK", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD",
    "LD_LIBRARY_PATH", "NODE_OPTIONS", "BCF_RELEASE_SDIST_PORTABLE_TEST",
)


def selected_probe(tmp_path):
    capture = tmp_path / "child-environment.json"
    selected = tmp_path / "selected-python"
    # -I on the shebang keeps the observation fixture executable even before
    # production isolation when a control supplies invalid PYTHONHOME/PYTHONPATH.
    selected.write_text(
        "#!" + sys.executable + " -I\nimport json,os,sys\n"
        + "with open(" + repr(str(capture)) + ",'w') as stream:"
        + "json.dump({'env':dict(os.environ),'cwd':os.getcwd()},stream)\n"
        + "exec(compile(sys.argv[-1],'<actual-selected-probe>','exec'))\n"
    )
    selected.chmod(0o700)
    return selected, capture


def subject(arguments, monkeypatch, version):
    # Admission-only fixture: the existing real archive checks still execute.
    # These controls do not establish manifest authenticity or release custody.
    monkeypatch.setattr(owner, "verify_wheelhouse", lambda *_: SimpleNamespace(
        manifest_schema_version=version,
        python=".".join(str(value) for value in sys.version_info[:3]),
        platform="linux_x86_64",
    ))
    return arguments


@pytest.mark.parametrize("version", ["1.0", "1.1"])
@pytest.mark.parametrize("variable", EXCLUDED)
def test_probe_excludes_ambient_configuration_before_native_execution(tmp_path, monkeypatch, version, variable):
    arguments = subject(inputs(tmp_path, monkeypatch), monkeypatch, version)
    selected, capture = selected_probe(tmp_path)
    monkeypatch.setenv(variable, str(tmp_path / "must-not-inherit"))
    with pytest.raises(ReachedAllocation):
        owner.run_release_runtime_verification(selected_python=selected, **arguments)
    observed = json.loads(capture.read_text())
    assert variable not in observed["env"], "selected interpreter inherited excluded configuration"
    expected = owner.runtime_environment(home=arguments["manifest_path"].parent)
    assert observed["env"] == expected
    assert observed["cwd"] == str(arguments["manifest_path"].parent.resolve())


@pytest.mark.parametrize("version", ["1.0", "1.1"])
def test_probe_closed_environment_precedes_output_and_environment_allocation(tmp_path, monkeypatch, version):
    arguments = subject(inputs(tmp_path, monkeypatch), monkeypatch, version)
    actual = owner.subprocess.run
    seen = []

    def inspect(argv, **kwargs):
        assert not arguments["output_dir"].exists()
        assert argv[1:4] == ["-I", "-B", "-c"]
        parent = arguments["manifest_path"].parent
        assert kwargs.get("env") == owner.runtime_environment(home=parent)
        assert kwargs.get("cwd") == parent
        seen.append(argv)
        return actual(argv, **kwargs)

    monkeypatch.setattr(owner.subprocess, "run", inspect)
    with pytest.raises(ReachedAllocation):
        owner.run_release_runtime_verification(selected_python=Path(sys.executable), **arguments)
    assert len(seen) == 1
    assert arguments["output_dir"].is_dir()

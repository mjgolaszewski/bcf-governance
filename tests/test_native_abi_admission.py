"""Exact runtime version and architecture spelling cannot substitute for ABI."""
from pathlib import Path
import sys

import pytest

from bcf_governance.tooling import release_runtime_verification as owner
from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from test_release_runtime_subject_migration import manifest
from test_release_runtime_verification import _fixture


class ReachedAllocation(Exception):
    pass


def inputs(tmp_path, monkeypatch):
    root = tmp_path/"inputs"
    root.mkdir()
    version = ".".join(str(value) for value in sys.version_info[:3])
    abi = "cp" + "".join(str(value) for value in sys.version_info[:2])
    path, lock, wheels = manifest(root,version,abi)
    archives = tmp_path/"archives"
    archives.mkdir()
    _, _, wheel, sdist = _fixture(archives)

    def reached(*args):
        raise ReachedAllocation("native admission reached source allocation")

    monkeypatch.setattr(owner,"_extract_sdist",reached)
    return dict(manifest_path=path,lock_path=lock,wheelhouse=wheels,wheel=wheel,
        sdist=sdist,output_dir=tmp_path/"verification")


def executable(tmp_path, change):
    # A real child executes the producer's actual probe. Only fixture ABI facts
    # change, leaving its version/platform checks and code path intact.
    prelude = "import sys,sysconfig,struct\n"
    config = change.get("config",{})
    prelude += "saved_config=sysconfig.get_config_var\nsaved_config('SOABI')\nconfig=" + repr(config) + "\n"
    prelude += "sysconfig.get_config_var=lambda name:config[name] if name in config else saved_config(name)\n"
    if "flags" in change:
        prelude += "sys.abiflags=" + repr(change["flags"]) + "\n"
    if "cache" in change:
        prelude += "sys.implementation.cache_tag=" + repr(change["cache"]) + "\n"
    if "bits" in change:
        prelude += "saved_size=struct.calcsize\nstruct.calcsize=lambda name:" + repr(change["bits"]) + "//8 if name=='P' else saved_size(name)\n"
    prelude += "exec(compile(sys.argv[-1],'<actual-native-probe>','exec'))\n"
    path = tmp_path/"selected-python"
    path.write_text("#!" + sys.executable + "\n" + prelude)
    path.chmod(0o700)
    return path


CASES = {
    "free-threaded-flag":{"flags":"t"},
    "free-threaded-config":{"config":{"Py_GIL_DISABLED":1}},
    "contradictory-gil-bool":{"config":{"Py_GIL_DISABLED":False}},
    "contradictory-gil-string":{"config":{"Py_GIL_DISABLED":"0"}},
    "debug-flag":{"flags":"d"},
    "debug-config":{"config":{"Py_DEBUG":1}},
    "debug-bool":{"config":{"Py_DEBUG":False}},
    "debug-float":{"config":{"Py_DEBUG":0.0}},
    "cross-minor-soabi":{"config":{"SOABI":"cpython-310-x86_64-linux-gnu"}},
    "missing-soabi":{"config":{"SOABI":None}},
    "musl-soabi":{"config":{"SOABI":"cpython-312-x86_64-linux-musl"}},
    "wrong-extension-suffix":{"config":{"EXT_SUFFIX":".foreign.so"}},
    "missing-extension-suffix":{"config":{"EXT_SUFFIX":None}},
    "foreign-multiarch":{"config":{"MULTIARCH":"aarch64-linux-gnu"}},
    "missing-multiarch":{"config":{"MULTIARCH":None}},
    "cross-minor-cache":{"cache":"cpython-310"},
    "missing-cache":{"cache":None},
    "x32-pointer":{"bits":32},
    "pointer-float":{"bits":64.0},
}


def capture_probe(monkeypatch):
    original = owner.subprocess.run
    results = []

    def record(*args, **kwargs):
        result = original(*args, **kwargs)
        results.append(result)
        return result

    monkeypatch.setattr(owner.subprocess,"run",record)
    return results


@pytest.mark.parametrize("case", CASES)
def test_incompatible_native_abi_stops_before_output_allocation(tmp_path, monkeypatch, case):
    arguments = inputs(tmp_path,monkeypatch)
    selected = executable(tmp_path,CASES[case])
    results = capture_probe(monkeypatch)
    with pytest.raises(GitHubControllerError,match="interpreter or platform"):
        owner.run_release_runtime_verification(selected_python=selected,**arguments)
    assert len(results) == 1 and results[0].returncode == 0, results
    assert not arguments["output_dir"].exists()


def test_actual_standard_native_runtime_reaches_next_boundary(tmp_path, monkeypatch):
    arguments = inputs(tmp_path,monkeypatch)
    with pytest.raises(ReachedAllocation):
        owner.run_release_runtime_verification(selected_python=Path(sys.executable),**arguments)
    assert arguments["output_dir"].is_dir()


@pytest.mark.parametrize("value", [None,0])
def test_absent_or_integer_zero_gil_config_preserves_standard_profile(tmp_path, monkeypatch, value):
    arguments = inputs(tmp_path,monkeypatch)
    selected = executable(tmp_path,{"config":{"Py_GIL_DISABLED":value}})
    with pytest.raises(ReachedAllocation):
        owner.run_release_runtime_verification(selected_python=selected,**arguments)
    assert arguments["output_dir"].is_dir()


@pytest.mark.parametrize("mutation", ["extra","missing","duplicate"])
def test_native_identity_response_requires_unambiguous_exact_facts(tmp_path, monkeypatch, mutation):
    arguments = inputs(tmp_path,monkeypatch)
    selected = tmp_path/"selected-python"
    body = "import sys,json,io,contextlib\noutput=io.StringIO()\n"
    body += "with contextlib.redirect_stdout(output):exec(compile(sys.argv[-1],'<actual-native-probe>','exec'))\n"
    body += "value=json.loads(output.getvalue())\n"
    if mutation == "extra":
        body += "value['extra']=True\nprint(json.dumps(value))\n"
    elif mutation == "missing":
        body += "value.pop('soabi',None)\nprint(json.dumps(value))\n"
    else:
        body += "print('{\"python\":\"3.0.0\",'+json.dumps(value)[1:])\n"
    selected.write_text("#!" + sys.executable + "\n" + body)
    selected.chmod(0o700)
    results = capture_probe(monkeypatch)
    with pytest.raises(GitHubControllerError,match="interpreter or platform"):
        owner.run_release_runtime_verification(selected_python=selected,**arguments)
    assert len(results) == 1 and results[0].returncode == 0, results
    assert not arguments["output_dir"].exists()

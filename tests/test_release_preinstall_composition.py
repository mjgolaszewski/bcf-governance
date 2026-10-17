from __future__ import annotations

import io
from pathlib import Path
from types import SimpleNamespace
import tarfile
import zipfile

import pytest

from bcf_governance.tooling import release_runtime_verification as runtime
from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from bcf_governance.tooling.release_closure import ReleaseClosureError


@pytest.fixture
def verification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    wheel = tmp_path / "bcf.whl"
    sdist = tmp_path / "bcf.tar.gz"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("bcf_governance/__init__.py", b"VALUE = 1\n")
    with tarfile.open(sdist, "w:gz") as archive:
        payload = b"VALUE = 1\n"
        info = tarfile.TarInfo("source/bcf_governance/__init__.py")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    events = []
    monkeypatch.setattr(runtime, "_executable", lambda value, label: value)
    monkeypatch.setattr(runtime, "verify_wheelhouse", lambda *args: SimpleNamespace(as_dict=lambda: {}))
    monkeypatch.setattr(runtime.platform, "machine", lambda: "x86_64")

    def identity(*args, **kwargs):
        events.append("interpreter")
        return SimpleNamespace(returncode=0, stdout="3.12.14\n")

    monkeypatch.setattr(runtime.subprocess, "run", identity)

    def environment(*args, **kwargs):
        events.append("environment")
        raise AssertionError("environment allocated before composition rejection")

    monkeypatch.setattr(runtime, "_environment", environment)
    return dict(selected_python=tmp_path / "python", manifest_path=wheel, lock_path=sdist,
                wheelhouse=tmp_path, wheel=wheel, sdist=sdist, output_dir=tmp_path / "result"), events


@pytest.mark.parametrize("subject", ["wheel", "sdist"])
@pytest.mark.parametrize("defect", ["unsafe", "malformed", "duplicate"])
def test_unsafe_release_archive_rejects_before_subprocess_or_output(verification, subject, defect):
    inputs, events = verification
    if defect == "malformed":
        inputs[subject].write_bytes(b"not an archive")
    elif subject == "wheel":
        with zipfile.ZipFile(inputs[subject], "a") as archive:
            name = "../escaped.py" if defect == "unsafe" else "bcf_governance/__init__.py"
            archive.writestr(name, b"unsafe")
    else:
        with tarfile.open(inputs[subject], "w:gz") as archive:
            info = tarfile.TarInfo("source/link")
            if defect == "unsafe":
                info.type = tarfile.SYMTYPE
                info.linkname = "../../escaped"
            else:
                archive.addfile(info)
            archive.addfile(info)
    with pytest.raises(ReleaseClosureError):
        runtime.run_release_runtime_verification(**inputs)
    assert events == []
    assert not inputs["output_dir"].exists()


def test_ambiguous_sdist_roots_reject_before_environment_allocation(verification):
    inputs, events = verification
    with tarfile.open(inputs["sdist"], "w:gz") as archive:
        for root in ("first", "second"):
            archive.addfile(tarfile.TarInfo(root + "/module.py"))
    with pytest.raises(GitHubControllerError, match="exactly one source root"):
        runtime.run_release_runtime_verification(**inputs)
    assert events == ["interpreter"]


@pytest.mark.parametrize("change", ["substitution", "unowned"])
def test_wheel_source_mismatch_rejects_before_environment_allocation(verification, change):
    inputs, events = verification
    with zipfile.ZipFile(inputs["wheel"], "w") as archive:
        name = "__init__" if change == "substitution" else "unowned"
        archive.writestr(f"bcf_governance/{name}.py", b"VALUE = 'changed'\n")
    with pytest.raises(GitHubControllerError, match="source mapping differs"):
        runtime.run_release_runtime_verification(**inputs)
    assert events == ["interpreter"]


def test_valid_release_composition_precedes_both_environments_and_preserves_report(verification, monkeypatch):
    inputs, events = verification
    original = runtime._validate_wheel_source_mapping

    def mapping(*args):
        events.append("source-mapping")
        return original(*args)

    def environment(*args, **kwargs):
        assert "source-mapping" in events
        events.append(kwargs["label"] + "-environment")
        return inputs["selected_python"], {}, []

    def run(label, argv, **kwargs):
        events.append(label)
        (kwargs["output_dir"] / (label + ".stdout")).write_bytes(b"passed\n")
        return dict(label=label, exit_code=0)

    monkeypatch.setattr(runtime, "_validate_wheel_source_mapping", mapping)
    monkeypatch.setattr(runtime, "_environment", environment)
    monkeypatch.setattr(runtime, "_run", run)
    result = runtime.run_release_runtime_verification(**inputs)
    assert result["status"] == "passed"
    assert result["source_mapping"] == dict(status="exact", mapped_files=1)
    assert events[:3] == ["interpreter", "source-mapping", "wheel-environment"]
    assert events.index("source-mapping") < events.index("sdist-environment")
    assert "wheel-installed-consumer" in events
    assert (inputs["output_dir"] / "runtime-verification.json").is_file()


def test_invalid_release_metadata_rejects_before_candidate_installation(verification, monkeypatch):
    inputs, events = verification

    def environment(*args, **kwargs):
        events.append(kwargs["label"] + "-environment")
        return inputs["selected_python"], {}, []

    def run(label, argv, **kwargs):
        events.append(label)
        if label == "twine-check":
            raise GitHubControllerError("invalid release metadata")
        raise AssertionError("candidate installation or execution preceded metadata admission")

    monkeypatch.setattr(runtime, "_environment", environment)
    monkeypatch.setattr(runtime, "_run", run)
    with pytest.raises(GitHubControllerError, match="invalid release metadata"):
        runtime.run_release_runtime_verification(**inputs)
    assert events == ["interpreter", "wheel-environment", "twine-check"]

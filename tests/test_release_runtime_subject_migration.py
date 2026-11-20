"""Versioned runtime subjects preserve history and require independent identity."""
import json
import sys
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from bcf_governance.tooling.release_closure import ReleaseClosureError, verify_release_lock
from bcf_governance.tooling.release_runtime_verification import (
    run_release_runtime_verification, verify_runtime_evidence,
)
from test_release_closure import _closure
from test_release_runtime_commands import command_report
from test_release_runtime_verification import _fixture


def manifest(tmp_path, python="3.12.99", abi="cp312", tag=None):
    path, lock, wheels = _closure(tmp_path)
    value = yaml.safe_load(path.read_text())
    value["schema_version"] = "1.1"
    value["subject"].update(python=python, abi=abi)
    if tag:
        name = "alpha-1.0-py3-none-any.whl"
        replacement = "alpha-1.0-" + tag + ".whl"
        value["wheels"][replacement] = value["wheels"].pop(name)
        (wheels/name).rename(wheels/replacement)
    path.write_text(yaml.safe_dump(value, sort_keys=False))
    return path, lock, wheels


@pytest.mark.parametrize("minor", [11,12,13,14])
def test_explicit_future_patch_subject_is_representable_without_selecting_it(tmp_path, minor):
    path, lock, _ = manifest(tmp_path, f"3.{minor}.99", f"cp3{minor}")
    result = verify_release_lock(path, lock)
    assert result.python == f"3.{minor}.99" and result.platform == "linux_x86_64"
    assert len(result.wheels) == 2
    assert result.manifest_schema_version == "1.1"


@pytest.mark.parametrize("tag", ["py3-none-any", "cp38-abi3-manylinux_2_17_x86_64",
                                  "cp312-cp312-manylinux2014_x86_64"])
def test_explicit_target_admits_pure_native_and_applicable_abi3_tags(tmp_path, tag):
    path, lock, _ = manifest(tmp_path, tag=tag)
    assert verify_release_lock(path, lock).python == "3.12.99"


@pytest.mark.parametrize("python,abi", [("3.12.99","cp311"),("3.15.0","cp315"),
    ("3.14.0rc1","cp314"),("3.12","cp312"),(True,"cp312"),("3.012.99","cp312")])
def test_new_subject_rejects_incompatible_or_nonstable_identity(tmp_path, python, abi):
    path, lock, _ = manifest(tmp_path, python, abi)
    with pytest.raises(ReleaseClosureError):
        verify_release_lock(path, lock)


@pytest.mark.parametrize("tag", ["cp311-cp311-manylinux_2_17_x86_64",
    "cp313-abi3-manylinux_2_17_x86_64","cp312-cp312-manylinux_2_17_aarch64"])
def test_new_subject_rejects_wheels_incompatible_with_its_exact_target(tmp_path, tag):
    path, lock, _ = manifest(tmp_path, tag=tag)
    with pytest.raises(ReleaseClosureError):
        verify_release_lock(path, lock)


def report(tmp_path, python="3.12.99"):
    path, evidence, wheel, sdist = command_report(tmp_path, "1.1")
    expected = {"status":"verified", "python":python, "platform":"linux_x86_64",
                "lock_sha256":"a"*64,"wheels":{"dependency.whl":"b"*64}}
    value = json.loads(path.read_text())
    value.update(schema_version="1.2", dependency_closure=expected)
    value["environment"]["python_version"] = python
    path.write_text(json.dumps(value))
    return path, evidence, wheel, sdist, expected


@pytest.mark.parametrize("minor", [11,12,13,14])
def test_new_report_binds_independent_exact_runtime_subject(tmp_path, minor):
    path, evidence, wheel, sdist, expected = report(tmp_path, f"3.{minor}.99")
    result = verify_runtime_evidence(path,evidence,wheel=wheel,sdist=sdist,
        required_version="1.2",expected_dependency_closure=expected)
    assert result["environment"]["python_version"] == expected["python"]


@pytest.mark.parametrize("required", [None,"1.2"])
def test_candidate_report_cannot_select_its_own_expected_runtime(tmp_path, required):
    path, evidence, wheel, sdist, _ = report(tmp_path)
    with pytest.raises(GitHubControllerError, match="dependency closure"):
        verify_runtime_evidence(path,evidence,wheel=wheel,sdist=sdist,required_version=required)


@pytest.mark.parametrize("defect", ["environment","expected","commands"])
def test_self_consistent_new_report_cannot_change_required_subject_or_commands(tmp_path, defect):
    path, evidence, wheel, sdist, expected = report(tmp_path)
    value = json.loads(path.read_text())
    if defect == "environment":
        value["environment"]["python_version"] = "3.12.98"
    elif defect == "expected":
        expected = dict(expected, python="3.12.98")
    else:
        next(row for row in value["commands"] if row["label"]=="wheel-install")["argv"].remove("--no-index")
    path.write_text(json.dumps(value))
    with pytest.raises(GitHubControllerError):
        verify_runtime_evidence(path,evidence,wheel=wheel,sdist=sdist,
            required_version="1.2",expected_dependency_closure=expected)


@pytest.mark.parametrize("version", ["1.0","1.1"])
def test_legacy_reports_cannot_be_reinterpreted_as_patched_runtime_proof(tmp_path, version):
    path, evidence, wheel, sdist = command_report(tmp_path, version)
    value = json.loads(path.read_text())
    value["environment"]["python_version"] = "3.12.99"
    path.write_text(json.dumps(value))
    with pytest.raises(GitHubControllerError):
        verify_runtime_evidence(path,evidence,wheel=wheel,sdist=sdist)


def test_wrong_native_runtime_stops_before_verification_output_allocation(tmp_path):
    inputs = tmp_path/"inputs"
    inputs.mkdir()
    path, lock, wheels = manifest(inputs)
    archives = tmp_path/"archives"
    archives.mkdir()
    _, _, wheel, sdist = _fixture(archives)
    output = tmp_path/"verification"
    with pytest.raises(GitHubControllerError, match="interpreter or platform"):
        run_release_runtime_verification(selected_python=Path(sys.executable),manifest_path=path,
            lock_path=lock,wheelhouse=wheels,wheel=wheel,sdist=sdist,output_dir=output)
    assert not output.exists()

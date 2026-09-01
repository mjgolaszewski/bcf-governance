from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from bcf_governance.tooling import ci_github_commands
from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from bcf_governance.tooling.release_runtime_verification import (
    SDIST_CUSTODY_COMMIT_MESSAGE,
    SDIST_PORTABLE_TEST_ENV,
    is_release_sdist_test_context,
    runtime_environment,
    runtime_evidence_paths,
    verify_runtime_evidence,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(tmp_path: Path) -> tuple[Path, tuple[Path, ...], Path, Path]:
    wheel = tmp_path / "bcf_governance-0.7.1-py3-none-any.whl"
    sdist = tmp_path / "bcf_governance-0.7.1.tar.gz"
    stdout = tmp_path / "sdist-tests.stdout"
    junit = tmp_path / "sdist-tests.xml"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    stdout.write_bytes(b"516 passed\n")
    junit.write_bytes(b'<testsuite tests="516" failures="0"/>\n')
    evidence = (stdout, junit)
    report = tmp_path / "runtime-verification.json"
    report.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "status": "passed",
                "environment": {
                    "python_executable": "/opt/python/bin/python",
                    "python_version": "3.12.14",
                    "platform": "linux_x86_64",
                },
                "release_artifacts": {wheel.name: _sha(wheel), sdist.name: _sha(sdist)},
                "evidence": {path.name: _sha(path) for path in evidence},
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return report, evidence, wheel, sdist


def test_runtime_evidence_binds_exact_release_bytes_and_raw_results(
    tmp_path: Path,
) -> None:
    report, evidence, wheel, sdist = _fixture(tmp_path)

    result = verify_runtime_evidence(report, evidence, wheel=wheel, sdist=sdist)

    assert result["status"] == "passed"
    assert result["environment"]["python_version"] == "3.12.14"


def test_runtime_evidence_directory_is_selected_from_the_report(tmp_path: Path) -> None:
    report, evidence, _, _ = _fixture(tmp_path)
    root = tmp_path / "runtime"
    root.mkdir()
    exact_report = root / report.name
    exact_report.write_bytes(report.read_bytes())
    exact_evidence = []
    for source in evidence:
        destination = root / source.name
        destination.write_bytes(source.read_bytes())
        exact_evidence.append(destination)

    assert runtime_evidence_paths(exact_report, root) == tuple(
        sorted(exact_evidence, key=lambda path: path.name)
    )

    extra = root / "operator-added.log"
    extra.write_text("not declared\n", encoding="utf-8")
    with pytest.raises(GitHubControllerError, match="directory is not exact"):
        runtime_evidence_paths(exact_report, root)


def test_candidate_runtime_environment_excludes_provider_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "never-inherit")
    monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "never-inherit")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "never-inherit")
    monkeypatch.setenv("LANG", "C.UTF-8")

    environment = runtime_environment(home=tmp_path)

    assert environment["HOME"] == str(tmp_path)
    assert environment["LANG"] == "C.UTF-8"
    assert environment["PIP_NO_INDEX"] == "1"
    assert "GITHUB_TOKEN" not in environment
    assert "ACTIONS_RUNTIME_TOKEN" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment


def test_portable_sdist_mode_requires_mechanically_created_archive_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(SDIST_PORTABLE_TEST_ENV, "1")
    with pytest.raises(GitHubControllerError, match="package metadata"):
        is_release_sdist_test_context(tmp_path)

    metadata = tmp_path / "PKG-INFO"
    metadata.write_text("Name: bcf-governance\nVersion: 0.7.1\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "release@example.invalid"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "BCF Release Verifier"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(["git", "add", "PKG-INFO"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "--quiet", "-m", SDIST_CUSTODY_COMMIT_MESSAGE],
        cwd=tmp_path,
        check=True,
    )

    assert is_release_sdist_test_context(tmp_path) is True


def test_runtime_cli_never_constructs_provider_api(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    github_output = tmp_path / "github-output"
    github_output.touch()
    monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
    monkeypatch.setattr(
        ci_github_commands,
        "environment_api",
        lambda: pytest.fail("token-free runtime constructed a provider API"),
    )
    monkeypatch.setattr(
        ci_github_commands,
        "run_release_runtime_verification",
        lambda **_: {"schema_version": "1.0", "status": "passed", "evidence": {}},
    )

    ci_github_commands._release(
        [
            "runtime",
            "--wheelhouse-manifest", str(tmp_path / "manifest.yml"),
            "--lock", str(tmp_path / "release.lock"),
            "--wheelhouse", str(tmp_path / "wheelhouse"),
            "--release-artifact", str(tmp_path / "bcf_governance-0.7.1-py3-none-any.whl"),
            "--release-artifact", str(tmp_path / "bcf_governance-0.7.1.tar.gz"),
            "--python", str(tmp_path / "python"),
            "--output", str(tmp_path / "runtime"),
        ]
    )

    assert "status=passed" in github_output.read_text(encoding="utf-8")


def test_provider_evidence_cli_never_executes_candidate_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    github_output = tmp_path / "github-output"
    github_output.touch()
    monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
    monkeypatch.setenv("GITHUB_RUN_ID", "31")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    monkeypatch.setattr(
        ci_github_commands,
        "run_release_runtime_verification",
        lambda **_: pytest.fail("provider authentication executed candidate runtime"),
    )
    monkeypatch.setattr(
        ci_github_commands,
        "environment_api",
        lambda: object(),
    )
    monkeypatch.setattr(
        ci_github_commands,
        "verify_release_build_provider",
        lambda *_, **__: {"schema_version": "1.0", "status": "passed"},
    )

    ci_github_commands._release(
        [
            "verify-evidence",
            "--repository", "owner/repo",
            "--authorization", str(tmp_path / "authorization.json"),
            "--build-manifest", str(tmp_path / "build.json"),
            "--wheelhouse-manifest", str(tmp_path / "manifest.yml"),
            "--lock", str(tmp_path / "release.lock"),
            "--wheelhouse", str(tmp_path / "wheelhouse"),
            "--release-artifact", str(tmp_path / "bcf_governance-0.7.1-py3-none-any.whl"),
            "--release-artifact", str(tmp_path / "bcf_governance-0.7.1.tar.gz"),
            "--runtime-report", str(tmp_path / "runtime.json"),
            "--runtime-evidence", str(tmp_path / "runtime.stdout"),
            "--output", str(tmp_path / "verification.json"),
        ]
    )

    assert "status=passed" in github_output.read_text(encoding="utf-8")


@pytest.mark.parametrize("mutation", ["wheel", "evidence", "environment", "inventory"])
def test_runtime_evidence_rejects_every_unbound_authority_surface(
    tmp_path: Path, mutation: str
) -> None:
    report, evidence, wheel, sdist = _fixture(tmp_path)
    if mutation == "wheel":
        wheel.write_bytes(b"changed")
    elif mutation == "evidence":
        evidence[0].write_bytes(b"fabricated pass")
    else:
        payload = json.loads(report.read_text(encoding="utf-8"))
        if mutation == "environment":
            payload["environment"]["python_version"] = "3.12.13"
        else:
            payload["evidence"]["extra.log"] = "0" * 64
        report.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    with pytest.raises(GitHubControllerError):
        verify_runtime_evidence(report, evidence, wheel=wheel, sdist=sdist)

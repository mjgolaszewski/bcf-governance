from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from bcf_governance.tooling.release_runtime_verification import verify_runtime_evidence


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

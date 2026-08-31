from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile

import pytest
import yaml

from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from bcf_governance.tooling.ci_github_release import inspect_release, verify_release_build
from bcf_governance.tooling.release_closure import verify_release_lock
from bcf_governance.tooling.release_receipts import (
    ReleaseReceiptError,
    build_trusted_release_receipt,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
TREE = "b" * 40


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _release_inputs(tmp_path: Path) -> dict[str, object]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    dependency = b"dependency-wheel"
    dependency_digest = hashlib.sha256(dependency).hexdigest()
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    dependency_name = "alpha-1.0-py3-none-any.whl"
    (wheelhouse / dependency_name).write_bytes(dependency)
    lock = tmp_path / "release.lock"
    lock.write_text(f"alpha==1.0 --hash=sha256:{dependency_digest}\n", encoding="utf-8")
    manifest = tmp_path / "wheelhouse.yml"
    manifest.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0",
                "subject": {
                    "python": "3.12.14",
                    "implementation": "CPython",
                    "operating_system": "ubuntu-24.04",
                    "platform": "linux_x86_64",
                    "wheel_platform": "manylinux_2_17_x86_64",
                    "abi": "cp312",
                },
                "resolution": {"lock_sha256": _sha(lock)},
                "wheels": {dependency_name: dependency_digest},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    wheel = tmp_path / "bcf_governance-0.7.1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("bcf_governance/__init__.py", "")
    sdist = tmp_path / "bcf_governance-0.7.1.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        raw = b"source"
        info = tarfile.TarInfo("bcf_governance-0.7.1/README.md")
        info.size = len(raw)
        archive.addfile(info, io.BytesIO(raw))
    sums = tmp_path / "SHA256SUMS"
    sums.write_text(f"{_sha(wheel)}  {wheel.name}\n{_sha(sdist)}  {sdist.name}\n", encoding="utf-8")
    subject = {"commit_sha": COMMIT, "tree_sha": TREE}
    authorization = _json(
        tmp_path / "release-authorization.json",
        {
            "schema_version": "1.0",
            "authority_contract_version": "1.1",
            "subject": subject,
            "exact_main": {},
            "authorizer": {"run_id": "10", "run_attempt": 1},
            "controller": {
                "artifact_id": "1",
                "provider_digest": f"sha256:{'c' * 64}",
                "wheel_sha256": "d" * 64,
                "commit_sha": COMMIT,
                "tree_sha": TREE,
            },
        },
    )
    assets = {path.name: _sha(path) for path in (wheel, sdist, sums)}
    build = _json(
        tmp_path / "release-build-manifest.json",
        {
            "schema_version": "1.0",
            "subject": subject,
            "authorization_sha256": _sha(authorization),
            "run_id": "20",
            "run_attempt": 1,
            "builder": {"run_id": "20", "run_attempt": 1},
            "artifact_name": f"bcf-release-build-{COMMIT}-1",
            "dependency_closure": verify_release_lock(manifest, lock).as_dict(),
            "started_at": "2026-08-31T00:00:00Z",
            "assets": assets,
        },
    )
    return {
        "authorization": authorization,
        "build": build,
        "manifest": manifest,
        "lock": lock,
        "wheelhouse": wheelhouse,
        "artifacts": (wheel, sdist, sums),
        "assets": assets,
    }


def _verify(values: dict[str, object], output: Path) -> dict[str, object]:
    return verify_release_build(
        authorization_path=values["authorization"],  # type: ignore[arg-type]
        build_manifest_path=values["build"],  # type: ignore[arg-type]
        manifest_path=values["manifest"],  # type: ignore[arg-type]
        lock_path=values["lock"],  # type: ignore[arg-type]
        wheelhouse=values["wheelhouse"],  # type: ignore[arg-type]
        release_artifacts=values["artifacts"],  # type: ignore[arg-type]
        verifier_run_id="30",
        verifier_run_attempt="2",
        build_artifact_id="40",
        build_provider_digest=f"sha256:{'e' * 64}",
        output_path=output,
    )


def test_release_verifier_recomputes_closed_bytes_and_archives(tmp_path: Path) -> None:
    values = _release_inputs(tmp_path)
    result = _verify(values, tmp_path / "release-verification.json")

    assert result["status"] == "passed"
    assert result["assets"] == values["assets"]
    assert result["dependency_closure"]["status"] == "verified"  # type: ignore[index]


def test_release_verifier_rejects_candidate_manifest_and_dependency_mutants(
    tmp_path: Path,
) -> None:
    values = _release_inputs(tmp_path)
    values["artifacts"][0].write_bytes(b"changed")  # type: ignore[index,union-attr]
    with pytest.raises(ValueError, match="archive|asset bytes"):
        _verify(values, tmp_path / "changed.json")

    values = _release_inputs(tmp_path / "second")
    (values["wheelhouse"] / "extra.whl").write_bytes(b"extra")  # type: ignore[operator]
    with pytest.raises(ValueError, match="inventory is not exact"):
        _verify(values, tmp_path / "second" / "changed.json")


def test_trusted_receipt_rejects_candidate_lookalike_and_binds_all_roles(
    tmp_path: Path,
) -> None:
    values = _release_inputs(tmp_path)
    certification = {
        "authority_contract_version": "1.1",
        "subject": {"checkout_sha": COMMIT, "tree_sha": TREE},
        "admission": {
            "admission_ordinal": "100001001",
            "control_plane_run_id": "100",
            "control_plane_run_attempt": 1,
        },
    }
    certification_path = _json(tmp_path / "ci-certification.json", certification)
    session = _json(tmp_path / "evidence-session.json", {"session": "exact"})
    authorization = json.loads(values["authorization"].read_text(encoding="utf-8"))  # type: ignore[union-attr]
    authorization["exact_main"] = {
        "admission_ordinal": "100001001",
        "run_id": "100",
        "run_attempt": 1,
        "certification_sha256": _sha(certification_path),
        "session_sha256": _sha(session),
    }
    _json(values["authorization"], authorization)  # type: ignore[arg-type]
    build = json.loads(values["build"].read_text(encoding="utf-8"))  # type: ignore[union-attr]
    build["authorization_sha256"] = _sha(values["authorization"])  # type: ignore[arg-type]
    _json(values["build"], build)  # type: ignore[arg-type]
    verification_path = tmp_path / "release-verification.json"
    verification = _verify(values, verification_path)

    receipt = build_trusted_release_receipt(
        REPO_ROOT,
        certification=certification,
        certification_path=certification_path,
        certification_verification={"status": "pass", "computed_state": "certified"},
        session_manifest_path=session,
        authorization_path=values["authorization"],  # type: ignore[arg-type]
        build_manifest_path=values["build"],  # type: ignore[arg-type]
        verification_path=verification_path,
        release_artifacts=values["artifacts"],  # type: ignore[arg-type]
        collector_identity={
            "workflow_path": ".github/workflows/bcf-release-collector.yml",
            "run_id": "50",
            "run_attempt": "1",
        },
        output_path=tmp_path / "release.evidence.json",
    )
    assert receipt.payload["observations"]["acyclic_construction"]["candidate_authored_receipt_accepted"] is False

    verification["build"]["manifest_sha256"] = "0" * 64  # type: ignore[index]
    _json(verification_path, verification)
    with pytest.raises(ReleaseReceiptError, match="exact build"):
        build_trusted_release_receipt(
            REPO_ROOT,
            certification=certification,
            certification_path=certification_path,
            certification_verification={"status": "pass", "computed_state": "certified"},
            session_manifest_path=session,
            authorization_path=values["authorization"],  # type: ignore[arg-type]
            build_manifest_path=values["build"],  # type: ignore[arg-type]
            verification_path=verification_path,
            release_artifacts=values["artifacts"],  # type: ignore[arg-type]
            collector_identity={"workflow_path": "x", "run_id": "1", "run_attempt": "1"},
            output_path=tmp_path / "lookalike.json",
        )


class _ReleaseAPI:
    def __init__(self) -> None:
        self.immutable = {"enabled": True}
        self.ref = {"object": {"type": "tag", "sha": "c" * 40}}
        self.tag = {
            "tag": "v0.7.1",
            "object": {"type": "commit", "sha": COMMIT},
            "verification": {"verified": False, "reason": "unsigned"},
        }
        self.release = {
            "immutable": True,
            "draft": False,
            "assets": [{"name": "asset.whl", "digest": f"sha256:{'d' * 64}"}],
        }
        self.attested = True

    def immutable_releases(self, repository: str):
        return self.immutable

    def reference(self, repository: str, ref: str):
        return self.ref

    def tag_object(self, repository: str, sha: str):
        return self.tag

    def release_by_tag(self, repository: str, tag: str):
        return self.release

    def attestations(self, repository: str, digest: str):
        return ({"bundle": "present"},) if self.attested else ()


def test_release_inspection_accepts_only_exact_immutable_attested_provider_state() -> None:
    api = _ReleaseAPI()
    result = inspect_release(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        tag="v0.7.1",
        expected_commit=COMMIT,
        expected_assets={"asset.whl": "d" * 64},
    )
    assert result["status"] == "verified"


@pytest.mark.parametrize(
    "mutation, message",
    [
        ("mutable", "immutable releases"),
        ("lightweight", "annotated"),
        ("signed", "unsigned policy"),
        ("draft", "immutable and non-draft"),
        ("changed-asset", "assets are not exact"),
        ("missing-attestation", "lacks attestation"),
    ],
)
def test_release_inspection_rejects_provider_custody_mutants(
    mutation: str, message: str
) -> None:
    api = _ReleaseAPI()
    if mutation == "mutable":
        api.immutable["enabled"] = False
    elif mutation == "lightweight":
        api.ref["object"]["type"] = "commit"
    elif mutation == "signed":
        api.tag["verification"] = {"verified": True, "reason": "valid"}
    elif mutation == "draft":
        api.release["draft"] = True
    elif mutation == "changed-asset":
        api.release["assets"][0]["digest"] = f"sha256:{'e' * 64}"
    else:
        api.attested = False
    with pytest.raises(GitHubControllerError, match=message):
        inspect_release(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            tag="v0.7.1",
            expected_commit=COMMIT,
            expected_assets={"asset.whl": "d" * 64},
        )

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile
from types import SimpleNamespace

import pytest
import yaml

from bcf_governance.tooling import ci_github_authority
from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from bcf_governance.tooling.ci_github_artifacts import ProviderArtifact
from bcf_governance.tooling.ci_github_api import GitHubContent
from bcf_governance.tooling.ci_github_identity import MainIdentity
from bcf_governance.tooling.ci_github_release import (
    authorize_release,
    collect_release,
    inspect_release,
    publish_certified_release,
    verify_release_build,
    verify_release_build_provider,
)
from bcf_governance.tooling.ci_github_release_inputs import (
    load_release_authorization_inputs,
    release_input_outputs,
    resolve_release_authorization_inputs,
)
from bcf_governance.tooling.ci_authority_state import WorkflowIdentity
from bcf_governance.tooling.release_closure import verify_release_lock
from bcf_governance.tooling.release_asset_inventory import release_asset_paths
from bcf_governance.tooling.release_receipts import (
    ReleaseReceiptError,
    build_trusted_release_receipt,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
TREE = "b" * 40


def test_nonterminal_privileged_inventory_accepts_only_pinned_partial_jobs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = {
        "schema_version": "1.1",
        "roles": {"release_authorizer": "release"},
        "workflow_registry": {
            "release": {
                "expected_jobs": [
                    {"job_id": "Authorize"},
                    {"job_id": "Build"},
                ],
            },
        },
    }
    identity = SimpleNamespace(run_id="10", run_attempt=1)
    monkeypatch.setattr(
        ci_github_authority, "authenticate_role_run", lambda *_, **__: identity
    )
    jobs = [{"name": "Authorize", "status": "in_progress", "conclusion": None}]
    api = SimpleNamespace(jobs=lambda *_, **__: jobs)
    kwargs = {
        "repository": "owner/repo",
        "main": MainIdentity("101", "main", COMMIT, TREE),
        "authority": authority,
        "role": "release_authorizer",
        "run_id": "10",
        "run_attempt": 1,
        "require_success": False,
    }

    _, observed = ci_github_authority.authenticate_role_job_inventory(
        api, require_terminal=False, **kwargs
    )
    assert observed == jobs

    jobs[0]["name"] = "Unpinned"
    with pytest.raises(GitHubControllerError, match="exact job inventory"):
        ci_github_authority.authenticate_role_job_inventory(
            api, require_terminal=False, **kwargs
        )
    jobs[0]["name"] = "Authorize"
    with pytest.raises(GitHubControllerError, match="exact job inventory"):
        ci_github_authority.authenticate_role_job_inventory(
            api, require_terminal=True, **kwargs
        )


def _workflow(path: str, event: str) -> WorkflowIdentity:
    return WorkflowIdentity(
        provider="github",
        repository_id="101",
        workflow_id="202",
        active_path=path,
        trusted_workflow_blob_oid="c" * 40,
        trusted_workflow_sha256="d" * 64,
        trusted_workflow_definition_commit="e" * 40,
        event=event,
    )


def _provider_artifact(
    run_id: str, attempt: int, artifact_id: str, digest_char: str = "f"
) -> dict[str, object]:
    return ProviderArtifact(
        run_id,
        attempt,
        artifact_id,
        f"artifact-{artifact_id}",
        f"sha256:{digest_char * 64}",
        {},
    ).as_dict()


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
            "release_inputs": {
                "dependency_lock": {
                    "path": "release/requirements-cp312-linux-x86_64.lock",
                    "blob_oid": "1" * 40,
                    "sha256": _sha(lock),
                },
                "wheelhouse_manifest": {
                    "path": "release/wheelhouse-manifest.yml",
                    "blob_oid": "2" * 40,
                    "sha256": _sha(manifest),
                },
            },
        },
    )
    assets = {path.name: _sha(path) for path in (wheel, sdist, sums)}
    runtime_stdout = tmp_path / "runtime.stdout"
    runtime_stdout.write_text("offline verification passed\n", encoding="utf-8")
    runtime_junit = tmp_path / "sdist-tests.xml"
    runtime_junit.write_text('<testsuite tests="1" failures="0"/>\n', encoding="utf-8")
    runtime_evidence = (runtime_stdout, runtime_junit)
    runtime_report = _json(
        tmp_path / "runtime-verification.json",
        {
            "schema_version": "1.0",
            "status": "passed",
            "environment": {
                "python_executable": "/opt/python/bin/python",
                "python_version": "3.12.14",
                "platform": "linux_x86_64",
            },
            "release_artifacts": {wheel.name: _sha(wheel), sdist.name: _sha(sdist)},
            "evidence": {path.name: _sha(path) for path in runtime_evidence},
        },
    )
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
        "runtime_report": runtime_report,
        "runtime_evidence": runtime_evidence,
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
        runtime_report_path=values["runtime_report"],  # type: ignore[arg-type]
        runtime_evidence=values["runtime_evidence"],  # type: ignore[arg-type]
    )


def test_release_verifier_recomputes_closed_bytes_and_archives(tmp_path: Path) -> None:
    values = _release_inputs(tmp_path)
    result = _verify(values, tmp_path / "release-verification.json")

    assert result["status"] == "passed"
    assert result["assets"] == values["assets"]
    assert result["dependency_closure"]["status"] == "verified"  # type: ignore[index]


def test_release_asset_directory_rejects_extra_or_unsafe_members(tmp_path: Path) -> None:
    values = _release_inputs(tmp_path / "inputs")
    root = tmp_path / "assets"
    root.mkdir()
    for source in values["artifacts"]:  # type: ignore[union-attr]
        (root / source.name).write_bytes(source.read_bytes())

    assert release_asset_paths(root) == tuple(sorted(root.iterdir()))

    (root / "operator-added.txt").write_text("extra\n", encoding="utf-8")
    with pytest.raises(GitHubControllerError, match="one wheel"):
        release_asset_paths(root)


def test_release_verifier_rejects_candidate_manifest_and_dependency_mutants(
    tmp_path: Path,
) -> None:
    values = _release_inputs(tmp_path)
    values["artifacts"][0].write_bytes(b"changed")  # type: ignore[index,union-attr]
    with pytest.raises(ValueError, match="archive|asset bytes|checksum"):
        _verify(values, tmp_path / "changed.json")

    values = _release_inputs(tmp_path / "second")
    (values["wheelhouse"] / "extra.whl").write_bytes(b"extra")  # type: ignore[operator]
    with pytest.raises(ValueError, match="inventory is not exact"):
        _verify(values, tmp_path / "second" / "changed.json")

    values = _release_inputs(tmp_path / "third")
    (tmp_path / "third" / "SHA256SUMS").write_text(
        f"{'0' * 64}  bcf_governance-0.7.1-py3-none-any.whl\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="checksum inventory"):
        _verify(values, tmp_path / "third" / "changed.json")


def test_release_verifier_rejects_manifest_bytes_not_bound_to_exact_main(
    tmp_path: Path,
) -> None:
    values = _release_inputs(tmp_path)
    manifest = values["manifest"]
    manifest.write_text(  # type: ignore[union-attr]
        manifest.read_text(encoding="utf-8") + "\n",  # type: ignore[union-attr]
        encoding="utf-8",
    )

    with pytest.raises(GitHubControllerError, match="authorized exact main"):
        _verify(values, tmp_path / "changed-source.json")


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
        "certification_artifact": _provider_artifact("50", 1, "41"),
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
        certification_provider_artifact=_provider_artifact("50", 1, "41"),
        build_provider_artifact=_provider_artifact("20", 1, "40", "e"),
        verification_provider_artifact=_provider_artifact("30", 2, "42"),
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
            certification_provider_artifact=_provider_artifact("50", 1, "41"),
            build_provider_artifact=_provider_artifact("20", 1, "40", "e"),
            verification_provider_artifact=_provider_artifact("30", 2, "42"),
        )


def test_release_authorizer_binds_newest_certification_and_controller_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    certification = {
        "authority_contract_version": "1.1",
        "subject": {"checkout_sha": COMMIT, "tree_sha": TREE},
        "admission": {
            "admission_ordinal": "100001001",
            "control_plane_run_id": "100",
            "control_plane_run_attempt": 1,
        },
    }
    _json(bundle / "ci-certification.json", certification)
    _json(
        bundle / "evidence-session.json",
        {"producer": {"run_id": "50", "run_attempt": "1"}},
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.verify_bundle",
        lambda root: {"subject": {"commit_sha": COMMIT, "tree_sha": TREE}},
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.verify_ci_certification",
        lambda *args, **kwargs: SimpleNamespace(status="pass", computed_state="certified"),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.resolve_main",
        lambda api, repository: MainIdentity("101", "main", COMMIT, TREE),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.load_authority",
        lambda *args, **kwargs: {},
    )
    authorizer = SimpleNamespace(
        run_id="60", run_attempt=1,
        workflow=_workflow(".github/workflows/release.yml", "workflow_dispatch"),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.authenticate_role_job_inventory",
        lambda *args, **kwargs: (authorizer, ()),
    )
    certification_artifact = ProviderArtifact(
        "50", 1, "41", "certification", f"sha256:{'a' * 64}", {}
    )
    controller_artifact = ProviderArtifact(
        "100", 1, "42", "controller", f"sha256:{'b' * 64}", {}
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.authenticate_role_artifact",
        lambda *args, **kwargs: (
            certification_artifact if kwargs["role"] == "finalizer" else controller_artifact
        ),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.select_latest_admission",
        lambda *args, **kwargs: ("100", 1),
    )
    controller_root = tmp_path / "controller"
    controller_root.mkdir()
    controller_wheel = controller_root / "bcf_governance-0.7.1-py3-none-any.whl"
    controller_wheel.write_bytes(b"controller")
    controller_metadata = _json(
        controller_root / "CONTROL-METADATA.json",
        {
            "schema_version": "1.0",
            "commit_sha": COMMIT,
            "tree_sha": TREE,
            "workflow_run_id": "100",
            "workflow_run_attempt": "1",
        },
    )
    (controller_root / "SHA256SUMS").write_text(
        f"{_sha(controller_metadata)}  {controller_metadata.name}\n"
        f"{_sha(controller_wheel)}  {controller_wheel.name}\n",
        encoding="utf-8",
    )
    controller_wheel_sha256 = _sha(controller_wheel)
    source_bytes = {
        "release/requirements-cp312-linux-x86_64.lock": b"lock bytes",
        "release/wheelhouse-manifest.yml": b"manifest bytes",
    }
    api = SimpleNamespace(
        content=lambda repository, path, ref: GitHubContent(
            path, "9" * 40, source_bytes[path]
        )
    )
    result = authorize_release(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        bundle_dir=bundle,
        run_id="60",
        run_attempt="1",
        certification_artifact={
            "run_id": "50",
            "run_attempt": "1",
            "artifact_id": "41",
            "artifact_name": "certification",
            "provider_digest": f"sha256:{'a' * 64}",
        },
        controller={
            "run_id": "100",
            "run_attempt": "1",
            "artifact_id": "42",
            "artifact_name": "controller",
            "provider_digest": f"sha256:{'b' * 64}",
            "commit_sha": COMMIT,
            "tree_sha": TREE,
        },
        controller_wheel_path=controller_wheel,
        output_path=tmp_path / "authorization.json",
    )
    assert result["exact_main"]["certification_artifact"] == certification_artifact.as_dict()
    assert result["controller"]["run_id"] == "100"
    assert result["controller"]["wheel_sha256"] == controller_wheel_sha256
    assert result["release_inputs"] == {
        "dependency_lock": {
            "path": "release/requirements-cp312-linux-x86_64.lock",
            "blob_oid": "9" * 40,
            "sha256": hashlib.sha256(source_bytes["release/requirements-cp312-linux-x86_64.lock"]).hexdigest(),
        },
        "wheelhouse_manifest": {
            "path": "release/wheelhouse-manifest.yml",
            "blob_oid": "9" * 40,
            "sha256": hashlib.sha256(source_bytes["release/wheelhouse-manifest.yml"]).hexdigest(),
        },
    }
    controller = dict(result["controller"])
    controller.pop("wheel_sha256")
    controller_wheel.write_bytes(b"corrupted-controller")
    with pytest.raises(GitHubControllerError, match="controller artifact digest"):
        authorize_release(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            bundle_dir=bundle,
            run_id="60",
            run_attempt="1",
            certification_artifact={
                "run_id": "50", "run_attempt": "1", "artifact_id": "41",
                "artifact_name": "certification", "provider_digest": f"sha256:{'a' * 64}",
            },
            controller=controller,
            controller_wheel_path=controller_wheel,
            output_path=tmp_path / "rejected-authorization.json",
        )


def test_release_authorization_inputs_are_provider_resolved_without_caller_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    main = MainIdentity("101", "main", COMMIT, TREE)
    controller = ProviderArtifact(
        "100", 2, "41", "controller", f"sha256:{'a' * 64}", {}
    )
    certification = ProviderArtifact(
        "50", 3, "42", "bcf-exact-main-certification-50-3",
        f"sha256:{'b' * 64}", {},
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release_inputs.resolve_main",
        lambda *args, **kwargs: main,
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release_inputs.load_authority",
        lambda *args, **kwargs: {},
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release_inputs.select_latest_admission",
        lambda *args, **kwargs: ("100", 2),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release_inputs.resolve_self_controller_artifact",
        lambda *args, **kwargs: (
            {"repository_id": "101", "commit_sha": COMMIT, "tree_sha": TREE},
            controller,
        ),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release_inputs.authority_role_workflow",
        lambda *args, **kwargs: {"workflow_id": "202"},
    )
    selected: dict[str, object] = {}

    def authenticate(*args: object, **kwargs: object):
        selected.update(kwargs)
        return SimpleNamespace(run_id="50", run_attempt=3), ()

    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release_inputs.authenticate_role_job_inventory",
        authenticate,
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release_inputs.resolve_role_artifact",
        lambda *args, **kwargs: certification,
    )
    runs = (
        {
            "id": 49, "run_attempt": 1, "head_sha": COMMIT,
            "head_branch": "main", "event": "workflow_run",
            "repository": {"id": 101}, "head_repository": {"id": 101},
        },
        {
            "id": 50, "run_attempt": 3, "head_sha": COMMIT,
            "head_branch": "main", "event": "workflow_run",
            "repository": {"id": 101}, "head_repository": {"id": 101},
        },
    )
    api = SimpleNamespace(workflow_runs=lambda *args, **kwargs: runs)
    path = tmp_path / "release-inputs.json"
    result = resolve_release_authorization_inputs(
        api, repository="owner/repo", output_path=path  # type: ignore[arg-type]
    )

    assert selected["run_id"] == 50
    assert selected["run_attempt"] == 3
    assert load_release_authorization_inputs(path) == result
    assert release_input_outputs(result) == {
        "subject_commit": COMMIT,
        "subject_tree": TREE,
        "certification_artifact_id": "42",
        "certification_run_id": "50",
        "controller_artifact_id": "41",
        "controller_run_id": "100",
    }


def test_release_input_resolution_never_falls_back_from_newest_finalizer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    main = MainIdentity("101", "main", COMMIT, TREE)
    controller = ProviderArtifact(
        "100", 2, "41", "controller", f"sha256:{'a' * 64}", {}
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release_inputs.resolve_main",
        lambda *args, **kwargs: main,
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release_inputs.load_authority",
        lambda *args, **kwargs: {},
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release_inputs.select_latest_admission",
        lambda *args, **kwargs: ("100", 2),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release_inputs.resolve_self_controller_artifact",
        lambda *args, **kwargs: (
            {"repository_id": "101", "commit_sha": COMMIT, "tree_sha": TREE},
            controller,
        ),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release_inputs.authority_role_workflow",
        lambda *args, **kwargs: {"workflow_id": "202"},
    )

    def reject_newest(*args: object, **kwargs: object):
        assert kwargs["run_id"] == 51
        raise GitHubControllerError("newest finalizer is failed")

    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release_inputs.authenticate_role_job_inventory",
        reject_newest,
    )
    runs = tuple(
        {
            "id": run_id, "run_attempt": 1, "head_sha": COMMIT,
            "head_branch": "main", "event": "workflow_run",
            "repository": {"id": 101}, "head_repository": {"id": 101},
        }
        for run_id in (50, 51)
    )
    api = SimpleNamespace(workflow_runs=lambda *args, **kwargs: runs)
    with pytest.raises(GitHubControllerError, match="newest finalizer is failed"):
        resolve_release_authorization_inputs(
            api, repository="owner/repo", output_path=tmp_path / "inputs.json"  # type: ignore[arg-type]
        )


def test_provider_verifier_requires_authorizer_and_build_same_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _release_inputs(tmp_path)
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.resolve_main",
        lambda api, repository: MainIdentity("101", "main", COMMIT, TREE),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.load_authority",
        lambda *args, **kwargs: {},
    )
    with pytest.raises(GitHubControllerError, match="share one attempt"):
        verify_release_build_provider(
            object(),  # type: ignore[arg-type]
            repository="owner/repo",
            authorization_path=values["authorization"],  # type: ignore[arg-type]
            build_manifest_path=values["build"],  # type: ignore[arg-type]
            manifest_path=values["manifest"],  # type: ignore[arg-type]
            lock_path=values["lock"],  # type: ignore[arg-type]
            wheelhouse=values["wheelhouse"],  # type: ignore[arg-type]
            release_artifacts=values["artifacts"],  # type: ignore[arg-type]
            verifier_run_id="30",
            verifier_run_attempt="1",
            output_path=tmp_path / "verification.json",
            runtime_report_path=values["runtime_report"],  # type: ignore[arg-type]
            runtime_evidence=values["runtime_evidence"],  # type: ignore[arg-type]
        )


def test_provider_verifier_binds_authenticated_build_and_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _release_inputs(tmp_path)
    authorization = json.loads(values["authorization"].read_text())  # type: ignore[union-attr]
    authorization["authorizer"] = {"run_id": "20", "run_attempt": 1}
    _json(values["authorization"], authorization)  # type: ignore[arg-type]
    build = json.loads(values["build"].read_text())  # type: ignore[union-attr]
    build["authorization_sha256"] = _sha(values["authorization"])  # type: ignore[arg-type]
    _json(values["build"], build)  # type: ignore[arg-type]
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.resolve_main",
        lambda api, repository: MainIdentity("101", "main", COMMIT, TREE),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.load_authority",
        lambda *args, **kwargs: {},
    )
    provider = ProviderArtifact(
        "20", 1, "40", build["artifact_name"], f"sha256:{'e' * 64}", {}
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.resolve_role_artifact",
        lambda *args, **kwargs: provider,
    )
    verifier = SimpleNamespace(
        run_id="30",
        run_attempt=2,
        workflow=_workflow(".github/workflows/bcf-release-verifier.yml", "workflow_run"),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.authenticate_role_job_inventory",
        lambda *args, **kwargs: (verifier, ()),
    )
    result = verify_release_build_provider(
        object(),  # type: ignore[arg-type]
        repository="owner/repo",
        authorization_path=values["authorization"],  # type: ignore[arg-type]
        build_manifest_path=values["build"],  # type: ignore[arg-type]
        manifest_path=values["manifest"],  # type: ignore[arg-type]
        lock_path=values["lock"],  # type: ignore[arg-type]
        wheelhouse=values["wheelhouse"],  # type: ignore[arg-type]
        release_artifacts=values["artifacts"],  # type: ignore[arg-type]
        verifier_run_id="30",
        verifier_run_attempt="2",
        output_path=tmp_path / "provider-verification.json",
        runtime_report_path=values["runtime_report"],  # type: ignore[arg-type]
        runtime_evidence=values["runtime_evidence"],  # type: ignore[arg-type]
    )
    assert result["build"]["artifact_id"] == "40"
    assert result["verifier"]["workflow"]["active_path"].endswith("verifier.yml")


def test_release_collection_rejects_an_older_same_sha_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _release_inputs(tmp_path)
    authorization = json.loads(values["authorization"].read_text())  # type: ignore[union-attr]
    authorization["authorizer"] = {"run_id": "20", "run_attempt": 1}
    _json(values["authorization"], authorization)  # type: ignore[arg-type]
    verification_path = _json(
        tmp_path / "release-verification.json",
        {
            "verifier": {"run_id": "30", "run_attempt": 1},
            "build": {"artifact_id": "40", "provider_digest": f"sha256:{'e' * 64}"},
        },
    )
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    _json(bundle / "ci-certification.json", {})
    _json(bundle / "evidence-session.json", {})
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.verify_bundle", lambda root: {}
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.resolve_main",
        lambda api, repository: MainIdentity("101", "main", COMMIT, TREE),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.load_authority",
        lambda *args, **kwargs: {},
    )
    identity = SimpleNamespace(
        run_id="50", run_attempt=1,
        workflow=_workflow(".github/workflows/bcf-release-collector.yml", "workflow_run"),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.authenticate_role_job_inventory",
        lambda *args, **kwargs: (identity, ()),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.authority_role_workflow",
        lambda authority, role: {"workflow_id": "202"},
    )
    api = SimpleNamespace(
        workflow_runs=lambda *args, **kwargs: (
            {"id": 20, "run_attempt": 1},
            {"id": 21, "run_attempt": 1},
        )
    )
    with pytest.raises(GitHubControllerError, match="newest same-run admission"):
        collect_release(
            api,  # type: ignore[arg-type]
            repository="owner/repo",
            bundle_dir=bundle,
            authorization_path=values["authorization"],  # type: ignore[arg-type]
            build_manifest_path=values["build"],  # type: ignore[arg-type]
            verification_path=verification_path,
            release_artifacts=values["artifacts"],  # type: ignore[arg-type]
            collector_run_id="50",
            collector_run_attempt="1",
            verification_artifact_name="verification",
            runtime_report_path=values["runtime_report"],  # type: ignore[arg-type]
            runtime_evidence=values["runtime_evidence"],  # type: ignore[arg-type]
            output_path=tmp_path / "receipt.json",
        )


def test_publisher_requires_collector_receipt_to_bind_exact_assets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _release_inputs(tmp_path)
    assets = values["assets"]
    receipt_path = _json(
        tmp_path / "release.evidence.json",
        {
            "kind": "release",
            "result": "passed",
            "subject": {
                "commit_sha": COMMIT,
                "tree_sha": TREE,
                "execution_tree_sha": TREE,
                "binding": "exact_tree",
                "tracked_clean": True,
                "untracked_clean": True,
                "status_porcelain_sha256": hashlib.sha256(b"").hexdigest(),
            },
            "invocation": {"workflow": {"run_id": "50", "run_attempt": "1"}},
            "observations": {
                "release_artifacts": [
                    {"path": name, "sha256": digest} for name, digest in assets.items()
                ]
            },
        },
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.resolve_main",
        lambda api, repository: MainIdentity("101", "main", COMMIT, TREE),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.load_authority",
        lambda *args, **kwargs: {},
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.authenticate_role_job_inventory",
        lambda *args, **kwargs: (object(), ()),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.authenticate_role_artifact",
        lambda *args, **kwargs: object(),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_release.publish_release",
        lambda *args, **kwargs: {"status": "published"},
    )
    result = publish_certified_release(
        object(),  # type: ignore[arg-type]
        repository="owner/repo",
        tag="v0.7.1",
        expected_commit=COMMIT,
        release_artifacts=values["artifacts"],  # type: ignore[arg-type]
        body="notes",
        receipt_path=receipt_path,
        receipt_artifact_id="70",
        receipt_artifact_name="receipt",
        receipt_provider_digest=f"sha256:{'f' * 64}",
        publisher_run_id="80",
        publisher_run_attempt="1",
    )
    assert result == {"status": "published"}
    receipt = json.loads(receipt_path.read_text())
    receipt["observations"]["release_artifacts"][0]["sha256"] = "0" * 64
    _json(receipt_path, receipt)
    with pytest.raises(GitHubControllerError, match="bind exact publication assets"):
        publish_certified_release(
            object(),  # type: ignore[arg-type]
            repository="owner/repo",
            tag="v0.7.1",
            expected_commit=COMMIT,
            release_artifacts=values["artifacts"],  # type: ignore[arg-type]
            body="notes",
            receipt_path=receipt_path,
            receipt_artifact_id="70",
            receipt_artifact_name="receipt",
            receipt_provider_digest=f"sha256:{'f' * 64}",
            publisher_run_id="80",
            publisher_run_attempt="1",
        )

    receipt["observations"]["release_artifacts"][0]["sha256"] = values["assets"][  # type: ignore[index]
        receipt["observations"]["release_artifacts"][0]["path"]  # type: ignore[index]
    ]
    receipt["observations"]["release_artifacts"].append(  # type: ignore[index]
        dict(receipt["observations"]["release_artifacts"][0])  # type: ignore[index]
    )
    _json(receipt_path, receipt)
    with pytest.raises(GitHubControllerError, match="bind exact publication assets"):
        publish_certified_release(
            object(),  # type: ignore[arg-type]
            repository="owner/repo",
            tag="v0.7.1",
            expected_commit=COMMIT,
            release_artifacts=values["artifacts"],  # type: ignore[arg-type]
            body="notes",
            receipt_path=receipt_path,
            receipt_artifact_id="70",
            receipt_artifact_name="receipt",
            receipt_provider_digest=f"sha256:{'f' * 64}",
            publisher_run_id="80",
            publisher_run_attempt="1",
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

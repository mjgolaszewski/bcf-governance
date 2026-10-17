"""Historical phase inputs require independent provider finalizer custody."""

from copy import deepcopy
import hashlib
from io import BytesIO
import json
from pathlib import Path
import zipfile

import pytest

from bcf_governance.tooling import ci_github_exact_main, trusted_inputs
from bcf_governance.tooling.ci_authority_certification import verify_ci_certification
from bcf_governance.tooling.ci_github_authority import packaged_repo_root
from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from tests.test_ci_github_controller import (
    FakeAPI, SHA_A, SHA_B, TREE, _controller_custody, _prepare_v11_run,
)


class PhaseAPI(FakeAPI):
    """Extend the existing exact-main fixture only at provider artifact ports."""

    archive = b""
    reads = 0
    moved = False
    missing = False
    expired = False
    digest_substituted = False
    outside_default_lineage = False
    later_failed = False
    rewritten = False
    later_failed_after_read = False
    artifact_changed_after_read = False

    def workflow_runs(self, repository, workflow_id, *, head_sha, event):
        if str(workflow_id) == "98":
            assert event == "workflow_run" and head_sha == SHA_A
            values = [dict(self.runs["400"])]
            if self.later_failed:
                values.append({**values[0], "id": 401, "conclusion": "failure"})
                self.runs["401"] = values[-1]
                self.run_job_names["401"] = ("Finalize",)
            return tuple(values)
        return super().workflow_runs(
            repository, workflow_id, head_sha=head_sha, event=event,
        )

    def compare_commits(self, repository, *, base, head):
        assert repository == "owner/repo" and base == SHA_A
        return {
            "status": "diverged" if self.outside_default_lineage else "ahead",
            "base_commit": {"sha": base},
            "merge_base_commit": {"sha": SHA_B if self.outside_default_lineage else base},
        }

    def artifacts(self, repository, run_id):
        if str(run_id) != "400":
            return super().artifacts(repository, run_id)
        if self.missing:
            return ()
        return ({
            "id": 800, "name": "bcf-exact-main-certification-400-1",
            "expired": self.expired,
            "digest": "sha256:" + (
                "0" * 64 if self.digest_substituted else hashlib.sha256(self.archive).hexdigest()
            ),
            "workflow_run": {
                "id": 400, "repository_id": 42, "head_repository_id": 42,
                "head_branch": "main", "head_sha": SHA_A,
            },
        },)

    def artifact_bytes(self, repository, artifact_id, *, maximum_bytes):
        if str(artifact_id) != "800":
            return super().artifact_bytes(repository, artifact_id, maximum_bytes=maximum_bytes)
        assert len(self.archive) <= maximum_bytes
        self.reads += 1
        if self.moved:
            self.main = SHA_B
        if self.later_failed_after_read:
            self.later_failed = True
        if self.artifact_changed_after_read:
            self.digest_substituted = True
        return self.archive

    def commit(self, repository, sha):
        value = super().commit(repository, sha)
        if self.rewritten and sha == SHA_A:
            value["tree"] = {"sha": SHA_B}
        return value


@pytest.fixture
def phase_input(tmp_path, monkeypatch):
    monkeypatch.setattr(ci_github_exact_main, "resolve_effective_controller", lambda *a, **kw: {})
    monkeypatch.setattr(
        ci_github_exact_main, "authenticate_admission_custody",
        lambda *a, main, **kw: _controller_custody(main),
    )
    api = PhaseAPI()
    _prepare_v11_run(api)
    result = ci_github_exact_main.finalize_exact_main(
        api, repository="owner/repo", collector_run_id=400,
        collector_run_attempt=1, output_dir=tmp_path / "bundle",
    )
    assert result.computed_state == "certified"
    api.runs["400"].update(status="completed", conclusion="success")
    api.run_job_names["400"] = ("Finalize",)
    root = Path(result.bundle_dir)
    files = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    _archive(api, files)
    api.reads = 0
    return api, files


def _archive(api, files):
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, raw in sorted(files.items()):
            archive.writestr(name, raw)
    api.archive = stream.getvalue()


def _verify(api, **kw):
    return trusted_inputs.verify_phase_closure_input(
        api, repository="owner/repo", phase_id=kw.get("phase_id", "P01"),
        source_commit=kw.get("source_commit", SHA_A), source_tree=kw.get("source_tree", TREE),
    )


def test_phase_input_reconstructs_provider_custody_and_returns_original_bytes(phase_input):
    api, _ = phase_input
    artifact, verification, raw = _verify(api)
    assert artifact.artifact_id == "800" and artifact.run_id == "400"
    assert verification.status == "pass" and verification.computed_state == "certified"
    assert verification.certified_proposition["target"] == {"kind": "phase", "id": "P01"}
    assert raw == api.archive and api.reads == 1


@pytest.mark.parametrize("mutation", [
    "missing", "expired", "digest_substituted", "outside_default_lineage",
    "later_failed", "moved", "rewritten",
    "later_failed_after_read", "artifact_changed_after_read",
])
def test_phase_input_rejects_uncertain_or_changed_provider_facts(phase_input, mutation):
    api, _ = phase_input
    setattr(api, mutation, True)
    with pytest.raises(GitHubControllerError):
        _verify(api)
    if mutation not in {
        "digest_substituted", "moved", "later_failed_after_read", "artifact_changed_after_read",
    }:
        assert api.reads == 0


@pytest.mark.parametrize("mutation", ["authority", "missing_file", "phase", "subject", "session_run"])
def test_provider_digest_alone_cannot_authorize_substituted_bundle(phase_input, mutation):
    api, original = phase_input
    files = deepcopy(original)
    if mutation == "missing_file":
        del files["raw/governance.json"]
    else:
        name = "ci-authority.json" if mutation == "authority" else "ci-certification.json"
        value = json.loads(files[name])
        if mutation == "authority":
            value["repository"]["repository_id"] = "999"
        elif mutation == "phase":
            value["evaluation_scope"]["target"]["id"] = "P99"
        elif mutation == "subject":
            value["subject"]["tree_sha"] = SHA_B
        else:
            value["evidence_session"]["run_id"] = "999"
        files[name] = json.dumps(value).encode()
        manifest = json.loads(files["bundle-manifest.json"])
        manifest["files"][name] = hashlib.sha256(files[name]).hexdigest()
        files["bundle-manifest.json"] = json.dumps(manifest).encode()
    _archive(api, files)
    with pytest.raises(GitHubControllerError):
        _verify(api)


def test_phase_input_has_no_candidate_schema_root_argument(phase_input, monkeypatch, tmp_path):
    api, _ = phase_input
    roots = []
    original = trusted_inputs.packaged_repo_root
    def packaged():
        root = original()
        roots.append(root)
        return root
    monkeypatch.setattr(trusted_inputs, "packaged_repo_root", packaged)
    monkeypatch.chdir(tmp_path)
    _verify(api)
    assert roots and all(root == original() for root in roots)


def test_real_other_phase_certificate_cannot_satisfy_expected_phase(phase_input):
    api, _ = phase_input
    with pytest.raises(GitHubControllerError, match="terminal scope"):
        _verify(api, phase_id="P99")


def test_wrong_repository_rejects_before_artifact_download(phase_input, monkeypatch):
    api, _ = phase_input
    monkeypatch.setattr(api, "repository", lambda repo: {
        "full_name": "other/repo", "id": 42, "default_branch": "main",
    })
    with pytest.raises(GitHubControllerError, match="repository identity"):
        _verify(api)
    assert api.reads == 0


def test_missing_trusted_sdk_schemas_rejects_before_provider_work(phase_input, monkeypatch):
    api, _ = phase_input
    calls = []
    original = api.repository
    def repository(name):
        calls.append(name)
        return original(name)
    def missing():
        raise GitHubControllerError("installed BCF package lacks CI authority schemas")
    monkeypatch.setattr(api, "repository", repository)
    monkeypatch.setattr(trusted_inputs, "packaged_repo_root", missing)
    with pytest.raises(GitHubControllerError, match="lacks CI authority schemas"):
        _verify(api)
    assert calls == [] and api.reads == 0


@pytest.mark.parametrize("kw", [
    {"phase_id": " P01"}, {"phase_id": "p01"}, {"phase_id": None},
    {"phase_id": "P01:closure"}, {"source_commit": "main"}, {"source_tree": "b" * 39},
])
def test_invalid_phase_coordinates_reject_before_provider_work(kw):
    class NoProviderCalls:
        def __getattr__(self, name):
            raise AssertionError(f"invalid coordinates reached provider: {name}")
    with pytest.raises(GitHubControllerError):
        _verify(NoProviderCalls(), **kw)


def _certified_substitution(files, root):
    """Rehash every modified byte, then prove normalized verification still passes."""
    manifest = json.loads(files["bundle-manifest.json"])
    for name in manifest["files"]:
        manifest["files"][name] = hashlib.sha256(files[name]).hexdigest()
    files["bundle-manifest.json"] = json.dumps(manifest).encode()
    root.mkdir()
    for name, raw in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    result = verify_ci_certification(
        packaged_repo_root(), authority_path=root / "ci-authority.json",
        certification_path=root / "ci-certification.json",
        session_manifest_path=root / "evidence-session.json",
    )
    assert result.status == "pass" and result.computed_state == "certified"


def test_valid_normalized_certificate_from_other_collector_cannot_authorize_input(phase_input, tmp_path):
    api, original = phase_input
    files = deepcopy(original)
    session = json.loads(files["evidence-session.json"])
    session["producer"]["run_id"] = "999"
    files["evidence-session.json"] = json.dumps(session).encode()
    report = json.loads(files["ci-certification.json"])
    report["evidence_session"]["run_id"] = "999"
    report["evidence_session"]["manifest_sha256"] = hashlib.sha256(files["evidence-session.json"]).hexdigest()
    files["ci-certification.json"] = json.dumps(report).encode()
    _certified_substitution(files, tmp_path / "other-collector")
    _archive(api, files)
    with pytest.raises(GitHubControllerError, match="provider finalizer"):
        _verify(api)


@pytest.mark.parametrize("intent", ["pr", "workitem"])
def test_valid_nonphase_proposition_cannot_authorize_phase_input(phase_input, tmp_path, intent):
    api, original = phase_input
    files = deepcopy(original)
    target = (
        {"kind": "pull_request_progress", "id": SHA_A} if intent == "pr"
        else {"kind": "workitem", "id": "P01-W01"}
    )
    report = json.loads(files["ci-certification.json"])
    truth = json.loads(files["governance-truth.json"])
    for value in (report, truth):
        value["evaluation_scope"] = {"intent": intent, "target": target}
        value["certified_proposition"] = {
            "predicate": "pull_request_progress_valid" if intent == "pr" else "workitem_closed",
            "target": target, "subject": {"commit_sha": SHA_A, "tree_sha": TREE},
            "conclusion": "success", "eligible_successors": [],
            "authorizes": [] if intent == "pr" else ["declared_successor_workitem_eligibility"],
        }
    files["governance-truth.json"] = json.dumps(truth).encode()
    report["governance_truth"]["report_sha256"] = hashlib.sha256(files["governance-truth.json"]).hexdigest()
    files["ci-certification.json"] = json.dumps(report).encode()
    _certified_substitution(files, tmp_path / intent)
    _archive(api, files)
    with pytest.raises(GitHubControllerError, match="terminal scope"):
        _verify(api)

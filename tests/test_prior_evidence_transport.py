from __future__ import annotations

from dataclasses import asdict
import copy
import hashlib
from io import BytesIO
import json
from pathlib import Path
import zipfile

from jsonschema import Draft202012Validator, RefResolver
import pytest
import yaml

from bcf_governance.tooling.ci_authority_state import CandidateIdentity, WorkflowIdentity
from bcf_governance.tooling.ci_github import GithubRunIdentity
from bcf_governance.tooling.ci_github_api import GitHubAPI
from bcf_governance.tooling.ci_github_identity import GitHubControllerError
from bcf_governance.tooling.github_protection import desired_ruleset
from bcf_governance.tooling.prior_evidence_transport import transport_prior_evidence


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "mjgolaszewski/bcf-governance"
REPOSITORY_ID = "1207503211"
MAIN = "a" * 40
BASE = "b" * 40
HEAD = "c" * 40
EXECUTION = "d" * 40
TREE = "e" * 40
BASE_TREE = "f" * 40
SESSION = "1" * 40
DIGEST = "2" * 64


def _json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True) + "\n").encode()


def _zip(files: dict[str, bytes]) -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for path, raw in sorted(files.items()):
            archive.writestr(path, raw)
    return stream.getvalue()


def _identity(run_id: str, workflow_id: str, path: str, event: str,
              candidate: CandidateIdentity) -> GithubRunIdentity:
    return GithubRunIdentity(
        workflow=WorkflowIdentity(
            provider="github", repository_id=REPOSITORY_ID,
            workflow_id=workflow_id, active_path=path,
            trusted_workflow_blob_oid="3" * 40,
            trusted_workflow_sha256="4" * 64,
            trusted_workflow_definition_commit=BASE, event=event,
        ),
        candidate=candidate, run_id=run_id, run_attempt=1,
    )


class Provider:
    def __init__(self) -> None:
        self.candidate = CandidateIdentity(HEAD, TREE)
        self.finalizer = _identity(
            "50", "105", ".github/workflows/bcf-pr-finalizer.yml",
            "workflow_run", CandidateIdentity(BASE, BASE_TREE),
        )
        self.producer = _identity(
            "30", "106", ".github/workflows/governance.yml",
            "pull_request", self.candidate,
        )
        self.protection = yaml.safe_load(
            (ROOT / "governance/github-protection.yml").read_text(encoding="utf-8")
        )
        session = {
            "schema_version": "2.0", "session_id": SESSION,
            "subject": {"commit_sha": EXECUTION, "tree_sha": TREE},
            "profile": "standard", "profile_contract_version": "3.0",
            "producer": {
                "kind": "workflow", "producer_id": "preflight",
                "provider": "github-actions", "repository": REPOSITORY,
                "repository_id": REPOSITORY_ID, "run_id": "30", "run_attempt": "1",
            },
            "expected_gate_inventory": ["test"],
            "expected_producer_inventory": ["evidence"],
            "preflight_satisfied_claims": [],
        }
        session_raw = _json(session)
        self.receipt = {
            "schema_version": "2.0", "kind": "test_suite",
            "evidence_id": "test-source", "gate_id": "test", "claims": ["test"],
            "producer": {"kind": "workflow", "id": "governance"},
            "invocation": {
                "argv": ["python", "test"], "cwd": ".", "environment": {},
                "workflow": {
                    "provider": "github-actions", "path": f"{REPOSITORY}/governance.yml",
                    "job": "evidence", "run_id": "30", "run_attempt": "1",
                    "matrix": {"gate": "test"},
                },
            },
            "subject": {
                "commit_sha": EXECUTION, "tree_sha": TREE,
                "execution_tree_sha": TREE, "binding": "exact_tree",
                "tracked_clean": True, "untracked_clean": True,
                "status_porcelain_sha256": hashlib.sha256(b"").hexdigest(),
            },
            "artifacts": [{
                "path": "evidence-session.json",
                "media_type": "application/vnd.bcf.evidence-session+json",
                "sha256": hashlib.sha256(session_raw).hexdigest(),
            }],
            "observations": {"exit_code": 0},
            "behavioral_probes": [{
                "id": "negative", "mutation_applied": True,
                "oracle": {}, "oracle_observation": {},
                "observed_exit_code": 1, "raw_artifacts": {},
            }],
            "result": "passed", "started_at": "2026-09-20T00:00:00Z",
            "timestamp": "2026-09-20T00:00:01Z",
        }
        truth = {
            "schema_version": "3.0", "status": "pass",
            "subject": {
                "commit_sha": EXECUTION, "tree_sha": TREE,
                "tracked_clean": True, "untracked_clean": True,
            },
            "certified_proposition": {
                "conclusion": "success", "authorizes": [], "eligible_successors": [],
                "predicate": "pull_request_progress_valid",
                "subject": {"commit_sha": EXECUTION, "tree_sha": TREE},
                "target": {"kind": "pull_request_progress", "id": EXECUTION},
            },
        }
        self.archives = {
            "bcf-session-30-1": _zip({f"{SESSION}/evidence-session.json": session_raw}),
            "bcf-governance-truth-30-1": _zip({"truth-report.json": _json(truth)}),
            "bcf-evidence-30-1-shard-0": _zip({
                f"{SESSION}/evidence-session.json": session_raw,
                f"{SESSION}/test/evidence-session.json": session_raw,
                f"{SESSION}/test/test.evidence.json": _json(self.receipt),
            }),
            **{
                f"bcf-evidence-30-1-shard-{index}": _zip(
                    {f"{SESSION}/evidence-session.json": session_raw}
                ) for index in range(1, 4)
            },
        }
        observation = {
            "schema_version": "1.0", "kind": "pr_certification_observation",
            "repository": {"full_name": REPOSITORY, "numeric_id": int(REPOSITORY_ID)},
            "pull_request": 7,
            "subject": {"commit_sha": HEAD, "tree_sha": TREE, "branch": "feature"},
            "computed_state": "successful",
            "producers": [{
                "id": "governance", "state": "successful",
                "reason": "all_required_jobs_green", "run_id": "30", "run_attempt": 1,
                "workflow": asdict(self.producer.workflow),
            }],
            "finalizer": {
                "run_id": "50", "run_attempt": 1,
                "workflow": asdict(self.finalizer.workflow),
            },
        }
        observation_raw = _json(observation)
        self.archives["bcf-pr-finalization-50-1"] = _zip({
            "pr-observation.json": observation_raw,
            "bundle-manifest.json": _json({
                "schema_version": "1.0", "kind": "pr_certification_observation",
                "subject": observation["subject"], "computed_state": "successful",
                "files": {"pr-observation.json": hashlib.sha256(observation_raw).hexdigest()},
            }),
        })
        self.records: dict[str, dict[str, object]] = {}
        for artifact_id, (name, raw) in enumerate(sorted(self.archives.items()), start=900):
            finalizer = name.startswith("bcf-pr-finalization")
            self.records[name] = {
                "id": artifact_id, "name": name, "expired": False,
                "digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
                "workflow_run": {
                    "id": 50 if finalizer else 30,
                    "repository_id": int(REPOSITORY_ID),
                    "head_repository_id": int(REPOSITORY_ID),
                    "head_branch": "main" if finalizer else "feature",
                    "head_sha": BASE if finalizer else HEAD,
                },
            }

    def repository(self, repository: str) -> dict[str, object]:
        return {"id": int(REPOSITORY_ID), "default_branch": "main"}

    def reference(self, repository: str, ref: str) -> dict[str, object]:
        return {"object": {"type": "commit", "sha": MAIN}}

    def commit(self, repository: str, sha: str) -> dict[str, object]:
        trees = {MAIN: TREE, HEAD: TREE, EXECUTION: TREE, BASE: BASE_TREE}
        return {"tree": {"sha": trees[sha]}}

    def commit_pull_requests(self, repository: str, *, sha: str):
        return (self.pull_request(repository, 7),)

    def pull_request(self, repository: str, number: object) -> dict[str, object]:
        repo = {"id": int(REPOSITORY_ID)}
        return {
            "number": 7, "state": "closed", "merged_at": "2026-09-20T00:02:00Z",
            "merge_commit_sha": MAIN, "merged_by": None,
            "head": {"sha": HEAD, "ref": "feature", "repo": repo},
            "base": {"sha": BASE, "ref": "main", "repo": repo},
        }

    def check_runs(self, repository: str, *, sha: str):
        return ({
            "id": 80, "name": "bcf/pr-certification", "head_sha": HEAD,
            "status": "completed", "conclusion": "success",
            "completed_at": "2026-09-20T00:01:00Z",
            "external_id": "bcf-pr-certification:50:1", "app": {"id": 15368},
        },)

    def artifacts(self, repository: str, run_id: str | int):
        finalizer = str(run_id) == "50"
        return tuple(
            copy.deepcopy(value) for name, value in self.records.items()
            if name.startswith("bcf-pr-finalization") == finalizer
        )

    def artifact_bytes(self, repository: str, artifact_id: object, *, maximum_bytes: int):
        record = next(
            value for value in self.records.values()
            if str(value["id"]) == str(artifact_id)
        )
        return self.archives[str(record["name"])]

    def jobs(self, repository: str, run_id: object, *, attempt: int):
        names = [
            "Validate governance front door", "bcf/pr-certification",
            "Verify exact-tree governance evidence",
            "Evidence / Boundaries, contracts, runtime, types, and secrets",
            "Evidence / CQRS, module size, exposure, and dependency risk",
            "Evidence / Duplication, routers, governance, and ownership",
            "Evidence / Full tests, lint, import boundaries, and SBOM",
        ]
        return tuple(
            {"name": name, "status": "completed", "conclusion": "success"}
            for name in names
        )

    def content(self, repository: str, path: str, *, ref: str):
        from bcf_governance.tooling.ci_github_api import GitHubContent

        if path == "governance/ci-graph.yml":
            raw = (ROOT / path).read_bytes()
        elif path == "governance/github-protection.yml":
            raw = yaml.safe_dump(self.protection, sort_keys=False).encode()
        elif path == "governance/self-governance-policy.yml":
            raw = yaml.safe_dump({
                "runner_security": {
                    "trusted_controller_artifact": {
                        "BCF_BOOTSTRAP_COMMIT_SHA": "9" * 40,
                        "BCF_BOOTSTRAP_WHEEL_SHA256": DIGEST,
                    },
                    "trusted_controller_installation": {
                        "installed_commit_sha": "9" * 40,
                    },
                }
            }).encode()
        else:
            raw = b"name: trusted\n"
        return GitHubContent(path=path, blob_oid="8" * 40, content=raw)

    def repository_rulesets(self, repository: str):
        return ({"id": 70, "name": self.protection["ruleset"]["name"]},)

    def ruleset(self, repository: str, ruleset_id: object):
        return {"id": 70, **desired_ruleset(self.protection)}


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> Provider:
    value = Provider()

    def authenticate(_api, *, run_id, **_kwargs):
        return value.finalizer if str(run_id) == "50" else value.producer

    monkeypatch.setattr(
        "bcf_governance.tooling.prior_evidence_transport.authenticate_trusted_run",
        authenticate,
    )
    return value


def test_transport_authenticates_and_preserves_exact_source_bytes(
    provider: Provider, tmp_path: Path,
) -> None:
    output = tmp_path / "transport"
    manifest = transport_prior_evidence(
        provider, repository=REPOSITORY, expected_main_sha=MAIN, output_root=output
    )
    assert manifest["candidate"] == {"commit_sha": HEAD, "tree_sha": TREE}
    assert manifest["main"] == {"commit_sha": MAIN, "tree_sha": TREE}
    assert manifest["merge"]["candidate_tree_equals_main_tree"] is True
    assert manifest["authority"]["controller_commit_sha"] == "9" * 40
    assert {value["role"] for value in manifest["artifacts"]} == {
        "certification", "session", "evidence", "truth"
    }
    source = _json(provider.receipt)
    receipt = manifest["receipts"][0]
    preserved = output / "expanded" / receipt["artifact_id"] / receipt["path"]
    assert preserved.read_bytes() == source
    schema = json.loads(
        (ROOT / "schemas/prior-evidence-transport.schema.json").read_text()
    )
    resolver = RefResolver(
        (ROOT / "schemas/prior-evidence-transport.schema.json").resolve().as_uri(),
        schema,
    )
    Draft202012Validator(schema, resolver=resolver).validate(manifest)
    assert not ({"decision", "qualification", "dependency_closure"} & set(manifest))


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda api: api.records["bcf-evidence-30-1-shard-0"].update(
            {"digest": "sha256:" + "0" * 64}), "provider digest"),
        (lambda api: api.records["bcf-evidence-30-1-shard-0"]["workflow_run"].update(
            {"head_sha": "0" * 40}), "provider identity"),
        (lambda api: api.protection["ruleset"].update({"bypass_actors": [{"id": 1}]}),
         "schema violation"),
    ],
)
def test_transport_rejects_substituted_artifact_or_authority(
    provider: Provider, tmp_path: Path, mutation, message: str,
) -> None:
    mutation(provider)
    with pytest.raises(GitHubControllerError, match=message):
        transport_prior_evidence(
            provider, repository=REPOSITORY, expected_main_sha=MAIN,
            output_root=tmp_path / "transport",
        )


def test_transport_rejects_replay_after_main_advances(
    provider: Provider, tmp_path: Path,
) -> None:
    with pytest.raises(GitHubControllerError, match="provider main moved"):
        transport_prior_evidence(
            provider, repository=REPOSITORY, expected_main_sha="0" * 40,
            output_root=tmp_path / "transport",
        )


def test_transport_rejects_unrelated_receipt_subject(
    provider: Provider, tmp_path: Path,
) -> None:
    name = "bcf-evidence-30-1-shard-0"
    with zipfile.ZipFile(BytesIO(provider.archives[name])) as archive:
        files = {path: archive.read(path) for path in archive.namelist()}
    provider.receipt["subject"]["tree_sha"] = "0" * 40
    provider.receipt["subject"]["execution_tree_sha"] = "0" * 40
    files[f"{SESSION}/test/test.evidence.json"] = _json(provider.receipt)
    provider.archives[name] = _zip(files)
    provider.records[name]["digest"] = "sha256:" + hashlib.sha256(
        provider.archives[name]
    ).hexdigest()
    with pytest.raises(GitHubControllerError, match="subject or invocation"):
        transport_prior_evidence(
            provider, repository=REPOSITORY, expected_main_sha=MAIN,
            output_root=tmp_path / "transport",
        )


def test_commit_pull_request_lookup_is_exact_commit_scoped() -> None:
    class RecordingAPI(GitHubAPI):
        def __init__(self) -> None:
            super().__init__(token="test")
            self.path = ""

        def _request(self, method: str, path: str, *, payload=None):  # type: ignore[no-untyped-def]
            self.path = path
            return [{"number": 7}]

    api = RecordingAPI()
    assert api.commit_pull_requests("owner/repo", sha=MAIN) == ({"number": 7},)
    assert api.path == f"/repos/owner/repo/commits/{MAIN}/pulls?per_page=100"

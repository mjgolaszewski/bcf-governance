from __future__ import annotations

import json
import io
from pathlib import Path
from types import SimpleNamespace
import zipfile

from jsonschema import Draft202012Validator, ValidationError
import pytest
import yaml

from bcf_governance.tooling import break_glass_recovery as recovery
from bcf_governance.tooling.ci_github_identity import GitHubControllerError, MainIdentity


ROOT = Path(__file__).resolve().parents[1]
OPERATION = "1" * 32
COMMIT = "a" * 40
TREE = "b" * 40
APP_ID = "4966894"
INSTALLATION_ID = "162228881"
WORKFLOW_ID = "359360291"
OWNER = "mjgolaszewski"
OWNER_ID = "202175348"


def recovery_receipt() -> dict[str, object]:
    jobs = {
        "one": {"id": "11", "runner_name": "runner-one"},
        "two": {"id": "12", "runner_name": "runner-two"},
    }
    confirmation = {
        "schema_version": "1.0", "installed_commit_sha": COMMIT,
        "subject_commit_sha": COMMIT, "subject_tree_sha": TREE,
        "bootstrap_run_id": "20", "bootstrap_run_attempt": "1",
        "probe_run_id": "30", "probe_run_attempt": "1",
    }
    return {
        "schema_version": "1.0", "operation_id": OPERATION,
        "reason_code": "ordinary_control_plane_bootstrap_deadlock",
        "repository": {"id": "1207503211", "name": "mjgolaszewski/bcf-governance", "branch": "main"},
        "actor": {"login": OWNER, "id": OWNER_ID, "permission": "admin", "app_id": APP_ID, "installation_id": INSTALLATION_ID, "identity_semantics": {"app_id": "configured-token-mint-binding", "installation_id": "configured-expected-not-token-observed", "repository_scope": "provider-installation-token-repository-inventory"}, "workflow_id": WORKFLOW_ID, "run_id": "30", "run_attempt": "1"},
        "pre_recovery_controller": "c" * 40,
        "subject": {"commit": COMMIT, "tree": TREE},
        "builder": {"workflow": ".github/workflows/bcf-break-glass-recovery.yml", "job": "Build exact-main recovery controller", "job_id": "10", "run_id": "10", "run_attempt": "1"},
        "artifact": {"id": "99", "name": f"bcf-break-glass-recovery-build-{OPERATION}", "provider_digest": f"sha256:{'d' * 64}", "wheel_sha256": "e" * 64, "checksum_inventory": {"CONTROL-METADATA.json": "f" * 64, "bcf_governance.whl": "1" * 64}, "checksum_inventory_sha256": "2" * 64, "control_metadata": {str(index): "value" for index in range(10)}},
        "install": {"run_id": "20", "run_attempt": "1", "jobs": jobs},
        "probe": {"run_id": "30", "run_attempt": "1", "jobs": jobs},
        "controller_confirmation": confirmation,
        "resulting_installed_controller": COMMIT,
        "provider_timestamps": {"builder_created_at": "2026-09-16T00:00:00Z", "install_created_at": "2026-09-16T00:01:00Z", "probe_created_at": "2026-09-16T00:02:00Z"},
        "recovery_only": True, "governance_certified": False,
        "created_at": "2026-09-16T00:03:00Z",
    }


class Provider:
    def __init__(
        self, *, permission: str = "admin", active: int = 1,
        receipt: bool = False, repositories: tuple[dict[str, object], ...] | None = None,
        actor: str = OWNER, actor_id: str = OWNER_ID,
    ):
        self.permission = permission
        self.active = active
        self.receipt = receipt
        self.repositories = repositories if repositories is not None else (
            {"id": 1207503211, "full_name": "mjgolaszewski/bcf-governance"},
        )
        self.actor = actor
        self.actor_id = actor_id

    def installation(self):
        raise AssertionError("installation access tokens must not call GET /installation")

    def installation_repositories(self):
        return self.repositories

    def run(self, _repository, run_id):
        return {
            "id": int(run_id), "run_attempt": 1, "event": "workflow_dispatch",
            "head_sha": COMMIT, "head_branch": "main", "workflow_id": int(WORKFLOW_ID),
            "path": ".github/workflows/bcf-break-glass-recovery.yml",
            "actor": {"login": self.actor, "id": int(self.actor_id)},
        }

    def user(self, login):
        return {"login": login, "id": int(self.actor_id)}

    def collaborator_permission(self, _repository, _login):
        return {"permission": self.permission}

    def workflow_runs(self, *_args, **_kwargs):
        return tuple({"id": 505 + index, "status": "in_progress"} for index in range(self.active))

    def repository_artifacts(self, _repository, *, name=None):
        if self.receipt and name and "receipt" in name:
            return ({"id": 606, "name": name, "expired": False},)
        return ()


@pytest.fixture(autouse=True)
def environment(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "BCF_BREAK_GLASS_APP_ID": APP_ID,
        "BCF_BREAK_GLASS_INSTALLATION_ID": INSTALLATION_ID,
        "BCF_BREAK_GLASS_WORKFLOW_ID": WORKFLOW_ID,
        "GITHUB_ACTOR": OWNER,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ID": "505",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SHA": COMMIT,
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(
        recovery, "resolve_main", lambda *_args: MainIdentity("1207503211", "main", COMMIT, TREE)
    )


def authorize(provider: Provider, tmp_path: Path):
    return recovery.authorize_build(
        provider, root=ROOT, repository="mjgolaszewski/bcf-governance",
        operation_id=OPERATION, reason_code="ordinary_control_plane_bootstrap_deadlock",
        output=tmp_path / "authorization.json",
    )


def test_live_installation_token_shape_authorizes_exact_repository_and_owner(
    tmp_path: Path,
) -> None:
    result = authorize(Provider(), tmp_path)
    assert result["status"] == "recovery_build_authorized"
    assert result["subject"] == {"commit": COMMIT, "tree": TREE}
    assert result["actor"]["permission"] == "admin"
    assert result["actor"]["identity_semantics"]["installation_id"] == (
        "configured-expected-not-token-observed"
    )


@pytest.mark.parametrize(
    "repositories",
    [
        (),
        ({"id": 9, "full_name": "mjgolaszewski/bcf-governance"},),
        ({"id": 1207503211, "full_name": "other/repo"},),
        (
            {"id": 1207503211, "full_name": "mjgolaszewski/bcf-governance"},
            {"id": 9, "full_name": "other/repo"},
        ),
    ],
)
def test_installation_token_repository_scope_must_be_exact(
    repositories: tuple[dict[str, object], ...], tmp_path: Path
) -> None:
    provider = Provider(repositories=repositories)
    provider.repositories = repositories
    with pytest.raises(GitHubControllerError, match="repository scope is not exact"):
        authorize(provider, tmp_path)


def test_policy_and_provider_actor_must_both_match(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("GITHUB_ACTOR", "other-admin")
    with pytest.raises(GitHubControllerError, match="repository administrator"):
        authorize(
            Provider(actor="other-admin", actor_id="999", permission="admin"), tmp_path
        )


def test_wrong_provider_run_actor_rejects_before_authority(tmp_path: Path) -> None:
    with pytest.raises(GitHubControllerError, match="workflow/run/actor"):
        authorize(Provider(actor="other-admin", actor_id="999"), tmp_path)


def test_historical_failed_operation_nonce_is_retired(tmp_path: Path) -> None:
    with pytest.raises(GitHubControllerError, match="retired failed evidence"):
        recovery.authorize_build(
            Provider(), root=ROOT, repository="mjgolaszewski/bcf-governance",
            operation_id="4aa49c3ab6a100df627619d23c1df483",
            reason_code="ordinary_control_plane_bootstrap_deadlock",
            output=tmp_path / "authorization.json",
        )


@pytest.mark.parametrize(
    ("variable", "value", "message"),
    [
        ("GITHUB_EVENT_NAME", "pull_request", "owner-dispatched"),
        ("GITHUB_EVENT_NAME", "push", "owner-dispatched"),
        ("GITHUB_EVENT_NAME", "workflow_run", "owner-dispatched"),
        ("GITHUB_EVENT_NAME", "schedule", "owner-dispatched"),
        ("GITHUB_REF", "refs/pull/1/merge", "owner-dispatched"),
        ("GITHUB_SHA", "c" * 40, "current main"),
        ("GITHUB_ACTOR", "caller-supplied", "workflow/run/actor"),
        ("BCF_BREAK_GLASS_APP_ID", "999", "configured recovery App"),
        ("BCF_BREAK_GLASS_INSTALLATION_ID", "999", "configured recovery App"),
        ("BCF_BREAK_GLASS_WORKFLOW_ID", "999", "configured recovery workflow"),
        ("GITHUB_RUN_ATTEMPT", "2", "workflow/run/actor"),
    ],
)
def test_untrusted_invocation_identities_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, variable: str, value: str, message: str
) -> None:
    monkeypatch.setenv(variable, value)
    with pytest.raises(GitHubControllerError, match=message):
        authorize(Provider(), tmp_path)


def test_non_admin_concurrent_and_replayed_recovery_reject(tmp_path: Path) -> None:
    with pytest.raises(GitHubControllerError, match="administrator"):
        authorize(Provider(permission="write"), tmp_path)
    with pytest.raises(GitHubControllerError, match="singleton"):
        authorize(Provider(active=2), tmp_path)
    with pytest.raises(GitHubControllerError, match="replayed"):
        authorize(Provider(receipt=True), tmp_path)


def test_archive_rejects_traversal_symlinks_and_invalid_bytes(tmp_path: Path) -> None:
    traversal = io.BytesIO()
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../controller.whl", b"unsafe")
    with pytest.raises(GitHubControllerError, match="path is unsafe"):
        recovery._safe_archive(traversal.getvalue(), tmp_path / "traversal")

    symlink = io.BytesIO()
    with zipfile.ZipFile(symlink, "w") as archive:
        member = zipfile.ZipInfo("controller-link")
        member.external_attr = 0o120777 << 16
        archive.writestr(member, "target")
    with pytest.raises(GitHubControllerError, match="special file"):
        recovery._safe_archive(symlink.getvalue(), tmp_path / "symlink")

    with pytest.raises(GitHubControllerError, match="archive is invalid"):
        recovery._safe_archive(b"not-a-zip", tmp_path / "invalid")


@pytest.mark.parametrize(
    ("artifacts", "message"),
    [
        ([], "not unique"),
        ([{"id": 1, "expired": True}], "not unique"),
        ([{"id": 1, "expired": False}, {"id": 2, "expired": False}], "not unique"),
        ([{"id": 10425078154, "expired": False}], "forensic artifact"),
        ([{"id": 1, "expired": False, "digest": "caller-value"}], "provider digest"),
    ],
)
def test_artifact_selection_rejects_missing_expired_duplicate_forensic_and_caller_digest(
    artifacts: list[dict[str, object]], message: str
) -> None:
    policy = yaml.safe_load((ROOT / recovery.POLICY).read_text())
    name = recovery._artifact_name(policy, "build", OPERATION)
    exact = tuple({**item, "name": name} for item in artifacts)
    provider = SimpleNamespace(repository_artifacts=lambda *_args, **_kwargs: exact)
    with pytest.raises(GitHubControllerError, match=message):
        recovery._one_artifact(
            provider, "mjgolaszewski/bcf-governance", policy, "build", OPERATION
        )


def test_invalid_operation_reason_and_repository_reject(tmp_path: Path) -> None:
    with pytest.raises(GitHubControllerError, match="exact nonce"):
        recovery.authorize_build(
            Provider(), root=ROOT, repository="mjgolaszewski/bcf-governance",
            operation_id="latest", reason_code="ordinary_control_plane_bootstrap_deadlock",
            output=tmp_path / "x",
        )
    with pytest.raises(GitHubControllerError, match="reason"):
        recovery.authorize_build(
            Provider(), root=ROOT, repository="mjgolaszewski/bcf-governance",
            operation_id=OPERATION, reason_code="candidate-requested",
            output=tmp_path / "x",
        )
    with pytest.raises(GitHubControllerError, match="owner-dispatched"):
        recovery.authorize_build(
            Provider(), root=ROOT, repository="other/repo", operation_id=OPERATION,
            reason_code="ordinary_control_plane_bootstrap_deadlock", output=tmp_path / "x",
        )


def test_policy_and_workflow_have_no_ordinary_authority() -> None:
    policy = yaml.safe_load((ROOT / recovery.POLICY).read_text())
    workflow = yaml.safe_load((ROOT / ".github/workflows/bcf-break-glass-recovery.yml").read_text())
    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["permissions"] == {"actions": "read", "contents": "read"}
    assert all(job["environment"] == "bcf-break-glass-recovery" for job in workflow["jobs"].values())
    assert policy["permissions"]["required"] == ["metadata:read", "contents:read", "actions:read"]
    assert policy["authority"]["authorized_actors"] == [
        {"login": OWNER, "user_id": OWNER_ID}
    ]
    assert policy["operation"]["stages"] == ["build", "install", "probe"]
    assert {"contents:write", "statuses:write", "administration:write"}.issubset(
        set(policy["permissions"]["forbidden"])
    )
    rendered = json.dumps(workflow)
    assert "10425078154" not in rendered
    assert "bcf/pr-certification" not in rendered
    assert "bcf/exact-main-certification" not in rendered
    assert "release" not in workflow["permissions"]
    recovery_steps = [
        step
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if "break_glass_recovery.py" in str(step.get("run", ""))
        and "bind-build" not in str(step.get("run", ""))
    ]
    identity_keys = {
        "BCF_BREAK_GLASS_APP_ID", "BCF_BREAK_GLASS_INSTALLATION_ID",
        "BCF_BREAK_GLASS_WORKFLOW_ID",
    }
    assert len(recovery_steps) == 5
    assert all(identity_keys.issubset(step["env"]) for step in recovery_steps)
    build_steps = workflow["jobs"]["build"]["steps"]
    authorize_index = next(
        index for index, step in enumerate(build_steps)
        if "authorize-build" in str(step.get("run", ""))
    )
    builder_index = next(
        index for index, step in enumerate(build_steps)
        if "build_trusted_controller.py" in str(step.get("run", ""))
    )
    assert authorize_index < builder_index
    assert "continue-on-error" not in build_steps[authorize_index]


def test_schema_expansion_is_explicit_and_unknown_fields_still_reject() -> None:
    schema = json.loads((ROOT / "schemas/ci-authority.schema.json").read_text())
    authority = yaml.safe_load((ROOT / "governance/ci-authority.yml").read_text())
    inactive = json.loads(json.dumps(authority))
    inactive.pop("controller_builder_jobs")
    inactive["workflow_registry"]["admission"]["job_roles"].pop("trusted-controller-build")
    Draft202012Validator(schema).validate(inactive)
    inactive["unknown_authority"] = True
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(inactive)


def test_receipt_can_never_claim_governance() -> None:
    schema = json.loads((ROOT / recovery.RECEIPT_SCHEMA).read_text())
    assert schema["properties"]["recovery_only"] == {"const": True}
    assert schema["properties"]["governance_certified"] == {"const": False}


def test_recovery_projection_changes_only_proven_installation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "schemas").mkdir()
    (tmp_path / "governance").mkdir()
    (tmp_path / recovery.RECEIPT_SCHEMA).write_bytes((ROOT / recovery.RECEIPT_SCHEMA).read_bytes())
    old = "c" * 40
    policy_path = tmp_path / "governance/self-governance-policy.yml"
    policy_path.write_text(
        "runner_security:\n"
        f"  trusted_controller_artifact: {{BCF_BOOTSTRAP_COMMIT_SHA: {old}}}\n"
        f"  trusted_controller_installation: {{schema_version: '1.0', installed_commit_sha: {old}, subject_commit_sha: {old}, subject_tree_sha: {'d' * 40}, bootstrap_run_id: '1', bootstrap_run_attempt: '1', probe_run_id: '2', probe_run_attempt: '1'}}\n"
    )
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(recovery_receipt()))
    answers = iter((COMMIT, TREE))
    monkeypatch.setattr(
        recovery.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=next(answers) + "\n"),
    )
    monkeypatch.setattr(
        recovery, "apply_ci_graph_locks",
        lambda _root: SimpleNamespace(changed_inputs=("governance/self-governance-policy.yml",)),
    )
    monkeypatch.setattr(
        recovery, "apply_ci_graph",
        lambda _root: SimpleNamespace(changed_paths=(".github/workflows/bcf-trusted-finalizer.yml",)),
    )
    result = recovery.project_installation(root=tmp_path, receipt_path=receipt_path)
    projected = yaml.safe_load(policy_path.read_text())["runner_security"]
    assert projected["trusted_controller_artifact"]["BCF_BOOTSTRAP_COMMIT_SHA"] == old
    assert projected["trusted_controller_installation"] == recovery_receipt()["controller_confirmation"]
    assert result["installed_commit_sha"] == COMMIT


def test_old_main_receipt_cannot_project_after_main_moves(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "schemas").mkdir()
    (tmp_path / recovery.RECEIPT_SCHEMA).write_bytes((ROOT / recovery.RECEIPT_SCHEMA).read_bytes())
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(recovery_receipt()))
    answers = iter(("9" * 40, TREE))
    monkeypatch.setattr(
        recovery.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=next(answers) + "\n"),
    )
    with pytest.raises(GitHubControllerError, match="exact local main"):
        recovery.project_installation(root=tmp_path, receipt_path=receipt_path)

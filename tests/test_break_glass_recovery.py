from __future__ import annotations

import json
import io
import hashlib
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
LIVE_OPERATION = "91e5e24100bad92c68f53428dbfcd586"
LIVE_MAIN = "8b4023448d3b243873f06724d0da513f9bea012a"
LIVE_TREE = "6a386c6a8374973dd077aa0bace40d80ddf0e289"
LIVE_BUILD_RUN = "35123826709"
LIVE_INSTALL_RUN = "35124127441"
LIVE_ARTIFACT = "10458328400"
LIVE_PROVIDER_DIGEST = "sha256:c96f2b0c79ca45805424fa94d7c1b58d7b82dd68f670feefac49fcd8425927c4"


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


class LiveResolveProvider(Provider):
    """Provider shape from the successful build and failed install invocation."""

    def __init__(self, *, stage: str = "install", current_sha: str = LIVE_MAIN):
        super().__init__()
        self.stage = stage
        self.current_sha = current_sha

    def run(self, _repository, run_id):
        if str(run_id) == LIVE_BUILD_RUN:
            return {
                "id": int(LIVE_BUILD_RUN), "run_attempt": 1,
                "status": "completed", "conclusion": "success",
                "event": "workflow_dispatch", "head_sha": LIVE_MAIN,
                "head_branch": "main", "workflow_id": int(WORKFLOW_ID),
                "path": ".github/workflows/bcf-break-glass-recovery.yml",
                "actor": {"login": OWNER, "id": int(OWNER_ID)},
                "repository": {"id": 1207503211},
                "head_repository": {"id": 1207503211},
            }
        return {
            "id": int(run_id), "run_attempt": 1, "event": "workflow_dispatch",
            "head_sha": self.current_sha, "head_branch": "main",
            "workflow_id": int(WORKFLOW_ID),
            "path": ".github/workflows/bcf-break-glass-recovery.yml",
            "actor": {"login": OWNER, "id": int(OWNER_ID)},
        }

    def workflow_runs(self, *_args, **_kwargs):
        return ({"id": int(LIVE_INSTALL_RUN), "status": "in_progress"},)

    def repository_artifacts(self, _repository, *, name=None):
        build_name = f"bcf-break-glass-recovery-build-{LIVE_OPERATION}"
        install_name = f"bcf-break-glass-recovery-install-{LIVE_OPERATION}"
        if name == build_name:
            return ({
                "id": int(LIVE_ARTIFACT), "name": build_name, "expired": False,
                "digest": LIVE_PROVIDER_DIGEST,
                "workflow_run": {"id": int(LIVE_BUILD_RUN)},
            },)
        if self.stage == "probe" and name == install_name:
            return ({"id": 10458328401, "name": install_name, "expired": False},)
        return ()

    def jobs(self, _repository, run_id, *, attempt):
        assert str(run_id) == LIVE_BUILD_RUN
        assert attempt == 1
        return ({
            "id": 104887000000, "name": "Build exact-main recovery controller",
            "status": "completed", "conclusion": "success",
        },)


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


def _common_cli(operation: str, *, output: Path) -> list[str]:
    return [
        operation, "--repo-root", str(ROOT),
        "--repository", "mjgolaszewski/bcf-governance",
        "--operation-id", LIVE_OPERATION,
        "--reason-code", "ordinary_control_plane_bootstrap_deadlock",
        "--output", str(output),
    ]


def test_authorize_build_cli_owns_build_stage_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    provider = Provider()
    calls: list[str] = []
    original = recovery._authorize

    def tracked(*args, **kwargs):
        calls.append(kwargs["stage"])
        return original(*args, **kwargs)

    monkeypatch.setenv("BCF_BREAK_GLASS_APP_TOKEN", "installation-token")
    monkeypatch.setattr(recovery, "GitHubAPI", lambda **_kwargs: provider)
    monkeypatch.setattr(recovery, "_authorize", tracked)
    recovery.main([
        *_common_cli("authorize-build", output=tmp_path / "authorization.json"),
        "--stage", "build",
    ])
    assert calls == ["build"]


@pytest.mark.parametrize("stage", ["install", "probe"])
def test_resolve_build_cli_propagates_each_stage_once_with_live_build(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stage: str,
) -> None:
    provider = LiveResolveProvider(stage=stage)
    calls: list[str] = []
    original = recovery._authorize

    def tracked(*args, **kwargs):
        calls.append(kwargs["stage"])
        return original(*args, **kwargs)

    github_output = tmp_path / "github-output"
    monkeypatch.setenv("BCF_BREAK_GLASS_APP_TOKEN", "installation-token")
    monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
    monkeypatch.setenv("GITHUB_RUN_ID", LIVE_INSTALL_RUN)
    monkeypatch.setenv("GITHUB_SHA", LIVE_MAIN)
    monkeypatch.setattr(
        recovery, "resolve_main",
        lambda *_args: MainIdentity("1207503211", "main", LIVE_MAIN, LIVE_TREE),
    )
    monkeypatch.setattr(recovery, "GitHubAPI", lambda **_kwargs: provider)
    monkeypatch.setattr(recovery, "_authorize", tracked)
    recovery.main([
        *_common_cli("resolve-build", output=tmp_path / "unused.json"),
        "--stage", stage,
    ])
    assert calls == [stage]
    assert f"artifact_id={LIVE_ARTIFACT}" in github_output.read_text()


def test_historical_build_rejects_after_current_main_moves(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    moved_main = "c" * 40
    provider = LiveResolveProvider(current_sha=moved_main)
    monkeypatch.setenv("BCF_BREAK_GLASS_APP_TOKEN", "installation-token")
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "github-output"))
    monkeypatch.setenv("GITHUB_RUN_ID", LIVE_INSTALL_RUN)
    monkeypatch.setenv("GITHUB_SHA", moved_main)
    monkeypatch.setattr(
        recovery, "resolve_main",
        lambda *_args: MainIdentity("1207503211", "main", moved_main, "d" * 40),
    )
    monkeypatch.setattr(recovery, "GitHubAPI", lambda **_kwargs: provider)
    with pytest.raises(GitHubControllerError, match="builder run identity"):
        recovery.main([
            *_common_cli("resolve-build", output=tmp_path / "unused.json"),
            "--stage", "install",
        ])


@pytest.mark.parametrize(
    "argv",
    [
        ["resolve-build"],
        ["resolve-build", "--stage", "invalid"],
        ["authorize-build", "--stage", "install"],
        ["install", "--stage", "probe"],
        ["probe", "--stage", "install"],
        ["finalize", "--stage", "build"],
    ],
)
def test_cli_rejects_missing_or_cross_operation_stage_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, argv: list[str],
) -> None:
    monkeypatch.setenv("BCF_BREAK_GLASS_APP_TOKEN", "installation-token")
    monkeypatch.setattr(recovery, "GitHubAPI", lambda **_kwargs: Provider())
    operation, *stage = argv
    with pytest.raises(SystemExit, match="2"):
        recovery.main([*_common_cli(operation, output=tmp_path / "unused.json"), *stage])


def test_finalize_cli_owns_probe_stage_and_emits_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    policy = yaml.safe_load((ROOT / recovery.POLICY).read_text())
    actor = recovery_receipt()["actor"]
    calls: list[str] = []
    probe_jobs = {
        f"Probe recovered controller / {runner['slot']}": {
            "id": 31 + index, "name": f"Probe recovered controller / {runner['slot']}",
            "runner_name": runner["runner_name"], "labels": [runner["slot"]],
            "status": "completed", "conclusion": "success",
        }
        for index, runner in enumerate(policy["runners"])
    }
    install_jobs = {
        f"Install recovered controller / {runner['slot']}": {
            "id": 21 + index, "runner_name": runner["runner_name"],
        }
        for index, runner in enumerate(policy["runners"])
    }

    class ReceiptProvider:
        def jobs(self, *_args, **_kwargs):
            return tuple(probe_jobs.values())

        def run(self, *_args, **_kwargs):
            return {"created_at": "2026-09-16T00:02:00Z"}

    def tracked(_api, **kwargs):
        calls.append(kwargs["stage"])
        return policy, MainIdentity("1207503211", "main", COMMIT, TREE), actor

    build_artifact = {
        "id": 99, "name": f"bcf-break-glass-recovery-build-{OPERATION}",
        "digest": f"sha256:{'d' * 64}",
    }
    build_run = {
        "id": 10, "run_attempt": 1, "created_at": "2026-09-16T00:00:00Z",
        "actor": {"login": OWNER},
    }
    custody = {
        "wheel_sha256": "e" * 64,
        "checksum_inventory": {"CONTROL-METADATA.json": "f" * 64, "bcf_governance.whl": "1" * 64},
        "checksum_inventory_sha256": "2" * 64,
        "control_metadata": {str(index): "value" for index in range(10)},
    }
    install_run = {
        "id": 20, "run_attempt": 1, "created_at": "2026-09-16T00:01:00Z",
        "actor": {"login": OWNER},
    }
    output = tmp_path / "receipt.json"
    monkeypatch.setenv("BCF_BREAK_GLASS_APP_TOKEN", "installation-token")
    monkeypatch.setenv("BCF_PRE_RECOVERY_CONTROLLER", "c" * 40)
    monkeypatch.setattr(recovery, "GitHubAPI", lambda **_kwargs: ReceiptProvider())
    monkeypatch.setattr(recovery, "_authorize", tracked)
    monkeypatch.setattr(
        recovery, "_authenticated_build",
        lambda *_args, **_kwargs: (build_artifact, build_run, {"id": 10}, custody),
    )
    monkeypatch.setattr(
        recovery, "_install_run",
        lambda *_args, **_kwargs: ({}, install_run, install_jobs),
    )
    recovery.main(_common_cli("finalize", output=output))
    assert calls == ["probe"]
    assert json.loads(output.read_text())["governance_certified"] is False


def test_project_installation_cli_authenticates_provider_receipt_input(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps(recovery_receipt()))
    artifact = {"id": "44", "name": "receipt", "digest": "sha256:" + "a" * 64}
    main = SimpleNamespace(checkout_sha=COMMIT, tree_sha=TREE)
    observed: list[tuple[Path, Path, dict[str, object], object]] = []

    def project(*, root: Path, receipt_path: Path, receipt_artifact, provider_main):
        observed.append((root, receipt_path, receipt_artifact, provider_main))
        return {"status": "projected"}

    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(
        recovery,
        "_projection_receipt",
        lambda *_args, **_kwargs: (recovery_receipt(), artifact, main),
    )
    monkeypatch.setattr(recovery, "project_installation", project)
    recovery.main([
        "project-installation", "--repo-root", str(ROOT),
        "--repository", "mjgolaszewski/bcf-governance", "--receipt", str(receipt)
    ])
    assert observed == [(ROOT.resolve(), receipt, artifact, main)]


def test_projection_receipt_authenticates_exact_provider_archive(
    tmp_path: Path,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(recovery_receipt(), sort_keys=True))
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as value:
        value.writestr("receipt.json", receipt_path.read_bytes())
    raw = archive.getvalue()

    class ProjectionProvider:
        def repository_artifacts(self, _repository, *, name=None):
            return ({
                "id": 606,
                "name": name,
                "expired": False,
                "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "workflow_run": {"id": 30},
            },)

        def artifact_bytes(self, _repository, _artifact_id):
            return raw

        def run(self, _repository, _run_id):
            return {
                "run_attempt": 1,
                "conclusion": "success",
                "head_sha": COMMIT,
                "workflow_id": int(WORKFLOW_ID),
                "repository": {"id": 1207503211},
            }

    receipt, artifact, main = recovery._projection_receipt(
        ProjectionProvider(),
        root=ROOT,
        repository="mjgolaszewski/bcf-governance",
        receipt_path=receipt_path,
    )
    assert receipt == recovery_receipt()
    assert str(artifact["id"]) == "606"
    assert main == MainIdentity("1207503211", "main", COMMIT, TREE)


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


def test_build_resolution_rejects_other_operation_and_failed_builder_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = yaml.safe_load((ROOT / recovery.POLICY).read_text())
    expected_name = recovery._artifact_name(policy, "build", OPERATION)
    other_name = recovery._artifact_name(policy, "build", "2" * 32)
    other_operation = SimpleNamespace(
        repository_artifacts=lambda *_args, **_kwargs: ({
            "id": 99, "name": other_name, "expired": False,
            "digest": f"sha256:{'d' * 64}",
        },)
    )
    with pytest.raises(GitHubControllerError, match="not unique"):
        recovery._one_artifact(
            other_operation, "mjgolaszewski/bcf-governance", policy, "build", OPERATION
        )

    class FailedBuild:
        def repository_artifacts(self, *_args, **_kwargs):
            return ({
                "id": 99, "name": expected_name, "expired": False,
                "digest": f"sha256:{'d' * 64}", "workflow_run": {"id": 10},
            },)

        def run(self, *_args, **_kwargs):
            return {
                "id": 10, "run_attempt": 1, "conclusion": "failure",
                "event": "workflow_dispatch", "head_sha": COMMIT,
                "head_branch": "main", "workflow_id": int(WORKFLOW_ID),
                "path": ".github/workflows/bcf-break-glass-recovery.yml",
                "repository": {"id": 1207503211},
                "head_repository": {"id": 1207503211},
            }

    monkeypatch.setenv("GITHUB_SHA", COMMIT)
    with pytest.raises(GitHubControllerError, match="builder run identity"):
        recovery._build_bundle(
            FailedBuild(), "mjgolaszewski/bcf-governance", policy, OPERATION
        )


def test_probe_and_receipt_cannot_treat_failed_install_as_evidence(
    tmp_path: Path,
) -> None:
    with pytest.raises(GitHubControllerError, match="duplicated or out of order"):
        recovery._authorize(
            Provider(), stage="probe", root=ROOT,
            repository="mjgolaszewski/bcf-governance", operation_id=OPERATION,
            reason_code="ordinary_control_plane_bootstrap_deadlock",
            output=tmp_path / "unused.json",
        )
    policy = yaml.safe_load((ROOT / recovery.POLICY).read_text())
    receipt_name = recovery._artifact_name(policy, "receipt", OPERATION)
    assert Provider().repository_artifacts(
        "mjgolaszewski/bcf-governance", name=receipt_name
    ) == ()


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
    (tmp_path / recovery.REENTRY_SCHEMA).write_bytes((ROOT / recovery.REENTRY_SCHEMA).read_bytes())
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
    artifact = {
        "id": "10462136837",
        "name": f"bcf-break-glass-recovery-receipt-{OPERATION}",
        "digest": "sha256:" + "e" * 64,
    }
    main = SimpleNamespace(
        checkout_sha=COMMIT,
        tree_sha=TREE,
        repository_id=recovery_receipt()["repository"]["id"],
        default_branch="main",
    )
    result = recovery.project_installation(
        root=tmp_path,
        receipt_path=receipt_path,
        receipt_artifact=artifact,
        provider_main=main,
    )
    projected = yaml.safe_load(policy_path.read_text())["runner_security"]
    assert projected["trusted_controller_artifact"]["BCF_BOOTSTRAP_COMMIT_SHA"] == old
    assert projected["trusted_controller_installation"] == recovery_receipt()["controller_confirmation"]
    assert projected["trusted_controller_recovery_reentry"]["authorized_source"] == {
        "commit": COMMIT,
        "tree": TREE,
    }
    assert result["installed_commit_sha"] == COMMIT


def test_old_main_receipt_cannot_project_after_main_moves(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "schemas").mkdir()
    (tmp_path / "governance").mkdir()
    (tmp_path / recovery.RECEIPT_SCHEMA).write_bytes((ROOT / recovery.RECEIPT_SCHEMA).read_bytes())
    (tmp_path / recovery.REENTRY_SCHEMA).write_bytes((ROOT / recovery.REENTRY_SCHEMA).read_bytes())
    old = "c" * 40
    (tmp_path / "governance/self-governance-policy.yml").write_text(
        "runner_security:\n"
        f"  trusted_controller_artifact: {{BCF_BOOTSTRAP_COMMIT_SHA: {old}}}\n"
        f"  trusted_controller_installation: {{schema_version: '1.0', installed_commit_sha: {old}, subject_commit_sha: {old}, subject_tree_sha: {'d' * 40}, bootstrap_run_id: '1', bootstrap_run_attempt: '1', probe_run_id: '2', probe_run_attempt: '1'}}\n"
    )
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(recovery_receipt()))
    answers = iter(("9" * 40, TREE))
    monkeypatch.setattr(
        recovery.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=next(answers) + "\n"),
    )
    main = SimpleNamespace(
        checkout_sha="9" * 40,
        tree_sha=TREE,
        repository_id=recovery_receipt()["repository"]["id"],
        default_branch="main",
    )
    artifact = {
        "id": "10462136837",
        "name": f"bcf-break-glass-recovery-receipt-{OPERATION}",
        "digest": "sha256:" + "e" * 64,
    }
    with pytest.raises(GitHubControllerError, match="not exact receipt subject"):
        recovery.project_installation(
            root=tmp_path,
            receipt_path=receipt_path,
            receipt_artifact=artifact,
            provider_main=main,
        )

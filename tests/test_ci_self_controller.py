from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from bcf_governance.tooling import ci_github_commands as commands
from bcf_governance.tooling import ci_self_controller as controller
from bcf_governance.tooling.ci_github_artifacts import ProviderArtifact
from bcf_governance.tooling.ci_github_identity import (
    GitHubControllerError,
    MainIdentity,
)
from tests._wheel_fixture import write_wheel


REPO_ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
TREE = "b" * 40


def _artifact_dir(root: Path) -> tuple[Path, str]:
    root.mkdir(parents=True)
    wheel = root / "bcf_governance-0.7.1-py3-none-any.whl"
    write_wheel(wheel, name="bcf-governance", version="0.7.1")
    metadata = root / "CONTROL-METADATA.json"
    metadata.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "commit_sha": COMMIT,
                "tree_sha": TREE,
                "workflow_run_id": "100",
                "workflow_run_attempt": "2",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    sums = root / "SHA256SUMS"
    sums.write_text(
        "\n".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
            for path in (wheel, metadata)
        )
        + "\n",
        encoding="utf-8",
    )
    return root, hashlib.sha256(wheel.read_bytes()).hexdigest()


def _provider(
    monkeypatch: pytest.MonkeyPatch,
    *,
    conclusion: str = "success",
    builder_conclusion: str = "success",
    legacy: bool = False,
    artifact: ProviderArtifact | None = None,
) -> SimpleNamespace:
    main = MainIdentity("101", "main", COMMIT, TREE)
    selected_artifact = artifact or ProviderArtifact(
        "100", 2, "300", f"bcf-trusted-control-{COMMIT}-2",
        f"sha256:{'c' * 64}", {},
    )
    monkeypatch.setattr(controller, "resolve_main", lambda *args: main)
    authority = {} if legacy else {
        "controller_builder_jobs": [
            {"job_id": "Build independent exact-main trusted controller"}
        ]
    }
    monkeypatch.setattr(
        controller, "load_authority", lambda *args, **kwargs: authority
    )
    monkeypatch.setattr(
        controller, "select_latest_admission", lambda *args, **kwargs: ("100", 2)
    )
    monkeypatch.setattr(
        controller,
        "collect_same_run_producers",
        lambda *args, **kwargs: (
            {
                "producer_id": "governance",
                "attempts": [
                    {"status": "completed", "conclusion": conclusion, "jobs": []}
                ],
            },
        ),
    )
    monkeypatch.setattr(controller, "authenticate_role_run", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        controller, "resolve_role_artifact", lambda *args, **kwargs: selected_artifact
    )
    return SimpleNamespace(
        run=lambda *_args, **_kwargs: {
            "status": "completed",
            "run_attempt": 2,
        },
        jobs=lambda *_args, **_kwargs: (
            {
                "id": 400,
                "name": "Build independent exact-main trusted controller",
                "status": "completed",
                "conclusion": builder_conclusion,
            },
        ),
    )


def test_controller_pin_uses_independent_builder_when_governance_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = _provider(monkeypatch, conclusion="failure")
    artifact_dir, wheel_digest = _artifact_dir(tmp_path / "artifact")

    pin = controller.compile_self_controller_pin(
        api,  # type: ignore[arg-type]
        repository="owner/repo",
        artifact_dir=artifact_dir,
    )

    assert pin == {
        "BCF_BOOTSTRAP_ARTIFACT_ID": "300",
        "BCF_BOOTSTRAP_ARTIFACT_NAME": f"bcf-trusted-control-{COMMIT}-2",
        "BCF_BOOTSTRAP_ARTIFACT_DIGEST": f"sha256:{'c' * 64}",
        "BCF_BOOTSTRAP_RUN_ID": "100",
        "BCF_BOOTSTRAP_RUN_ATTEMPT": "2",
        "BCF_BOOTSTRAP_COMMIT_SHA": COMMIT,
        "BCF_BOOTSTRAP_TREE_SHA": TREE,
        "BCF_BOOTSTRAP_REPOSITORY_ID": "101",
        "BCF_BOOTSTRAP_WHEEL_SHA256": wheel_digest,
    }


def test_controller_pin_rejects_failed_governance_producer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _provider(monkeypatch, conclusion="failure", legacy=True)
    with pytest.raises(GitHubControllerError, match="governance producer"):
        controller.resolve_self_controller_artifact(
            api, repository="owner/repo"  # type: ignore[arg-type]
        )


def test_controller_pin_requires_successful_independent_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _provider(monkeypatch, builder_conclusion="failure")

    with pytest.raises(GitHubControllerError, match="builder job is not successful"):
        controller.resolve_self_controller_artifact(
            api, repository="owner/repo"  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("jobs", "message"),
    [
        ((), "job inventory is empty or duplicated"),
        (
            (
                {
                    "id": 400,
                    "name": "some other job",
                    "status": "completed",
                    "conclusion": "success",
                },
            ),
            "builder job identity is not exact",
        ),
        (
            (
                {
                    "id": 400,
                    "name": "Build independent exact-main trusted controller",
                    "status": "completed",
                    "conclusion": "success",
                },
                {
                    "id": 401,
                    "name": "Build independent exact-main trusted controller",
                    "status": "completed",
                    "conclusion": "success",
                },
            ),
            "job inventory is empty or duplicated",
        ),
        (
            (
                {
                    "id": 400,
                    "name": "Build independent exact-main trusted controller",
                    "status": "completed",
                    "conclusion": "skipped",
                },
            ),
            "builder job is not successful",
        ),
    ],
)
def test_controller_pin_rejects_missing_wrong_duplicate_or_skipped_builder(
    monkeypatch: pytest.MonkeyPatch,
    jobs: tuple[dict[str, object], ...],
    message: str,
) -> None:
    api = _provider(monkeypatch)
    api.jobs = lambda *_args, **_kwargs: jobs

    with pytest.raises(GitHubControllerError, match=message):
        controller.resolve_self_controller_artifact(
            api, repository="owner/repo"  # type: ignore[arg-type]
        )


def test_controller_pin_requires_terminal_exact_admission_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _provider(monkeypatch)
    api.run = lambda *_args, **_kwargs: {
        "status": "in_progress",
        "run_attempt": 2,
    }

    with pytest.raises(GitHubControllerError, match="not terminal"):
        controller.resolve_self_controller_artifact(
            api, repository="owner/repo"  # type: ignore[arg-type]
        )


def test_controller_pin_rejects_forensic_failed_governance_artifact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forensic = ProviderArtifact(
        "35041092138",
        1,
        "10425078154",
        "bcf-trusted-control-2fc02544a238a049fe72e37f030598602f098f6d-1",
        "sha256:587e6a19e35d2f310fa8aeafc96435ee18bac29945c63c2f805bdb931e5335f0",
        {},
    )
    api = _provider(monkeypatch, artifact=forensic)

    with pytest.raises(GitHubControllerError, match="not bound to its builder admission"):
        controller.resolve_self_controller_artifact(
            api, repository="owner/repo"  # type: ignore[arg-type]
        )


def test_controller_pin_rejects_non_derived_artifact_name() -> None:
    policy = yaml.safe_load(
        (REPO_ROOT / "governance/self-governance-policy.yml").read_text(encoding="utf-8")
    )
    pin = dict(policy["runner_security"]["trusted_controller_artifact"])
    pin["BCF_BOOTSTRAP_ARTIFACT_NAME"] = "operator-copied-name"
    with pytest.raises(GitHubControllerError, match="name is not derived"):
        controller.validate_controller_pin(pin)


def test_legacy_rotation_surfaces_are_absent() -> None:
    assert not hasattr(commands, "_controller_pin")
    assert not hasattr(controller, "compile_self_controller_confirmation")
    assert not hasattr(controller, "project_self_controller_pin")
    assert not (REPO_ROOT / ".github/workflows/bcf-trusted-control-bootstrap.yml").exists()
    assert not (REPO_ROOT / ".github/workflows/bcf-trusted-control-probe.yml").exists()


def test_source_controller_is_an_immutable_transition_genesis() -> None:
    policy = yaml.safe_load(
        (REPO_ROOT / "governance/self-governance-policy.yml").read_text(encoding="utf-8")
    )["runner_security"]
    pin = controller.validate_controller_pin(policy["trusted_controller_artifact"])
    installation = controller.validate_controller_installation(
        policy["trusted_controller_installation"]
    )
    assert pin["BCF_BOOTSTRAP_COMMIT_SHA"] == installation["installed_commit_sha"]
    assert controller.verify_self_controller_projection(REPO_ROOT) > 0

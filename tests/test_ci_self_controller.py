from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
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


REPO_ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
TREE = "b" * 40


def _job_step(workflow: dict[str, object], job_id: str, name: str) -> dict[str, object]:
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    job = jobs[job_id]
    assert isinstance(job, dict)
    steps = job["steps"]
    assert isinstance(steps, list)
    matches = [step for step in steps if isinstance(step, dict) and step.get("name") == name]
    assert len(matches) == 1, name
    return matches[0]


class ConfirmationAPI:
    def __init__(self, policy: dict[str, object]) -> None:
        self.policy = policy

    def content(self, _: str, path: str, *, ref: str) -> SimpleNamespace:
        assert ref == COMMIT
        if path == "governance/self-governance-policy.yml":
            raw = yaml.safe_dump(self.policy).encode()
        else:
            role = "bootstrap" if "bootstrap" in path else "probe"
            raw = yaml.safe_dump({
                "jobs": {
                    role: {
                        "name": f"{role.title()} controller / ${{{{ matrix.trusted_runner }}}}",
                        "strategy": {"matrix": {"trusted_runner": ["one", "two"]}},
                    }
                }
            }).encode()
        return SimpleNamespace(content=raw)

    def workflow_runs(self, *_: object, **__: object) -> tuple[dict[str, object], ...]:
        return ({
            "id": 200 if len(getattr(self, "seen", ())) == 0 else 201,
            "run_attempt": 1,
            "head_sha": COMMIT,
            "event": "workflow_dispatch",
            "repository": {"id": 101},
        },)

    def jobs(self, _: str, run_id: object, *, attempt: int) -> tuple[dict[str, str], ...]:
        assert attempt == 1
        role = "Bootstrap" if str(run_id) == "200" else "Probe"
        return tuple(
            {"name": f"{role} controller / {label}", "status": "completed", "conclusion": "success"}
            for label in ("one", "two")
        )


def _artifact_dir(root: Path) -> tuple[Path, str]:
    root.mkdir(parents=True)
    wheel = root / "bcf_governance-0.7.1-py3-none-any.whl"
    wheel.write_bytes(b"controller-wheel")
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


def _provider(monkeypatch: pytest.MonkeyPatch, *, conclusion: str = "success") -> None:
    main = MainIdentity("101", "main", COMMIT, TREE)
    artifact = ProviderArtifact(
        "100", 2, "300", f"bcf-trusted-control-{COMMIT}-2",
        f"sha256:{'c' * 64}", {},
    )
    monkeypatch.setattr(controller, "resolve_main", lambda *args: main)
    monkeypatch.setattr(controller, "load_authority", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        controller, "select_latest_admission", lambda *args, **kwargs: ("100", 2)
    )
    monkeypatch.setattr(
        controller,
        "collect_same_run_producers",
        lambda *args, **kwargs: (
            {
                "producer_id": "governance-pack",
                "attempts": [
                    {"status": "completed", "conclusion": conclusion, "jobs": []}
                ],
            },
        ),
    )
    monkeypatch.setattr(
        controller, "resolve_role_artifact", lambda *args, **kwargs: artifact
    )


def test_controller_pin_is_compiled_from_latest_provider_and_downloaded_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _provider(monkeypatch)
    artifact_dir, wheel_digest = _artifact_dir(tmp_path / "artifact")

    pin = controller.compile_self_controller_pin(
        SimpleNamespace(),  # type: ignore[arg-type]
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


def test_controller_pin_rejects_failed_package_producer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _provider(monkeypatch, conclusion="failure")
    with pytest.raises(GitHubControllerError, match="package producer"):
        controller.resolve_self_controller_artifact(
            SimpleNamespace(), repository="owner/repo"  # type: ignore[arg-type]
        )


def test_controller_pin_rejects_non_derived_artifact_name() -> None:
    policy = yaml.safe_load(
        (REPO_ROOT / "governance/self-governance-policy.yml").read_text(encoding="utf-8")
    )
    pin = dict(policy["runner_security"]["trusted_controller_artifact"])
    pin["BCF_BOOTSTRAP_ARTIFACT_NAME"] = "operator-copied-name"
    with pytest.raises(GitHubControllerError, match="name is not derived"):
        controller.project_self_controller_pin(REPO_ROOT, pin=pin, apply=False)


def test_self_controller_projection_has_one_canonical_pin_owner(
    tmp_path: Path,
) -> None:
    policy = yaml.safe_load(
        (REPO_ROOT / "governance/self-governance-policy.yml").read_text(encoding="utf-8")
    )
    paths = [
        "governance/self-governance-policy.yml",
        "governance/ci-graph.yml",
        "governance/public-contracts.yml",
        "schemas/ci-graph.schema.json",
        "schemas/ci-graph-extension.schema.json",
    ]
    for relative in paths:
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / relative, destination)
    shutil.copytree(
        REPO_ROOT / "governance/ci-extensions",
        tmp_path / "governance/ci-extensions",
    )
    shutil.copytree(REPO_ROOT / ".github/workflows", tmp_path / ".github/workflows")
    pin = dict(policy["runner_security"]["trusted_controller_artifact"])
    baseline_proof = dict(
        policy["runner_security"]["trusted_controller_installation"]
    )
    baseline_proof["installed_commit_sha"] = pin["BCF_BOOTSTRAP_COMMIT_SHA"]
    controller.project_self_controller_pin(
        tmp_path, pin=pin, confirmation=baseline_proof, apply=True
    )
    assert controller.project_self_controller_pin(
        tmp_path, pin=pin, apply=False
    ).status == "clean"
    pin.update(
        {
            "BCF_BOOTSTRAP_ARTIFACT_ID": "400",
            "BCF_BOOTSTRAP_ARTIFACT_NAME": f"bcf-trusted-control-{COMMIT}-2",
            "BCF_BOOTSTRAP_ARTIFACT_DIGEST": f"sha256:{'d' * 64}",
            "BCF_BOOTSTRAP_RUN_ID": "500",
            "BCF_BOOTSTRAP_RUN_ATTEMPT": "2",
            "BCF_BOOTSTRAP_COMMIT_SHA": COMMIT,
            "BCF_BOOTSTRAP_TREE_SHA": TREE,
            "BCF_BOOTSTRAP_REPOSITORY_ID": "101",
            "BCF_BOOTSTRAP_WHEEL_SHA256": "e" * 64,
        }
    )
    started = controller.project_self_controller_pin(tmp_path, pin=pin, apply=True)
    assert started.status == "changed"
    bootstrap = yaml.safe_load(
        (tmp_path / controller.BOOTSTRAP_WORKFLOW).read_text(encoding="utf-8")
    )
    assert {key: str(bootstrap["env"][key]) for key in controller.PIN_KEYS} == pin
    install = _job_step(
        bootstrap,
        "bootstrap",
        "Authenticate provider custody and install offline through the controller",
    )
    assert baseline_proof["installed_commit_sha"] in str(install["run"])
    second_target = dict(pin)
    second_target["BCF_BOOTSTRAP_ARTIFACT_ID"] = "401"
    with pytest.raises(GitHubControllerError, match="rotation is already pending"):
        controller.project_self_controller_pin(
            tmp_path, pin=second_target, apply=True
        )

    proof = dict(policy["runner_security"]["trusted_controller_installation"])
    proof["installed_commit_sha"] = COMMIT
    changed = controller.project_self_controller_pin(
        tmp_path, pin=pin, confirmation=proof, apply=True
    )

    assert changed.status == "changed"
    projected = yaml.safe_load(
        (tmp_path / "governance/self-governance-policy.yml").read_text(encoding="utf-8")
    )["runner_security"]["trusted_controller_artifact"]
    assert {key: str(value) for key, value in projected.items()} == pin
    bootstrap = yaml.safe_load(
        (tmp_path / controller.BOOTSTRAP_WORKFLOW).read_text(encoding="utf-8")
    )
    install = _job_step(
        bootstrap,
        "bootstrap",
        "Authenticate provider custody and install offline through the controller",
    )
    assert COMMIT in str(install["run"])
    probe = yaml.safe_load(
        (tmp_path / controller.PROBE_WORKFLOW).read_text(encoding="utf-8")
    )
    assert {key: str(probe["env"][key]) for key in controller.PIN_KEYS} == pin
    download = _job_step(
        probe, "probe", "Download only the mechanically pinned controller artifact"
    )
    assert str(download["uses"]).startswith("actions/download-artifact@")
    install = _job_step(
        probe,
        "probe",
        "Authenticate provider custody and install offline through the controller",
    )
    assert "ci-github bootstrap" in str(install["run"])
    assert ".github/" not in str(install["run"])
    assert controller.project_self_controller_pin(
        tmp_path, pin=pin, apply=False
    ).status == "clean"


def test_controller_installation_confirmation_is_provider_compiled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = {
        "runner_security": {
            "trusted_controller_artifact": {
                "BCF_BOOTSTRAP_ARTIFACT_ID": "300",
                "BCF_BOOTSTRAP_ARTIFACT_NAME": f"bcf-trusted-control-{COMMIT}-2",
                "BCF_BOOTSTRAP_ARTIFACT_DIGEST": f"sha256:{'c' * 64}",
                "BCF_BOOTSTRAP_RUN_ID": "100",
                "BCF_BOOTSTRAP_RUN_ATTEMPT": "2",
                "BCF_BOOTSTRAP_COMMIT_SHA": COMMIT,
                "BCF_BOOTSTRAP_TREE_SHA": TREE,
                "BCF_BOOTSTRAP_REPOSITORY_ID": "101",
                "BCF_BOOTSTRAP_WHEEL_SHA256": "e" * 64,
            },
            "trusted_instance_labels": ["one", "two"],
        }
    }
    api = ConfirmationAPI(policy)
    main = SimpleNamespace(
        repository_id="101", checkout_sha=COMMIT, tree_sha=TREE
    )
    authority = {
        "schema_version": "1.1",
        "roles": {"bootstrap": "bootstrap", "probe": "probe"},
        "workflow_registry": {
            "bootstrap": {
                "workflow_id": "10",
                "active_path": controller.BOOTSTRAP_WORKFLOW,
            },
            "probe": {
                "workflow_id": "11",
                "active_path": controller.PROBE_WORKFLOW,
            },
        },
    }
    monkeypatch.setattr(controller, "resolve_main", lambda *_: main)
    monkeypatch.setattr(controller, "load_authority", lambda *_, **__: authority)
    calls = iter(("200", "201"))
    monkeypatch.setattr(
        controller,
        "authenticate_role_run",
        lambda *_, **__: SimpleNamespace(run_id=next(calls), run_attempt=1),
    )

    proof = controller.compile_self_controller_confirmation(
        api, repository="owner/repo"  # type: ignore[arg-type]
    )

    assert proof["installed_commit_sha"] == COMMIT
    assert proof["bootstrap_run_id"] == "200"
    assert proof["probe_run_id"] == "201"


@pytest.mark.parametrize("output_channel", [None, "missing"])
def test_controller_confirmation_preflights_output_before_provider_or_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output_channel: str | None,
) -> None:
    authority_output = tmp_path / "controller-confirmation.json"
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    if output_channel == "missing":
        monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "missing-output-channel"))

    def forbidden_provider() -> object:
        raise AssertionError("provider access preceded output-channel preflight")

    monkeypatch.setattr(commands, "environment_api", forbidden_provider)

    with pytest.raises(GitHubControllerError, match="GITHUB_OUTPUT"):
        commands._controller_pin(
            [
                "confirm",
                "--repository",
                "owner/repo",
                "--output",
                str(authority_output),
            ]
        )

    assert not authority_output.exists()

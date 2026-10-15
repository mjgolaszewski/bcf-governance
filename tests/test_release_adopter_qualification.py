from __future__ import annotations

import hashlib
import copy
import json
from pathlib import Path
import subprocess
import sys
import venv

import pytest

from bcf_governance.tooling import local_pr
from bcf_governance.tooling import ci_commands
from bcf_governance.tooling import release_adopter_qualification as qualification
from bcf_governance.tooling.ci_github_values import GitHubValueError, remote_repository
from bcf_governance.tooling.ci_github_identity import MainIdentity
from bcf_governance.tooling.local_pr_context import LocalValidationLane
from bcf_governance.tooling.release_adopter_qualification import (
    ReleaseQualificationError,
    _exact_release_runtime,
    _release_assets,
    _isolated_project_python,
    load_contract,
    qualify_release,
    validate_qualification_receipt,
)
from bcf_governance.tooling.release_adopter_sources import (
    AdopterSourceError,
    AdopterSourceIdentity,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCER = {
    "repository_id": "101",
    "workflow": ".github/workflows/bcf-release-verifier.yml",
    "job": "qualify",
    "run_id": "80",
    "run_attempt": "1",
}


def test_qualification_cli_derives_provider_producer_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    monkeypatch.setenv(
        "GITHUB_WORKFLOW_REF",
        "owner/repo/.github/workflows/bcf-release-verifier.yml@refs/heads/main",
    )
    monkeypatch.setenv("GITHUB_REPOSITORY_ID", "101")
    monkeypatch.setenv("GITHUB_JOB", "qualify")
    monkeypatch.setenv("GITHUB_RUN_ID", "80")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    monkeypatch.setattr(
        "bcf_governance.tooling.ci_github_controller.environment_api", lambda: object()
    )

    def qualify(*_args: object, **kwargs: object) -> dict[str, str]:
        observed.update(kwargs)
        return {"status": "pass"}

    monkeypatch.setattr(ci_commands, "qualify_release", qualify)
    ci_commands.main([
        "qualify-release", "--repo-root", str(tmp_path),
        "--repository", "owner/repo",
        "--release-assets", str(tmp_path / "assets"),
        "--release-build-manifest", str(tmp_path / "build.json"),
        "--output", str(tmp_path / "receipt.json"),
    ])
    assert observed["producer"] == {
        "repository_id": "101",
        "workflow": ".github/workflows/bcf-release-verifier.yml",
        "job": "qualify",
        "run_id": "80",
        "run_attempt": "2",
    }


def test_qualification_cli_rejects_unbound_workflow_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GITHUB_WORKFLOW_REF", raising=False)
    with pytest.raises(SystemExit, match="workflow identity"):
        ci_commands.main([
            "qualify-release", "--repo-root", str(tmp_path),
            "--repository", "owner/repo",
            "--release-assets", str(tmp_path / "assets"),
            "--release-build-manifest", str(tmp_path / "build.json"),
            "--output", str(tmp_path / "receipt.json"),
        ])


def _assets(root: Path) -> dict[str, str]:
    names = {
        "bcf_governance-2.2.1-py3-none-any.whl": b"wheel",
        "bcf_governance-2.2.1.tar.gz": b"sdist",
    }
    for name, data in names.items():
        (root / name).write_bytes(data)
    digests = {name: hashlib.sha256(data).hexdigest() for name, data in names.items()}
    (root / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(digests.items())),
        encoding="utf-8",
    )
    return digests


def _build_assets(root: Path, archives: dict[str, str]) -> dict[str, str]:
    return {
        **archives,
        "SHA256SUMS": hashlib.sha256((root / "SHA256SUMS").read_bytes()).hexdigest(),
    }


def _build_manifest(
    path: Path, assets: dict[str, str], *, commit: str, tree: str
) -> Path:
    path.write_text(
        json.dumps(
            {
                "subject": {"commit_sha": commit, "tree_sha": tree},
                "assets": assets,
            }
        ),
        encoding="utf-8",
    )
    return path


def _receipt(contract: dict[str, object], assets: dict[str, str]) -> dict[str, object]:
    adopters = []
    for index, item in enumerate(contract["required_adopters"]):  # type: ignore[index]
        identity = str(index + 1) * 40
        adopters.append(
            {
                "id": item["id"],
                "repository": item["repository"],
                "repository_id": str(index + 100),
                "profile": item["profile"],
                "source_branch": "main",
                "source_commit": identity,
                "source_tree": identity,
                "candidate_commit": identity,
                "candidate_tree": identity,
                "evaluation": {"intent": "pr", "target": None},
                "status": "pass",
            }
        )
    return {
        "schema_version": "1.1",
        "kind": "release_adopter_qualification",
        "authority": False,
        "subject": {
            "repository": "owner/repo",
            "commit_sha": "a" * 40,
            "tree_sha": "b" * 40,
        },
        "release": {"version": "2.2.1", "assets": dict(sorted(assets.items()))},
        "contract_sha256": "c" * 64,
        "source_inventory_sha256": qualification.source_inventory_sha256(
            [
                AdopterSourceIdentity(
                    id=item["id"],
                    repository=item["repository"],
                    repository_id=str(index + 100),
                    profile=item["profile"],
                    default_branch="main",
                    commit_sha=str(index + 1) * 40,
                    tree_sha=str(index + 1) * 40,
                )
                for index, item in enumerate(
                    contract["required_adopters"]  # type: ignore[index]
                )
            ]
        ),
        "producer": PRODUCER,
        "adopters": adopters,
        "status": "pass",
        "publication_eligible_observation": True,
    }


def test_release_qualification_contract_is_closed_and_unique() -> None:
    contract = load_contract(REPO_ROOT)

    assert [item["id"] for item in contract["required_adopters"]] == [
        "tradeflow-lite",
        "racecar-standard-v3",
        "agentbus-standard-v3",
    ]
    assert [item["repository"] for item in contract["provider_credentials"]] == [
        "tradeflow", "racecar", "AgentBus",
    ]
    assert [item["provider_credential"] for item in contract["required_adopters"]] == [
        "tradeflow-read", "racecar-read", "agentbus-read",
    ]
    assert contract["qualification"] == {
        "source": "provider_default_branch_transaction",
        "caller_checkout_role": "environment_and_object_cache_only",
        "mutation_scope": "disposable_clone_only",
        "fixed_point": "required",
        "evaluation_scope": "canonical_graph_derived",
        "authority": "local_non_authoritative",
        "execution_provenance": "provider_workflow_run_attempt_job_artifact",
        "continuation": "automatic_release_verifier_dag",
        "source_freshness": "current_at_trusted_collection",
        "product_failure": "blocks_custody_until_attributed",
        "release_asset_identity": "exact_sha256sums",
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("git@github.com:mjgolaszewski/racecar.git", "mjgolaszewski/racecar"),
        ("https://github.com/moranwm/tradeflow.git", "moranwm/tradeflow"),
        ("ssh://git@ssh.github.com/mjgolaszewski/AgentBus.git", "mjgolaszewski/AgentBus"),
    ],
)
def test_github_remote_identity_is_shared_by_submit_and_qualification(
    value: str, expected: str
) -> None:
    assert remote_repository(value) == expected


def test_non_github_or_ambiguous_remote_is_rejected() -> None:
    with pytest.raises(GitHubValueError):
        remote_repository("/docker/racecar")


def test_release_assets_require_exact_wheel_sdist_and_digests(tmp_path: Path) -> None:
    expected = _assets(tmp_path)

    assert _release_assets(tmp_path) == (
        "2.2.1",
        dict(sorted(_build_assets(tmp_path, expected).items())),
        dict(sorted(expected.items())),
    )
    (tmp_path / "bcf_governance-2.2.1.tar.gz").write_bytes(b"changed")
    with pytest.raises(ReleaseQualificationError, match="checksum inventory is not exact"):
        _release_assets(tmp_path)


def test_archive_projection_cannot_replace_complete_build_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    archive_digests = _assets(assets)
    release_commit = "a" * 40
    release_tree = "b" * 40
    manifest = _build_manifest(
        tmp_path / "release-build-manifest.json",
        archive_digests,
        commit=release_commit,
        tree=release_tree,
    )
    monkeypatch.setattr(
        qualification,
        "resolve_main",
        lambda *_args: MainIdentity("101", "main", release_commit, release_tree),
    )
    source_resolution_called = False

    def unexpected_source_resolution(*_args: object) -> object:
        nonlocal source_resolution_called
        source_resolution_called = True
        raise AssertionError("adopter source resolution must not start")

    monkeypatch.setattr(
        qualification, "resolve_adopter_sources", unexpected_source_resolution
    )

    with pytest.raises(
        ReleaseQualificationError,
        match="release assets are not bound to the current exact build manifest",
    ):
        qualify_release(
            REPO_ROOT,
            provider_api=object(),  # type: ignore[arg-type]
            repository="mjgolaszewski/bcf-governance",
            release_assets=assets,
            release_build_manifest=manifest,
            adopter_roots=(),
            adopter_pythons={},
            producer=PRODUCER,
            output=tmp_path / "receipt.json",
        )
    assert source_resolution_called is False


def test_exact_release_runtime_projects_wheel_over_admitted_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / "bcf_governance-2.2.1-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    controller = tmp_path / "controller"
    calls: list[tuple[list[str], dict[str, str] | None]] = []

    def run(
        argv: list[str] | tuple[str, ...], *, cwd: Path,
        env: dict[str, str] | None = None,
    ) -> str:
        del cwd
        calls.append((list(argv), env))
        if len(argv) == 4 and list(argv)[1:3] == ["-P", "-c"]:
            return json.dumps({
                "distribution_root": str(controller),
                "executable": str(controller / "bin/python"),
                "module_file": str(controller / "bcf_governance/__init__.py"),
                "requirements": [
                    {
                        "installed": "6.0.2",
                        "name": "PyYAML",
                        "required": ">=6.0,<7",
                        "satisfied": True,
                    }
                ],
                "version": "2.2.1",
            })
        return ""

    monkeypatch.setattr(qualification, "_run", run)
    command, environment = _exact_release_runtime(
        wheel,
        controller,
        version="2.2.1",
        cwd=tmp_path,
        environment={"GITHUB_TOKEN": "observation-only", "PYTHONPATH": "ambient"},
    )

    assert calls[0][0] == [
        sys.executable, "-m", "venv", str(controller),
    ]
    assert calls[1][0] == [
        str(controller / "bin/python"), "-m", "pip", "install",
        "--disable-pip-version-check", "--no-deps", "--force-reinstall", str(wheel),
    ]
    assert command == (
        str(controller / "bin/python"), "-P", "-c",
        "from bcf_governance.cli import main; main()",
    )
    assert "PYTHONPATH" not in environment
    admitted = (
        controller / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages/bcf-admitted-runtime.pth"
    ).read_text(encoding="utf-8").splitlines()
    assert admitted
    assert all(Path(value).is_absolute() for value in admitted)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"module_file": "/ambient/bcf_governance/__init__.py"}, "shadowed"),
        ({"requirements": [{"installed": None, "name": "PyYAML", "required": ">=6", "satisfied": False}]}, "dependencies"),
        ({"version": "2.2.0"}, "dependencies"),
    ],
)
def test_exact_release_runtime_rejects_shadowing_or_incompatible_dependencies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: dict[str, object],
    message: str,
) -> None:
    wheel = tmp_path / "bcf_governance-2.2.1-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    controller = tmp_path / "controller"
    observation: dict[str, object] = {
        "distribution_root": str(controller),
        "executable": str(controller / "bin/python"),
        "module_file": str(controller / "bcf_governance/__init__.py"),
        "requirements": [],
        "version": "2.2.1",
    }
    observation.update(mutation)

    monkeypatch.setattr(
        qualification,
        "_run",
        lambda argv, **_kwargs: json.dumps(observation)
        if len(argv) == 4 and list(argv)[1:3] == ["-P", "-c"] else "",
    )

    with pytest.raises(ReleaseQualificationError, match=message):
        _exact_release_runtime(
            wheel,
            controller,
            version="2.2.1",
            cwd=tmp_path,
            environment={},
        )


def test_missing_adopter_matrix_fails_before_environment_or_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    digests = _assets(assets)
    release_commit = "a" * 40
    release_tree = "b" * 40
    manifest = _build_manifest(
        tmp_path / "release-build-manifest.json",
        _build_assets(assets, digests),
        commit=release_commit,
        tree=release_tree,
    )
    monkeypatch.setenv("GITHUB_TOKEN", "observation-only")
    monkeypatch.setattr(
        qualification,
        "resolve_main",
        lambda *_args: MainIdentity("101", "main", release_commit, release_tree),
    )
    monkeypatch.setattr(
        qualification,
        "_source_identity",
        lambda _root: ("mjgolaszewski/bcf-governance", release_commit, release_tree),
    )
    monkeypatch.setattr(
        qualification,
        "resolve_adopter_sources",
        lambda *_args: (_ for _ in ()).throw(
            AdopterSourceError("required adopter provider inventory is incomplete")
        ),
    )

    with pytest.raises(
        ReleaseQualificationError,
        match="provider inventory is incomplete",
    ):
        qualify_release(
            REPO_ROOT,
            provider_api=object(),  # type: ignore[arg-type]
            repository="mjgolaszewski/bcf-governance",
            release_assets=assets,
            release_build_manifest=manifest,
            adopter_roots=(),
            adopter_pythons={},
            producer=PRODUCER,
            output=tmp_path / "receipt.json",
        )
    assert not (tmp_path / "receipt.json").exists()


def test_release_subject_identity_cannot_be_replaced_by_adopter_iteration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = load_contract(REPO_ROOT)
    assets = tmp_path / "assets"
    assets.mkdir()
    digests = _assets(assets)
    release_identity = ("mjgolaszewski/bcf-governance", "a" * 40, "b" * 40)
    manifest = _build_manifest(
        tmp_path / "release-build-manifest.json",
        _build_assets(assets, digests),
        commit=release_identity[1],
        tree=release_identity[2],
    )
    identities = {REPO_ROOT.resolve(): release_identity}
    adopter_roots: list[Path] = []
    adopter_pythons: dict[str, Path] = {}
    profiles: dict[str, str] = {}
    calls: list[list[str]] = []
    for index, item in enumerate(contract["required_adopters"], start=1):
        root = tmp_path / item["id"]
        root.mkdir()
        python = root / ".venv/bin/python"
        python.parent.mkdir(parents=True)
        python.write_text("#!/bin/sh\n", encoding="utf-8")
        python.chmod(0o755)
        identity = str(index) * 40
        identities[root.resolve()] = (item["repository"], identity, identity)
        adopter_roots.append(root)
        adopter_pythons[item["repository"]] = python
        profiles[item["id"]] = item["profile"]

    def source_identity(root: Path) -> tuple[str, str, str]:
        return identities[root.resolve()]

    def run(
        argv: list[str], *, cwd: Path, env: object | None = None,
    ) -> str:
        calls.append(list(argv))
        if len(argv) == 4 and argv[1:3] == ["-P", "-c"]:
            controller = Path(argv[0]).parents[1]
            return json.dumps({
                "distribution_root": str(controller),
                "executable": str(controller / "bin/python"),
                "module_file": str(controller / "bcf_governance/__init__.py"),
                "requirements": [],
                "version": "2.2.1",
            })
        if len(argv) == 6 and argv[1:3] == ["-P", "-c"]:
            return json.dumps({
                "status": "prospectively_admissible_provider_proof_required",
                "subject": {"commit_sha": "c" * 40, "tree_sha": "d" * 40},
                "post_merge_evaluation": {"intent": "pr", "target": None},
            })
        if argv[:2] == ["git", "clone"]:
            destination = Path(argv[-1])
            destination.mkdir()
            (destination / "governance-profile.yml").write_text(
                f"profile:\n  selected: {profiles[destination.name]}\n",
                encoding="utf-8",
            )
        if argv[:3] == ["git", "remote", "get-url"]:
            repository = identities[cwd.resolve()][0]
            return f"https://github.com/{repository}.git"
        if "prospective-train" in argv:
            return json.dumps({
                "status": "prospectively_admissible_provider_proof_required",
                "subject": {"commit_sha": "c" * 40, "tree_sha": "d" * 40},
                "post_merge_evaluation": {"intent": "pr", "target": None},
            })
        return ""

    monkeypatch.setenv("GITHUB_TOKEN", "observation-only")
    monkeypatch.setattr(
        qualification,
        "resolve_main",
        lambda *_args: MainIdentity(
            "101", "main", release_identity[1], release_identity[2]
        ),
    )
    sources = tuple(
        AdopterSourceIdentity(
            id=item["id"],
            repository=item["repository"],
            repository_id=str(index + 100),
            profile=item["profile"],
            default_branch="main",
            commit_sha=str(index) * 40,
            tree_sha=str(index) * 40,
        )
        for index, item in enumerate(contract["required_adopters"], start=1)
    )
    monkeypatch.setattr(
        qualification, "resolve_adopter_sources", lambda *_args: sources
    )
    def materialize(source: AdopterSourceIdentity, destination: Path) -> None:
        destination.mkdir()
        (destination / "governance-profile.yml").write_text(
            f"profile:\n  selected: {source.profile}\n", encoding="utf-8"
        )
    monkeypatch.setattr(qualification, "materialize_provider_source", materialize)
    monkeypatch.setattr(qualification, "require_adopter_profile", lambda *_args: None)
    monkeypatch.setattr(qualification, "_source_identity", source_identity)
    monkeypatch.setattr(qualification, "_run", run)
    monkeypatch.setattr(
        qualification, "_isolated_project_python",
        lambda _source, source_python, _destination, _environment: source_python,
    )
    monkeypatch.setattr(
        qualification, "ensure_local_project_python",
        lambda _root, _controller, requested=None: requested or Path(sys.executable),
    )
    monkeypatch.setattr(qualification, "_commit", lambda *_args, **_kwargs: None)

    receipt = qualify_release(
        REPO_ROOT,
        provider_api=object(),  # type: ignore[arg-type]
        repository=release_identity[0],
        release_assets=assets,
        release_build_manifest=manifest,
        adopter_roots=tuple(reversed(adopter_roots)),
        adopter_pythons=adopter_pythons,
        producer=PRODUCER,
        output=tmp_path / "receipt.json",
    )

    assert receipt["subject"] == {
        "repository": release_identity[0],
        "commit_sha": release_identity[1],
        "tree_sha": release_identity[2],
    }
    assert {
        item["repository"]: (item["source_commit"], item["source_tree"])
        for item in receipt["adopters"]
    } == {
        source.repository: (source.commit_sha, source.tree_sha)
        for source in sources
    }
    install_calls = [call for call in calls if call[4:5] == ["install"]]
    assert len(install_calls) == len(contract["required_adopters"])
    assert all(
        "--candidate-qualification-source" in call
        and call[call.index("--candidate-qualification-source") + 1]
        == str(REPO_ROOT.resolve())
        and "--release-assets" not in call
        for call in install_calls
    )
    qualification_calls = [
        call for call in calls if len(call) == 6 and call[1:3] == ["-P", "-c"]
    ]
    assert len(qualification_calls) == len(contract["required_adopters"])
    assert all("prospective-train" not in call for call in calls)


def test_repository_environment_is_copied_and_own_editable_path_is_rebound(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "candidate"
    source.mkdir()
    destination.mkdir()
    environment = source / ".venv"
    venv.EnvBuilder(with_pip=False).create(environment)
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    hook = environment / "lib" / version / "site-packages" / "project.pth"
    hook.write_text(str(source / "src") + "\n", encoding="utf-8")

    projected = _isolated_project_python(
        source,
        environment / "bin/python",
        destination,
        tmp_path / "qualification-environment",
    )

    assert projected == tmp_path / "qualification-environment/bin/python"
    assert not (destination / ".bcf-qualification-venv").exists()
    projected_hook = (
        tmp_path / "qualification-environment/lib" / version
        / "site-packages/project.pth"
    )
    assert projected_hook.read_text(encoding="utf-8") == str(destination / "src") + "\n"


def test_nested_repository_environment_is_copied_from_its_interpreter_root(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "candidate"
    source.mkdir()
    destination.mkdir()
    environment = source / ".artifacts/runtime/execution-state/session/project-environments/exact/venv"
    venv.EnvBuilder(with_pip=False).create(environment)
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    hook = environment / "lib" / version / "site-packages" / "project.pth"
    hook.write_text(str(source / "src") + "\n", encoding="utf-8")

    projected = _isolated_project_python(
        source,
        environment / "bin/python",
        destination,
        tmp_path / "qualification-environment",
    )

    assert projected == tmp_path / "qualification-environment/bin/python"
    assert projected.is_file()
    projected_hook = (
        tmp_path / "qualification-environment/lib" / version
        / "site-packages/project.pth"
    )
    assert projected_hook.read_text(encoding="utf-8") == str(destination / "src") + "\n"
    assert not (tmp_path / "qualification-environment/runtime").exists()


def test_external_virtual_environment_preserves_lexical_package_custody(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    external = tmp_path / "external/.venv/bin/python"
    source.mkdir()
    destination.mkdir()
    external.parent.mkdir(parents=True)
    external.symlink_to(sys.executable)
    observed: list[list[str]] = []

    def run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        observed.append(argv)
        return subprocess.CompletedProcess(argv, 0, '["/isolated/site-packages"]\n', "")

    monkeypatch.setattr(qualification.subprocess, "run", run)

    selected = _isolated_project_python(
        source, external, destination, tmp_path / "unused-copy"
    )

    assert selected == external.absolute()
    assert observed[0][0] == str(external.absolute())


def test_candidate_qualification_derives_the_closed_observation_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from bcf_governance.tooling import prospective_candidate_identity

    captured: dict[str, object] = {}
    monkeypatch.setattr(
        prospective_candidate_identity,
        "canonical_prospective_inputs",
        lambda _root, **_kwargs: {
            "semantic_intent": "pr",
            "evaluation_target": None,
            "subject_commit": "a" * 40,
            "subject_tree": "b" * 40,
        },
    )

    def run(_root: Path, **kwargs: object) -> dict[str, str]:
        captured.update(kwargs)
        return {"status": "prospectively_admissible_provider_proof_required"}

    monkeypatch.setattr(local_pr, "run_prospective_train", run)

    result = qualification.run_candidate_qualification_train(
        tmp_path, Path(sys.executable)
    )

    assert result["status"] == "prospectively_admissible_provider_proof_required"
    assert (
        captured["validation_lane"]
        is LocalValidationLane.ISOLATED_CANDIDATE_QUALIFICATION
    )
    assert captured["semantic_intent"] == "pr"
    assert captured["evaluation_target"] is None
    assert captured["remote"] == "bcf-qualification-base"


def test_qualification_base_remote_is_immutable_at_captured_adopter_subject(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=candidate, check=True)
    subprocess.run(["git", "config", "user.name", "BCF Fixture"], cwd=candidate, check=True)
    subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=candidate, check=True)
    (candidate / "README.md").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=candidate, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "base"], cwd=candidate, check=True)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=candidate, capture_output=True,
        text=True, check=True,
    ).stdout.strip()

    qualification._project_qualification_base_remote(
        candidate, tmp_path / "qualification-base.git", commit
    )
    observed = subprocess.run(
        ["git", "ls-remote", "bcf-qualification-base", "HEAD"],
        cwd=candidate, capture_output=True, text=True, check=True,
    ).stdout.split()[0]

    assert observed == commit


def test_qualification_receipt_requires_exact_subject_assets_and_adopters(
    tmp_path: Path,
) -> None:
    contract = load_contract(REPO_ROOT)
    assets = _assets(tmp_path)
    receipt = _receipt(contract, assets)
    kwargs = {
        "contract": contract,
        "contract_sha256": "c" * 64,
        "repository": "owner/repo",
        "commit_sha": "a" * 40,
        "tree_sha": "b" * 40,
        "version": "2.2.1",
        "assets": assets,
        "producer": PRODUCER,
    }

    assert validate_qualification_receipt(receipt, **kwargs) == receipt
    mutations = []
    for key, value in (
        ("authority", True),
        ("publication_eligible_observation", False),
        ("status", "failed"),
    ):
        mutation = copy.deepcopy(receipt)
        mutation[key] = value
        mutations.append(mutation)
    missing = copy.deepcopy(receipt)
    missing["adopters"].pop()  # type: ignore[union-attr]
    mutations.append(missing)
    wrong = copy.deepcopy(receipt)
    wrong["adopters"][0]["repository"] = "owner/unrelated"  # type: ignore[index]
    mutations.append(wrong)
    for mutation in mutations:
        with pytest.raises(ReleaseQualificationError):
            validate_qualification_receipt(mutation, **kwargs)

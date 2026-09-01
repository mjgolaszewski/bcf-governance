from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from bcf_governance.tooling import preflight


REPO_ROOT = Path(__file__).resolve().parents[1]


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True)


def _committed_repo(tmp_path: Path, relative: str, content: str) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _git(repo, "init")
    _git(repo, "config", "user.email", "preflight@example.test")
    _git(repo, "config", "user.name", "Preflight Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "fixture")
    return repo


def test_syntax_preflight_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    repo = _committed_repo(tmp_path, "duplicate.yml", "owner: first\nowner: second\n")

    with pytest.raises(preflight.PreflightError, match="duplicate YAML key"):
        preflight._syntax_checks(repo)


def test_source_preflight_wrapper_runs_without_an_installed_package(
    tmp_path: Path,
) -> None:
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts/preflight_governance.py"), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Run cheap governance preflight" in result.stdout


def test_syntax_preflight_rejects_invalid_python(tmp_path: Path) -> None:
    repo = _committed_repo(tmp_path, "broken.py", "def broken(:\n    pass\n")

    with pytest.raises(preflight.PreflightError, match="syntax validation failed"):
        preflight._syntax_checks(repo)


def test_source_entrypoint_preflight_rejects_unbootstrapped_package_import(
    tmp_path: Path,
) -> None:
    repo = _committed_repo(
        tmp_path,
        ".github/scripts/release.py",
        "from bcf_governance.tooling import release_closure\n"
        "if __name__ == '__main__':\n"
        "    pass\n",
    )

    with pytest.raises(preflight.PreflightError, match="before establishing"):
        preflight._source_entrypoint_authority(repo)


def test_source_entrypoint_preflight_derives_valid_roots_without_a_file_list(
    tmp_path: Path,
) -> None:
    repo = _committed_repo(
        tmp_path,
        "scripts/operator.py",
        "import sys\nfrom pathlib import Path\n"
        "sys.path.insert(0, str(Path(__file__).resolve().parents[1]))\n"
        "from bcf_governance.tooling import preflight\n"
        "if __name__ == '__main__':\n"
        "    pass\n",
    )
    github = repo / ".github/scripts/worker.py"
    github.parent.mkdir(parents=True)
    github.write_text(
        "import sys\nfrom pathlib import Path\n"
        "REPO_ROOT = Path(__file__).resolve().parents[2]\n"
        "if str(REPO_ROOT) not in sys.path:\n"
        "    sys.path.insert(0, str(REPO_ROOT))\n"
        "from bcf_governance.tooling import release_closure\n"
        "if __name__ == '__main__':\n"
        "    pass\n",
        encoding="utf-8",
    )
    private_runtime = repo / "scripts/_bcf_runtime/owned.py"
    private_runtime.parent.mkdir(parents=True)
    private_runtime.write_text(
        "from bcf_governance import __version__\n"
        "if __name__ == '__main__':\n"
        "    pass\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "add github entrypoint")

    assert preflight._source_entrypoint_authority(repo) == {
        "discovered": 2,
        "package_imports_checked": 2,
    }


def test_repository_source_entrypoints_establish_import_authority() -> None:
    report = preflight._source_entrypoint_authority(REPO_ROOT)

    assert report["discovered"] > 0
    assert report["package_imports_checked"] > 0


def test_dirty_tree_fails_before_other_preflight_work(tmp_path: Path) -> None:
    repo = _committed_repo(tmp_path, "tracked.txt", "clean\n")
    (repo / "tracked.txt").write_text("dirty\n", encoding="utf-8")

    with pytest.raises(preflight.PreflightError, match="clean committed HEAD"):
        preflight._git_state(repo)


def test_negative_control_preflight_rejects_stale_source_target(tmp_path: Path) -> None:
    repo = _committed_repo(tmp_path, "owner.py", "AUTHORITY = 'new'\n")
    contracts = repo / "governance/gate-contracts.yml"
    contracts.parent.mkdir(parents=True)
    contracts.write_text(
        "gates:\n"
        "  contract-test:\n"
        "    negative_controls:\n"
        "    - id: stale-owner-must-fail\n"
        "      mutation:\n"
        "        path: owner.py\n"
        "        search: \"AUTHORITY = 'old'\"\n"
        "        replace: \"AUTHORITY = 'mutant'\"\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "add control")

    with pytest.raises(preflight.PreflightError, match="stale-owner-must-fail"):
        preflight._negative_control_targets(repo)


def test_negative_control_preflight_accepts_unique_tracked_target(tmp_path: Path) -> None:
    repo = _committed_repo(tmp_path, "owner.py", "AUTHORITY = 'new'\n")
    contracts = repo / "governance/gate-contracts.yml"
    contracts.parent.mkdir(parents=True)
    contracts.write_text(
        "gates:\n"
        "  contract-test:\n"
        "    negative_controls:\n"
        "    - id: current-owner-must-fail\n"
        "      mutation:\n"
        "        path: owner.py\n"
        "        search: \"AUTHORITY = 'new'\"\n"
        "        replace: \"AUTHORITY = 'mutant'\"\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "add control")

    assert preflight._negative_control_targets(repo) == 1


def test_negative_control_preflight_rejects_stale_oracle_node(tmp_path: Path) -> None:
    repo = _committed_repo(tmp_path, "owner.py", "AUTHORITY = 'new'\n")
    manifest = repo / "governance/test-manifests/contract-test.txt"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("tests.test_owner::test_current\n", encoding="utf-8")
    contracts = repo / "governance/gate-contracts.yml"
    contracts.write_text(
        "gates:\n"
        "  contract-test:\n"
        "    evidence:\n"
        "      test_contract:\n"
        "        expected_node_manifest: governance/test-manifests/contract-test.txt\n"
        "    negative_controls:\n"
        "    - id: stale-oracle-must-fail\n"
        "      mutation: {path: owner.py, search: new, replace: mutant}\n"
        "      oracle:\n"
        "        kind: test_node_failure\n"
        "        node_ids: [tests.test_owner::test_removed]\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "add oracle")

    with pytest.raises(preflight.PreflightError, match="stale-oracle-must-fail"):
        preflight._negative_control_targets(repo)


def test_preflight_allocates_session_only_after_all_deterministic_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    repo = tmp_path / "repo"
    repo.mkdir()

    monkeypatch.setattr(
        preflight, "_git_state", lambda _: {"commit_sha": "a" * 40, "tree_sha": "b" * 40}
    )
    monkeypatch.setattr(preflight, "_syntax_checks", lambda _: {"python": 1})
    monkeypatch.setattr(preflight, "_interpreter_requirements", lambda *_: {"pytest": "9.0.3"})
    monkeypatch.setattr(preflight, "_source_entrypoint_authority", lambda _: {"package_imports_checked": 1})
    monkeypatch.setattr(preflight, "validate_repo_root", lambda _: None)
    monkeypatch.setattr(preflight, "_workflow_authority", lambda _: 12)
    monkeypatch.setattr(preflight, "_self_controller", lambda _: 6)
    monkeypatch.setattr(preflight, "_negative_control_targets", lambda _: 1)
    monkeypatch.setattr(
        preflight,
        "_semantic_ownership",
        lambda _: {"status": "conformant", "blocking_violation_count": 0},
    )
    monkeypatch.setattr(preflight, "_vendored_source_locks", lambda _: 0)
    monkeypatch.setattr(preflight, "_pack_manifest", lambda _: {"applicable": False})
    monkeypatch.setattr(preflight, "check_all", lambda *_, **__: {"test": 1})
    monkeypatch.setattr(preflight, "_pr_context", lambda *_: {"applicable": False})
    monkeypatch.setattr(preflight, "_required_gates", lambda _: ["test"])

    class Session:
        manifest_path = tmp_path / "session.json"

    monkeypatch.setattr(
        preflight,
        "allocate_session",
        lambda *_, **__: (calls.append("allocated") or Session()),
    )

    report = preflight.run_preflight(
        repo,
        mode="release",
        python_executable=sys.executable,
        artifact_root=tmp_path / "evidence",
        trace=calls.append,
    )

    assert calls == [
        "git-state",
        "syntax",
        "interpreter",
        "source-entrypoints",
        "governance",
        "workflow-authority",
        "self-controller",
        "negative-controls",
        "semantic-ownership",
        "source-locks",
        "pack-manifest",
        "test-manifests",
        "pr-context",
        "session",
        "allocated",
    ]
    assert report["session_manifest"] == (tmp_path / "session.json").as_posix()
    assert report["workflow_authority"] == 12
    assert report["self_controller"] == 6


def test_stale_pack_manifest_fails_before_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    template = tmp_path / "bcf_governance/pack/template-repo"
    template.mkdir(parents=True)
    (template / "owned.txt").write_text("current\n", encoding="utf-8")
    (template / ".bcf-pack-manifest.json").write_text(
        '{"files":{"owned.txt":{"operation":"copy","sha256":"'
        + "0" * 64
        + '"}}}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(preflight, "_git_state", lambda _: {})
    monkeypatch.setattr(preflight, "_syntax_checks", lambda _: {})
    monkeypatch.setattr(preflight, "_interpreter_requirements", lambda *_: {})
    monkeypatch.setattr(preflight, "_source_entrypoint_authority", lambda _: {})
    monkeypatch.setattr(preflight, "validate_repo_root", lambda _: None)
    monkeypatch.setattr(preflight, "_workflow_authority", lambda _: 0)
    monkeypatch.setattr(preflight, "_self_controller", lambda _: 0)
    monkeypatch.setattr(preflight, "_negative_control_targets", lambda _: 0)
    monkeypatch.setattr(preflight, "_semantic_ownership", lambda _: {})
    monkeypatch.setattr(preflight, "_vendored_source_locks", lambda _: 0)
    monkeypatch.setattr(preflight, "check_all", lambda *_, **__: {})
    monkeypatch.setattr(preflight, "_pr_context", lambda *_: {})
    monkeypatch.setattr(preflight, "_required_gates", lambda _: ["test"])
    monkeypatch.setattr(
        preflight,
        "allocate_session",
        lambda *_, **__: pytest.fail("session allocated after stale pack manifest"),
    )

    with pytest.raises(preflight.PreflightError, match="pack manifest mismatch"):
        preflight.run_preflight(
            tmp_path,
            mode="release",
            python_executable=sys.executable,
            artifact_root=tmp_path / ".artifacts",
        )


def test_workflow_authority_failure_prevents_session_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(preflight, "_git_state", lambda _: {})
    monkeypatch.setattr(preflight, "_syntax_checks", lambda _: {})
    monkeypatch.setattr(preflight, "_interpreter_requirements", lambda *_: {})
    monkeypatch.setattr(preflight, "_source_entrypoint_authority", lambda _: {})
    monkeypatch.setattr(preflight, "validate_repo_root", lambda _: None)
    monkeypatch.setattr(
        preflight,
        "_workflow_authority",
        lambda _: (_ for _ in ()).throw(
            preflight.PreflightError("workflow authority drift")
        ),
    )
    monkeypatch.setattr(preflight, "_self_controller", lambda _: 6)
    monkeypatch.setattr(
        preflight, "allocate_session", lambda *_, **__: calls.append("allocated")
    )

    with pytest.raises(preflight.PreflightError, match="authority drift"):
        preflight.run_preflight(
            repo,
            mode="release",
            python_executable=sys.executable,
            artifact_root=tmp_path / "evidence",
            trace=calls.append,
        )

    assert calls == [
        "git-state",
        "syntax",
        "interpreter",
        "source-entrypoints",
        "governance",
        "workflow-authority",
    ]


def test_missing_interpreter_distribution_fails_before_evidence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "governance").mkdir(parents=True)
    (repo / "governance/gate-contracts.yml").write_text(
        "interpreter_contract: {project_dependencies: true, optional_dependency_groups: [], gate_requirements: {test: [bcf-definitely-absent-tool]}}\n"
        "gates: {test: {}}\n",
        encoding="utf-8",
    )
    (repo / "pyproject.toml").write_text(
        "[project]\nname='fixture'\nversion='1.0.0'\nrequires-python='>=3.11'\ndependencies=[]\n[project.optional-dependencies]\n",
        encoding="utf-8",
    )

    with pytest.raises(preflight.PreflightError, match="dependency contract failed"):
        preflight._interpreter_requirements(repo, Path(sys.executable))


def test_missing_build_backend_requirement_fails_before_evidence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "governance").mkdir(parents=True)
    (repo / "governance/gate-contracts.yml").write_text(
        "interpreter_contract: {project_dependencies: true, build_system_requirements: true, optional_dependency_groups: [], gate_requirements: {}}\n"
        "gates: {}\n",
        encoding="utf-8",
    )
    (repo / "pyproject.toml").write_text(
        "[build-system]\nrequires=['bcf-definitely-absent-build-backend']\n"
        "build-backend='missing.backend'\n"
        "[project]\nname='fixture'\nversion='1.0.0'\nrequires-python='>=3.11'\n"
        "dependencies=[]\n[project.optional-dependencies]\n",
        encoding="utf-8",
    )

    with pytest.raises(preflight.PreflightError, match="dependency contract failed"):
        preflight._interpreter_requirements(repo, Path(sys.executable))


def test_wrong_interpreter_distribution_version_fails_before_evidence(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    (repo / "governance").mkdir(parents=True)
    (repo / "governance/gate-contracts.yml").write_text(
        "interpreter_contract: {project_dependencies: true, optional_dependency_groups: [], gate_requirements: {}}\n"
        "gates: {}\n",
        encoding="utf-8",
    )
    (repo / "pyproject.toml").write_text(
        "[project]\nname='fixture'\nversion='1.0.0'\nrequires-python='>=3.11'\n"
        "dependencies=['pytest<1']\n[project.optional-dependencies]\n",
        encoding="utf-8",
    )

    with pytest.raises(preflight.PreflightError, match=r"pytest .* violates <1"):
        preflight._interpreter_requirements(repo, Path(sys.executable))


def test_symlinked_virtualenv_interpreter_identity_is_validated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    environment = tmp_path / ".venv"
    subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(environment)],
        check=True,
        capture_output=True,
    )

    identity = preflight._interpreter_identity(environment / "bin/python")

    assert (environment / "bin/python").is_symlink()
    assert identity["environment_kind"] == "virtualenv"
    assert identity["environment_root"] == str(environment)


def test_selected_virtualenv_rejects_ambient_identity_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment = tmp_path / ".venv"
    subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(environment)],
        check=True,
        capture_output=True,
    )
    monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / "different-environment"))

    with pytest.raises(preflight.PreflightError, match="does not identify"):
        preflight._interpreter_identity(environment / "bin/python")


def test_broken_project_virtualenv_fails_before_evidence(tmp_path: Path) -> None:
    python = tmp_path / ".venv/bin/python"
    python.parent.mkdir(parents=True)
    python.symlink_to(sys.executable)

    with pytest.raises(preflight.PreflightError, match="has no pyvenv.cfg"):
        preflight._interpreter_identity(python)


def test_interpreter_failure_prevents_session_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(preflight, "_git_state", lambda _: {})
    monkeypatch.setattr(preflight, "_syntax_checks", lambda _: {})
    monkeypatch.setattr(
        preflight,
        "_interpreter_requirements",
        lambda *_: (_ for _ in ()).throw(
            preflight.PreflightError("selected interpreter is missing pip")
        ),
    )
    monkeypatch.setattr(
        preflight, "allocate_session", lambda *_, **__: calls.append("allocated")
    )

    with pytest.raises(preflight.PreflightError, match="missing pip"):
        preflight.run_preflight(
            repo,
            mode="release",
            python_executable=sys.executable,
            artifact_root=tmp_path / "evidence",
            trace=calls.append,
        )

    assert calls == ["git-state", "syntax", "interpreter"]


def test_deterministic_failure_prevents_session_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(preflight, "_git_state", lambda _: {})
    monkeypatch.setattr(
        preflight,
        "_syntax_checks",
        lambda _: (_ for _ in ()).throw(preflight.PreflightError("syntax defect")),
    )
    monkeypatch.setattr(
        preflight, "allocate_session", lambda *_, **__: calls.append("allocated")
    )

    with pytest.raises(preflight.PreflightError, match="syntax defect"):
        preflight.run_preflight(
            repo,
            mode="release",
            python_executable=sys.executable,
            artifact_root=tmp_path / "evidence",
            trace=calls.append,
        )

    assert calls == ["git-state", "syntax"]


def test_semantic_ownership_failure_prevents_session_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    repo = tmp_path / "repo"
    (repo / "governance").mkdir(parents=True)
    (repo / "governance/canonical-representations.yml").write_text(
        "representations: []\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        preflight,
        "run_semantic_ownership_scan",
        lambda _: {
            "verdict": "non_conformant",
            "blocking_violation_count": 1,
            "violations": [
                {
                    "kind": "downstream_normalization",
                    "symbol": "src/duplicate.py::normalize",
                }
            ],
        },
    )
    monkeypatch.setattr(
        preflight, "allocate_session", lambda *_, **__: calls.append("allocated")
    )

    with pytest.raises(preflight.PreflightError, match="downstream_normalization"):
        preflight._semantic_ownership(repo)

    assert calls == []

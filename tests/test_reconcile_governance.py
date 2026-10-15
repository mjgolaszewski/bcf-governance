from __future__ import annotations

from pathlib import Path
import hashlib
import subprocess
import sys

import pytest
import yaml

from bcf_governance.tooling import reconcile_authority_transition as authority_transition
from bcf_governance.tooling import scaffold_governance_artifacts as scaffold
from bcf_governance.cli import COMMANDS
from bcf_governance.tooling.scaffold_governance_artifacts import (
    ReconcileError,
    ReconcileStep,
    converge,
    reconcile_steps,
    check_reconcile_steps,
)
from bcf_governance.tooling.editorial_audit_projection import editorial_base
from bcf_governance.tooling.release_version_projection import (
    ReleaseVersionProjectionError,
    reconcile_release_version_surfaces,
)
from bcf_governance.tooling.profile_surface_generation import (
    reconcile_makefile,
    reconcile_template_workflow,
)
from bcf_governance.tooling.nested_cli_runtime import exact_nested_cli_command
from bcf_governance.tooling.reconcile_authority_transition import (
    ReconcileAuthorityTransitionError,
    apply_workflow_authority_transition,
)


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def test_reconcile_ledger_skips_only_exact_clean_stage(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet", "--initial-branch=main")
    (tmp_path / "schemas").mkdir()
    (tmp_path / "schemas/reconcile-ledger.schema.json").write_bytes(
        (Path(__file__).resolve().parents[1] / "schemas/reconcile-ledger.schema.json").read_bytes()
    )
    source = tmp_path / "source.txt"
    source.write_text("one\n", encoding="utf-8")
    calls: list[str] = []
    step = ReconcileStep(
        "fixture",
        lambda: calls.append("check"),
        lambda: calls.append("apply"),
        watch_paths=("source.txt",),
    )
    first = check_reconcile_steps(tmp_path, [step])
    second = check_reconcile_steps(tmp_path, [step])
    source.write_text("two\n", encoding="utf-8")
    third = check_reconcile_steps(tmp_path, [step])
    assert calls == ["check", "check"]
    assert first["stages"][0]["state"] == "checked"
    assert second["stages"][0]["state"] == "skipped_clean"
    assert third["stages"][0]["state"] == "checked"


@pytest.mark.parametrize("version_source", ["bcf_governance/_version.py", "scripts/_bcf_runtime/_version.py"])
def test_version_only_change_invalidates_clean_release_projection_cache(tmp_path, monkeypatch, version_source):
    _git(tmp_path, "init", "--quiet", "--initial-branch=main")
    root = Path(__file__).resolve().parents[1]
    for directory in ("schemas", "governance", "bcf_governance"):
        (tmp_path / directory).mkdir()
    (tmp_path / "schemas/reconcile-ledger.schema.json").write_bytes(
        (root / "schemas/reconcile-ledger.schema.json").read_bytes()
    )
    (tmp_path / "manifest.yml").write_text("document:\n  version: 1.0.0\n")
    (tmp_path / "governance/public-contracts.yml").write_text("package:\n  version: 1.0.0\n")
    source = tmp_path / version_source
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text('__version__ = "1.0.0"\n')
    monkeypatch.setattr(scaffold, "__version__", "1.0.0")
    monkeypatch.setattr(scaffold, "capability_states", lambda *_a: {})
    monkeypatch.setattr(scaffold, "declared_test_gates", lambda *_a: [])
    def stage():
        return next(item for item in reconcile_steps(tmp_path, Path(sys.executable))
                    if item.step_id == "release-version-surfaces")
    check_reconcile_steps(tmp_path, [stage()])
    assert check_reconcile_steps(tmp_path, [stage()])["stages"][0]["state"] == "skipped_clean"
    source.write_text('__version__ = "2.0.0"\n')
    monkeypatch.setattr(scaffold, "__version__", "2.0.0")
    with pytest.raises(ReleaseVersionProjectionError, match="stale"):
        check_reconcile_steps(tmp_path, [stage()])


def test_reconcile_derives_project_python_before_compiling_test_stages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    selected = tmp_path / ".artifacts/project/bin/python"
    observed: list[Path] = []
    monkeypatch.setattr(scaffold, "declared_test_gates", lambda _root: ("test",))
    monkeypatch.setattr(
        scaffold,
        "ensure_local_project_python",
        lambda root, controller, requested=None: selected,
    )
    monkeypatch.setattr(
        scaffold,
        "reconcile_steps",
        lambda _root, python: observed.append(python) or (),
    )
    monkeypatch.setattr(
        scaffold,
        "check_reconcile_steps",
        lambda _root, _steps, force=False: {"stages": []},
    )

    scaffold.reconcile_main(["--repo-root", str(tmp_path), "--check"])

    assert observed == [selected]
    assert '"status": "clean"' in capsys.readouterr().out


def test_reconcile_forced_check_proves_cached_equivalence(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet", "--initial-branch=main")
    (tmp_path / "schemas").mkdir()
    (tmp_path / "schemas/reconcile-ledger.schema.json").write_bytes(
        (Path(__file__).resolve().parents[1] / "schemas/reconcile-ledger.schema.json").read_bytes()
    )
    (tmp_path / "source.txt").write_text("same\n", encoding="utf-8")
    calls: list[str] = []
    step = ReconcileStep(
        "fixture",
        lambda: calls.append("check"),
        lambda: None,
        watch_paths=("source.txt",),
    )
    selective = check_reconcile_steps(tmp_path, [step])
    forced = check_reconcile_steps(tmp_path, [step], force=True)
    assert calls == ["check", "check"]
    assert selective["convergence_token"] == forced["convergence_token"]


def _authority_transition_repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "--quiet", "--initial-branch=main")
    _git(root, "config", "user.name", "BCF Test")
    _git(root, "config", "user.email", "bcf@example.invalid")
    (root / ".github/workflows").mkdir(parents=True)
    (root / "governance").mkdir()
    (root / ".github/workflows/admission.yml").write_text("name: old\n", encoding="utf-8")
    (root / "intent").write_text("old\n", encoding="utf-8")
    (root / "governance/ci-authority.yml").write_text(
        yaml.safe_dump(
            {
                "workflow_registry": {
                    "admission": {
                        "active_path": ".github/workflows/admission.yml",
                        "trusted_workflow_definition_commit": "0" * 40,
                    }
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    _git(root, "add", "--all")
    _git(root, "commit", "--quiet", "-m", "base")
    _git(root, "switch", "--quiet", "-c", "fix/reconcile")
    return root


def _transition_snapshot(root: Path) -> str:
    digest = hashlib.sha256()
    for relative in sorted(
        value
        for value in _git(root, "ls-files", "--cached", "--others", "--exclude-standard").splitlines()
        if value
    ):
        digest.update(relative.encode() + b"\0" + (root / relative).read_bytes())
    return digest.hexdigest()


def _transition_steps(root: Path, *, fail_authority: bool = False) -> tuple[ReconcileStep, ...]:
    workflow = root / ".github/workflows/admission.yml"
    authority = root / "governance/ci-authority.yml"

    def project() -> None:
        workflow.write_text(
            f"name: {(root / 'intent').read_text(encoding='utf-8').strip()}\n",
            encoding="utf-8",
        )

    def pin() -> None:
        if fail_authority:
            raise ReconcileError("injected authority failure")
        payload = yaml.safe_load(authority.read_text(encoding="utf-8"))
        payload["workflow_registry"]["admission"][
            "trusted_workflow_definition_commit"
        ] = _git(root, "rev-parse", "HEAD")
        authority.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    def check_pin() -> None:
        payload = yaml.safe_load(authority.read_text(encoding="utf-8"))
        commit = payload["workflow_registry"]["admission"][
            "trusted_workflow_definition_commit"
        ]
        assert _git(root, "show", f"{commit}:.github/workflows/admission.yml") == workflow.read_text().strip()

    return (
        ReconcileStep("projection", lambda: None, project),
        ReconcileStep("workflow-authority", check_pin, pin),
    )


def test_reconcile_is_the_canonical_cli_surface() -> None:
    assert "reconcile" in COMMANDS


def test_new_release_editorial_base_is_derived_from_tracking_upstream(
    tmp_path: Path,
) -> None:
    remote = tmp_path / "remote.git"
    root = tmp_path / "repo"
    _git(tmp_path, "init", "--quiet", "--bare", str(remote))
    _git(tmp_path, "init", "--quiet", "--initial-branch=main", str(root))
    _git(root, "config", "user.name", "BCF Test")
    _git(root, "config", "user.email", "bcf@example.invalid")
    (root / "base").write_text("base\n", encoding="utf-8")
    _git(root, "add", "base")
    _git(root, "commit", "--quiet", "-m", "base")
    expected = _git(root, "rev-parse", "HEAD")
    _git(root, "remote", "add", "origin", str(remote))
    _git(root, "push", "--quiet", "--set-upstream", "origin", "main")
    _git(root, "switch", "--quiet", "-c", "release/next")
    _git(root, "branch", "--set-upstream-to", "origin/main")
    (root / "candidate").write_text("candidate\n", encoding="utf-8")
    _git(root, "add", "candidate")
    _git(root, "commit", "--quiet", "-m", "candidate")

    assert editorial_base(root, root / "audits/v9.0.0-editorial-review.yml") == expected


def test_new_release_editorial_base_rejects_untracked_branch(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet", "--initial-branch=main")
    with pytest.raises(ReconcileError, match="tracked upstream"):
        editorial_base(tmp_path, tmp_path / "audits/v9.0.0-editorial-review.yml")


def test_reconcile_declares_one_closed_dependency_order() -> None:
    root = Path(__file__).resolve().parents[1]
    ids = [step.step_id for step in reconcile_steps(root, Path(sys.executable))]
    assert ids[:12] == [
        "authored-phase-state",
        "ci-state-matrix",
        "authored-release-target",
        "ci-provider-permissions",
        "interpreter-environment",
        "structural-limits",
        "release-version-surfaces",
        "profile-makefile",
        "profile-template-workflow",
        "ci-graph-post-merge-scope",
        "pack-projection",
        "semantic-lock",
    ]
    phase_scope = next(step for step in reconcile_steps(root, Path(sys.executable)) if step.step_id == "ci-graph-post-merge-scope")
    active = yaml.safe_load((root / "plans/phase-ledger.yml").read_text())[
        "active_phase"
    ]
    watched = set(phase_scope.watch_paths or ())
    assert active["workitems"] in watched
    assert active["log"] in watched
    authored = next(step for step in reconcile_steps(root, Path(sys.executable)) if step.step_id == "authored-phase-state")
    authored_watched = set(authored.watch_paths or ())
    ledger = yaml.safe_load((root / "plans/phase-ledger.yml").read_text())
    assert {
        record["hotfix_log"]
        for key in ("open_records", "remediation_history")
        for record in ledger["hotfix_lane"][key]
    } <= authored_watched
    assert {
        path
        for path in watched
        if path.startswith("plans/phase-") and path.endswith("-workitems.yml")
    } == {active["workitems"]}
    assert {
        path
        for path in watched
        if path.startswith("phases/phase-") and path.endswith("-log.yml")
    } == {active["log"]}
    assert ids.index("ci-graph-lock") < ids.index("ci-graph-render")
    assert ids.index("ci-graph-render") < ids.index("editorial-audit")
    assert ids.index("editorial-audit") < ids.index("workflow-authority")
    assert ids[-1] == "workflow-authority"


def test_graph_projection_stages_watch_every_declared_value_source() -> None:
    root = Path(__file__).resolve().parents[1]
    graph = yaml.safe_load((root / "governance/ci-graph.yml").read_text())
    expected = {
        str(contract["path"])
        for contract in graph["value_sources"].values()
    }
    steps = reconcile_steps(root, Path(sys.executable))

    for step_id in ("ci-graph-lock", "ci-graph-render"):
        step = next(step for step in steps if step.step_id == step_id)
        assert step.watch_paths is not None
        assert expected <= set(step.watch_paths)


def test_reconcile_owns_template_workflow_projection() -> None:
    reconcile_template_workflow(Path(__file__).resolve().parents[1], apply=False)


def test_reconcile_owns_profile_makefile_projection(tmp_path: Path) -> None:
    governance = tmp_path / "governance"
    governance.mkdir()
    (governance / "gate-contracts.yml").write_text(
        yaml.safe_dump(
            {
                "profile_contract_version": "2.0",
                "gates": {
                    "test": {
                        "invocation": {
                            "argv": ["python3", "-m", "pytest", "-q"],
                            "cwd": ".",
                            "env": {},
                        }
                    }
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (tmp_path / "Makefile.fragment").write_text("stale\n", encoding="utf-8")

    with pytest.raises(ValueError, match="canonical profile projection"):
        reconcile_makefile(tmp_path, apply=False)

    reconcile_makefile(tmp_path, apply=True)
    reconcile_makefile(tmp_path, apply=False)
    assert "--all-planned" in (tmp_path / "Makefile.fragment").read_text()


def test_reconcile_projects_all_derived_release_versions_before_pack_work(
    tmp_path: Path,
) -> None:
    (tmp_path / "governance").mkdir()
    (tmp_path / "manifest.yml").write_text(
        "document:\n  kind: template_governance_pack_manifest\n  version: 2.1.4\n",
        encoding="utf-8",
    )
    contracts = tmp_path / "governance/public-contracts.yml"
    contracts.write_text(
        "document: {kind: public_contract_registry}\npackage:\n  version: 2.1.4\n",
        encoding="utf-8",
    )
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text(
        "Supported package version: `v2.1.4`.\n"
        "python -m pip install releases/download/v2.1.4/"
        "bcf_governance-2.1.4-py3-none-any.whl\n",
        encoding="utf-8",
    )
    (tmp_path / "docs/USAGE.md").write_text(
        "gh release download v2.1.4 --dir /tmp/bcf-v2.1.4\n"
        "  --release-assets /tmp/bcf-v2.1.4\n",
        encoding="utf-8",
    )

    with pytest.raises(ReleaseVersionProjectionError, match="manifest.yml"):
        reconcile_release_version_surfaces(tmp_path, version="2.1.5", apply=False)

    changed = reconcile_release_version_surfaces(
        tmp_path, version="2.1.5", apply=True
    )

    assert changed == (
        "manifest.yml",
        "governance/public-contracts.yml",
        "README.md",
        "docs/USAGE.md",
    )
    assert yaml.safe_load((tmp_path / "manifest.yml").read_text())["document"]["version"] == "2.1.5"
    assert yaml.safe_load(contracts.read_text())["package"]["version"] == "2.1.5"
    assert "2.1.4" not in (tmp_path / "README.md").read_text()
    assert "2.1.4" not in (tmp_path / "docs/USAGE.md").read_text()
    assert not reconcile_release_version_surfaces(
        tmp_path, version="2.1.5", apply=False
    )


def test_reconcile_skips_release_versions_when_adopter_owns_no_release_surfaces(
    tmp_path: Path,
) -> None:
    assert not reconcile_release_version_surfaces(
        tmp_path, version="2.1.5", apply=False
    )
    assert not reconcile_release_version_surfaces(
        tmp_path, version="2.1.5", apply=True
    )


def test_reconcile_rejects_partial_release_version_ownership(tmp_path: Path) -> None:
    (tmp_path / "manifest.yml").write_text(
        "document:\n  version: 2.1.5\n", encoding="utf-8"
    )

    with pytest.raises(ReleaseVersionProjectionError, match="ownership is partial"):
        reconcile_release_version_surfaces(tmp_path, version="2.1.5", apply=True)


def test_reconcile_omits_workflow_authority_when_contract_is_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    (tmp_path / "governance-profile.yml").write_text(
        "semantic_capabilities: {}\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.scaffold_governance_artifacts.declared_test_gates",
        lambda _root: (),
    )

    assert "workflow-authority" not in {
        step.step_id for step in reconcile_steps(tmp_path, Path(sys.executable))
    }


def test_reconcile_omits_semantic_lock_for_closed_disabled_capabilities(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    (tmp_path / "governance-profile.yml").write_text(
        yaml.safe_dump(
            {
                "semantic_capabilities": {
                    "semantic_family_completeness": "disabled",
                    "application_operation_inventory": "disabled",
                    "representation_provenance": "disabled",
                }
            }
        ),
        encoding="utf-8",
    )
    governance = tmp_path / "governance"
    governance.mkdir()
    (governance / "canonical-representations.yml").write_text("representations: []\n", encoding="utf-8")
    monkeypatch.setattr(
        "bcf_governance.tooling.scaffold_governance_artifacts.declared_test_gates",
        lambda _root: (),
    )

    ids = [step.step_id for step in reconcile_steps(tmp_path, Path(sys.executable))]

    assert "semantic-lock" not in ids


def test_reconcile_rejects_disabled_capabilities_with_partial_semantic_runtime(
    tmp_path: Path,
) -> None:
    (tmp_path / "governance-profile.yml").write_text(
        "semantic_capabilities: {}\n", encoding="utf-8"
    )
    governance = tmp_path / "governance"
    governance.mkdir()
    (governance / "semantic-families.yml").write_text("families: []\n", encoding="utf-8")

    with pytest.raises(ReconcileError, match="without an enabled semantic capability"):
        reconcile_steps(tmp_path, Path(sys.executable))


def test_reconcile_separates_tool_runtime_from_selected_project_python(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    (tmp_path / "governance-profile.yml").write_text(
        "semantic_capabilities: {}\n", encoding="utf-8"
    )
    selected = tmp_path / "venv/bin/python"
    selected.parent.mkdir(parents=True)
    selected.symlink_to(sys.executable)
    observed: list[list[str]] = []
    monkeypatch.setattr(
        "bcf_governance.tooling.scaffold_governance_artifacts._run_reconcile_command",
        lambda command, **_kwargs: observed.append(command),
    )
    monkeypatch.setattr(
        "bcf_governance.tooling.scaffold_governance_artifacts.declared_test_gates",
        lambda _root: ("test",),
    )

    steps = reconcile_steps(tmp_path, selected)
    graph_lock = next(step for step in steps if step.step_id == "ci-graph-lock")
    graph_lock.check()
    manifest = next(step for step in steps if step.step_id == "test-manifests")
    manifest.check()

    assert observed[0][0] == str(Path(sys.executable).absolute())
    assert observed[0][0] != str(selected.absolute())
    assert observed[0][1:3] == ["-I", "-c"]
    assert observed[1][0] == str(Path(sys.executable).absolute())
    assert observed[1][1:3] == ["-I", "-c"]
    assert "--all" in observed[1]
    assert observed[1][observed[1].index("--python") + 1] == str(selected.absolute())


def test_nested_cli_rejects_ambient_adopter_and_pythonpath_implementations(
    tmp_path: Path,
) -> None:
    fake = tmp_path / "bcf_governance"
    fake.mkdir()
    (fake / "__init__.py").write_text("\n", encoding="utf-8")
    (fake / "cli.py").write_text(
        "raise SystemExit('ambient adopter implementation executed')\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        exact_nested_cli_command("--version"),
        cwd=tmp_path,
        env={"PYTHONPATH": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().startswith("bcf ")
    assert "ambient adopter implementation" not in result.stderr


def test_reconcile_runs_declared_order_to_a_fixed_point(tmp_path: Path) -> None:
    state = tmp_path / "state"
    calls: list[str] = []

    def first() -> None:
        calls.append("first")
        if not state.exists():
            state.write_text("stable", encoding="utf-8")

    def second() -> None:
        calls.append("second")

    checks: list[str] = []
    steps = (
        ReconcileStep("first", lambda: checks.append("first"), first),
        ReconcileStep("second", lambda: checks.append("second"), second),
    )
    rounds = converge(
        steps,
        lambda: state.read_text(encoding="utf-8") if state.exists() else "absent",
    )
    assert rounds == 2
    assert calls == ["first", "second", "first", "second"]
    assert checks == ["first", "second"]


def test_reconcile_does_not_repeat_checks_already_proven_by_apply(
    tmp_path: Path,
) -> None:
    checks: list[str] = []
    applications: list[str] = []
    steps = (
        ReconcileStep(
            "self-verifying",
            lambda: checks.append("self-verifying"),
            lambda: applications.append("self-verifying"),
            apply_verifies=True,
        ),
        ReconcileStep(
            "independent-check",
            lambda: checks.append("independent-check"),
            lambda: applications.append("independent-check"),
        ),
    )

    rounds = converge(steps, lambda: "stable")

    assert rounds == 1
    assert applications == ["self-verifying", "independent-check"]
    assert checks == ["independent-check"]


def test_reconcile_rejects_non_convergence(tmp_path: Path) -> None:
    state = tmp_path / "state"

    def oscillate() -> None:
        current = state.read_text(encoding="utf-8") if state.exists() else "a"
        state.write_text("b" if current == "a" else "a", encoding="utf-8")

    with pytest.raises(ReconcileError, match="did not converge after 3 rounds"):
        converge(
            (ReconcileStep("oscillating-owner", lambda: None, oscillate),),
            lambda: state.read_text(encoding="utf-8") if state.exists() else "absent",
            max_rounds=3,
        )


def test_reconcile_mechanically_commits_definition_then_exact_authority(
    tmp_path: Path,
) -> None:
    root = _authority_transition_repository(tmp_path)
    base = _git(root, "rev-parse", "HEAD")
    (root / "intent").write_text("new\n", encoding="utf-8")

    result = apply_workflow_authority_transition(
        root,
        step_factory=_transition_steps,
        converge=converge,
        snapshot=_transition_snapshot,
    )

    assert result is not None
    assert _git(root, "rev-parse", f"{result.definition_commit}^") == base
    assert _git(root, "rev-parse", f"{result.authority_commit}^") == result.definition_commit
    authority = yaml.safe_load(
        (root / "governance/ci-authority.yml").read_text(encoding="utf-8")
    )
    assert authority["workflow_registry"]["admission"][
        "trusted_workflow_definition_commit"
    ] == result.definition_commit
    assert _git(root, "status", "--porcelain") == ""
    assert (root / ".github/workflows/admission.yml").read_text() == "name: new\n"


def test_reconcile_decides_transition_only_after_ordered_projection_closure(
    tmp_path: Path,
) -> None:
    root = _authority_transition_repository(tmp_path)
    base = _git(root, "rev-parse", "HEAD")
    (root / "intent").write_text("transient\n", encoding="utf-8")

    def steps(candidate: Path) -> tuple[ReconcileStep, ...]:
        workflow = candidate / ".github/workflows/admission.yml"
        intent = candidate / "intent"

        def canonical_owner() -> None:
            intent.write_text("old\n", encoding="utf-8")

        def render() -> None:
            workflow.write_text(
                f"name: {intent.read_text(encoding='utf-8').strip()}\n",
                encoding="utf-8",
            )

        return (
            ReconcileStep("release-version-surfaces", lambda: None, canonical_owner),
            ReconcileStep("ci-graph-render", lambda: None, render),
            _transition_steps(candidate)[-1],
        )

    result = apply_workflow_authority_transition(
        root,
        step_factory=steps,
        converge=converge,
        snapshot=_transition_snapshot,
    )

    assert result is None
    assert _git(root, "rev-parse", "HEAD") == base
    assert (root / "intent").read_text() == "transient\n"
    assert (root / ".github/workflows/admission.yml").read_text() == "name: old\n"


def test_reconcile_mechanical_commits_do_not_require_ambient_git_identity(
    tmp_path: Path,
) -> None:
    root = _authority_transition_repository(tmp_path)
    _git(root, "config", "--unset-all", "user.name")
    _git(root, "config", "--unset-all", "user.email")
    (root / "intent").write_text("new\n", encoding="utf-8")

    result = apply_workflow_authority_transition(
        root,
        step_factory=_transition_steps,
        converge=converge,
        snapshot=_transition_snapshot,
    )

    assert result is not None
    for commit in (result.definition_commit, result.authority_commit):
        assert _git(root, "show", "-s", "--format=%an <%ae>", commit) == (
            "BCF Reconciler <bcf-reconciler@example.invalid>"
        )


def test_reconcile_authority_transition_preserves_tracked_deletions(
    tmp_path: Path,
) -> None:
    root = _authority_transition_repository(tmp_path)
    obsolete = root / "obsolete-governed-record.yml"
    obsolete.write_text("status: obsolete\n", encoding="utf-8")
    _git(root, "add", obsolete.name)
    _git(root, "commit", "--quiet", "-m", "add governed record")
    (root / "intent").write_text("new\n", encoding="utf-8")
    obsolete.unlink()
    _git(root, "add", "--update")

    result = apply_workflow_authority_transition(
        root,
        step_factory=_transition_steps,
        converge=converge,
        snapshot=_transition_snapshot,
    )

    assert result is not None
    assert not obsolete.exists()
    absent = subprocess.run(
        ["git", "-C", str(root), "cat-file", "-e", f"{result.definition_commit}:{obsolete.name}"],
        capture_output=True,
        check=False,
    )
    assert absent.returncode != 0


def test_reconcile_authority_failure_leaves_original_repository_byte_exact(
    tmp_path: Path,
) -> None:
    root = _authority_transition_repository(tmp_path)
    (root / "intent").write_text("new\n", encoding="utf-8")
    head = _git(root, "rev-parse", "HEAD")
    snapshot = _transition_snapshot(root)
    status = _git(root, "status", "--porcelain=v1")

    with pytest.raises(ReconcileError, match="injected authority failure"):
        apply_workflow_authority_transition(
            root,
            step_factory=lambda candidate: _transition_steps(
                candidate, fail_authority=True
            ),
            converge=converge,
            snapshot=_transition_snapshot,
        )

    assert _git(root, "rev-parse", "HEAD") == head
    assert _transition_snapshot(root) == snapshot
    assert _git(root, "status", "--porcelain=v1") == status


def test_reconcile_rejects_ambiguous_preexisting_workflow_drift_before_mutation(
    tmp_path: Path,
) -> None:
    root = _authority_transition_repository(tmp_path)
    workflow = root / ".github/workflows/admission.yml"
    workflow.write_text("name: hand-authored\n", encoding="utf-8")
    snapshot = _transition_snapshot(root)

    with pytest.raises(
        ReconcileAuthorityTransitionError,
        match="differ from both committed authority and canonical projection",
    ):
        apply_workflow_authority_transition(
            root,
            step_factory=_transition_steps,
            converge=converge,
            snapshot=_transition_snapshot,
        )

    assert _transition_snapshot(root) == snapshot
    assert workflow.read_text() == "name: hand-authored\n"


def test_reconcile_preserves_detached_candidate_identity(tmp_path: Path) -> None:
    root = _authority_transition_repository(tmp_path)
    _git(root, "checkout", "--quiet", "--detach")
    (root / "intent").write_text("new\n", encoding="utf-8")

    result = apply_workflow_authority_transition(
        root,
        step_factory=_transition_steps,
        converge=converge,
        snapshot=_transition_snapshot,
    )

    assert result is not None
    assert _git(root, "rev-parse", "HEAD") == result.authority_commit
    detached = subprocess.run(
        ["git", "-C", str(root), "symbolic-ref", "--quiet", "HEAD"],
        check=False,
    )
    assert detached.returncode == 1


def test_reconcile_rejects_unowned_untracked_input_before_mutation(
    tmp_path: Path,
) -> None:
    root = _authority_transition_repository(tmp_path)
    secret = root / "unreviewed.txt"
    secret.write_text("not candidate input\n", encoding="utf-8")

    with pytest.raises(
        ReconcileAuthorityTransitionError,
        match="new candidate files to be staged or authenticated",
    ):
        apply_workflow_authority_transition(
            root,
            step_factory=_transition_steps,
            converge=converge,
            snapshot=_transition_snapshot,
        )

    assert secret.read_text() == "not candidate input\n"


def test_reconcile_promotion_failure_restores_head_index_and_worktree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    root = _authority_transition_repository(tmp_path)
    (root / "intent").write_text("new\n", encoding="utf-8")
    _git(root, "add", "intent")
    head = _git(root, "rev-parse", "HEAD")
    snapshot = _transition_snapshot(root)
    status = _git(root, "status", "--porcelain=v1")
    original_git = authority_transition._git
    failed = False

    def fail_after_first_promotion(
        candidate: Path,
        *args: str,
        input_bytes: bytes | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal failed
        result = original_git(
            candidate, *args, input_bytes=input_bytes, check=check
        )
        if args[:3] == ("reset", "--hard", "--quiet") and not failed:
            failed = True
            raise ReconcileAuthorityTransitionError("injected promotion failure")
        return result

    monkeypatch.setattr(authority_transition, "_git", fail_after_first_promotion)

    with pytest.raises(
        ReconcileAuthorityTransitionError, match="injected promotion failure"
    ):
        apply_workflow_authority_transition(
            root,
            step_factory=_transition_steps,
            converge=converge,
            snapshot=_transition_snapshot,
        )

    assert _git(root, "rev-parse", "HEAD") == head
    assert _transition_snapshot(root) == snapshot
    assert _git(root, "status", "--porcelain=v1") == status


def test_reconcile_rejects_graph_declared_default_branch_without_remote_head(
    tmp_path: Path,
) -> None:
    root = _authority_transition_repository(tmp_path)
    (root / "governance/ci-graph.yml").write_text(
        "default_branch: trunk\n", encoding="utf-8"
    )
    _git(root, "add", "governance/ci-graph.yml")
    _git(root, "commit", "--quiet", "-m", "declare exact default branch")
    _git(root, "branch", "-m", "trunk")
    (root / "governance/ci-graph.yml").write_text(
        "default_branch: other\n", encoding="utf-8"
    )
    (root / "intent").write_text("new\n", encoding="utf-8")

    with pytest.raises(
        ReconcileAuthorityTransitionError, match="forbidden on the default branch"
    ):
        apply_workflow_authority_transition(
            root,
            step_factory=_transition_steps,
            converge=converge,
            snapshot=_transition_snapshot,
        )


def _release_surface_fixture(root: Path, version: str = '2.5.0') -> None:
    (root / 'governance').mkdir(exist_ok=True)
    (root / 'manifest.yml').write_text(f'document:\n  version: {version}\n')
    (root / 'governance/public-contracts.yml').write_text(f'package:\n  version: {version}\n')


@pytest.mark.parametrize('changelog', [
    '# Changelog\n\n## [Unreleased]\n',
    '# Changelog\n\n## [Unreleased]\n\nRelease target: `2.3.2`\n',
    '# Changelog\n\n## [Unreleased]\n\nRelease target: `2.5.0`\nRelease target: `2.5.0`\n',
    '# Changelog\n\n## [Unreleased]\n\n## [2.3.2] - 2026-10-13\nRelease target: `2.5.0`\n',
])
def test_release_target_contradiction_rejects_before_any_projection(tmp_path, changelog):
    _release_surface_fixture(tmp_path, '2.3.2')
    (tmp_path / 'CHANGELOG.md').write_text(changelog)
    before = {path: path.read_bytes() for path in tmp_path.rglob('*') if path.is_file()}
    with pytest.raises(ReleaseVersionProjectionError, match='changelog'):
        reconcile_release_version_surfaces(tmp_path, version='2.5.0', apply=True)
    assert {path: path.read_bytes() for path in before} == before


@pytest.mark.parametrize('changelog', [
    '# Changelog\n\n## [Unreleased]\n\nRelease target: `2.5.0`\n',
    '# Changelog\n\n## [Unreleased]\n\n## [2.5.0] - 2026-10-15\n',
])
def test_release_target_or_existing_release_is_accepted(tmp_path, changelog):
    _release_surface_fixture(tmp_path)
    (tmp_path / 'CHANGELOG.md').write_text(changelog)
    assert reconcile_release_version_surfaces(tmp_path, version='2.5.0', apply=False) == ()
    assert (tmp_path / 'CHANGELOG.md').read_text() == changelog


@pytest.mark.parametrize('surface', ['README.md', 'docs/USAGE.md', 'CHANGELOG.md'])
def test_release_text_change_invalidates_clean_projection_cache(tmp_path, monkeypatch, surface):
    _git(tmp_path, 'init', '--quiet', '--initial-branch=main')
    _release_surface_fixture(tmp_path)
    (tmp_path / 'schemas').mkdir()
    root = Path(__file__).resolve().parents[1]
    (tmp_path / 'schemas/reconcile-ledger.schema.json').write_bytes(
        (root / 'schemas/reconcile-ledger.schema.json').read_bytes()
    )
    (tmp_path / 'CHANGELOG.md').write_text('# Changelog\n\n## [Unreleased]\n\nRelease target: `2.5.0`\n')
    monkeypatch.setattr(scaffold, '__version__', '2.5.0')
    monkeypatch.setattr(scaffold, 'capability_states', lambda *_a: {})
    monkeypatch.setattr(scaffold, 'declared_test_gates', lambda *_a: [])
    stage = next(item for item in reconcile_steps(tmp_path, Path(sys.executable))
                 if item.step_id == 'release-version-surfaces')
    check_reconcile_steps(tmp_path, [stage])
    assert check_reconcile_steps(tmp_path, [stage])['stages'][0]['state'] == 'skipped_clean'
    path = tmp_path / surface
    path.parent.mkdir(parents=True, exist_ok=True)
    text = '# Changelog\n\n## [Unreleased]\n' if surface == 'CHANGELOG.md' else 'Supported package version: `v2.3.2`.\n'
    path.write_text(text)
    with pytest.raises(ReleaseVersionProjectionError):
        check_reconcile_steps(tmp_path, [stage])


def test_authored_release_target_precedes_every_projection_mutation(tmp_path, monkeypatch):
    _release_surface_fixture(tmp_path, '2.3.2')
    (tmp_path / 'CHANGELOG.md').write_text('# Changelog\n\n## [Unreleased]\n')
    monkeypatch.setattr(scaffold, '__version__', '2.5.0')
    monkeypatch.setattr(scaffold, 'capability_states', lambda *_a: {})
    monkeypatch.setattr(scaffold, 'declared_test_gates', lambda *_a: [])
    steps = reconcile_steps(tmp_path, Path(sys.executable))
    assert steps[0].step_id == 'authored-release-target'
    with pytest.raises(ReleaseVersionProjectionError, match='changelog'):
        steps[0].apply()
    assert yaml.safe_load((tmp_path / 'manifest.yml').read_text())['document']['version'] == '2.3.2'


def test_partial_release_ownership_rejects_in_first_authored_stage(tmp_path, monkeypatch):
    (tmp_path / 'manifest.yml').write_text('document:\n  version: 2.5.0\n')
    monkeypatch.setattr(scaffold, 'capability_states', lambda *_a: {})
    monkeypatch.setattr(scaffold, 'declared_test_gates', lambda *_a: [])
    steps = reconcile_steps(tmp_path, Path(sys.executable))
    assert steps[0].step_id == 'authored-release-target'
    with pytest.raises(ReleaseVersionProjectionError, match='ownership is partial'):
        steps[0].apply()


def _candidate_projection_steps(root: Path) -> tuple[ReconcileStep, ...]:
    output = root / 'derived.txt'

    def project() -> None:
        output.write_text('derived\n')

    def check() -> None:
        assert output.read_text() == 'derived\n'

    return (
        ReconcileStep('projection', check, project),
        ReconcileStep('workflow-authority', lambda: None, lambda: None),
    )


def test_candidate_file_projection_commits_exact_derived_bytes_and_is_idempotent(tmp_path):
    import json

    root = _authority_transition_repository(tmp_path)
    base = _git(root, 'rev-parse', 'HEAD')
    workflow = (root / '.github/workflows/admission.yml').read_bytes()
    authority = (root / 'governance/ci-authority.yml').read_bytes()
    result = apply_workflow_authority_transition(
        root, step_factory=_candidate_projection_steps, converge=converge,
        snapshot=_transition_snapshot, commit_projection=True,
    )
    assert result.source_commit == base
    assert _git(root, 'rev-parse', result.projection_commit + '^') == base
    assert _git(root, 'rev-parse', 'HEAD') == result.projection_commit
    assert _git(root, 'status', '--porcelain') == ''
    assert _git(root, 'diff-tree', '--no-commit-id', '--name-only', '-r', 'HEAD') == 'derived.txt'
    assert (root / '.github/workflows/admission.yml').read_bytes() == workflow
    assert (root / 'governance/ci-authority.yml').read_bytes() == authority
    report = json.loads(authority_transition.result_json(result))
    assert report['status'] == 'committed_candidate_projection'
    assert report['projection_commit'] == result.projection_commit
    assert 'authority_commit' not in report
    assert apply_workflow_authority_transition(
        root, step_factory=_candidate_projection_steps, converge=converge,
        snapshot=_transition_snapshot, commit_projection=True,
    ) is None
    assert _git(root, 'rev-parse', 'HEAD') == result.projection_commit


def test_candidate_file_projection_rejects_dirty_source_before_shadow(tmp_path):
    root = _authority_transition_repository(tmp_path)
    (root / 'intent').write_text('uncommitted\n')
    with pytest.raises(ReconcileAuthorityTransitionError, match='clean committed'):
        apply_workflow_authority_transition(
            root, step_factory=lambda _root: pytest.fail('dirty candidate allocated shadow owners'),
            converge=converge, snapshot=_transition_snapshot, commit_projection=True,
        )
    assert (root / 'intent').read_text() == 'uncommitted\n'


def test_candidate_file_projection_preserves_concurrent_source_movement(tmp_path):
    root = _authority_transition_repository(tmp_path)
    base = _git(root, 'rev-parse', 'HEAD')

    def steps(candidate):
        first, authority = _candidate_projection_steps(candidate)

        def project():
            first.apply()
            (root / 'intent').write_text('concurrent\n')

        return (ReconcileStep('projection', first.check, project), authority)

    with pytest.raises(ReconcileAuthorityTransitionError, match='repository changed'):
        apply_workflow_authority_transition(
            root, step_factory=steps, converge=converge,
            snapshot=_transition_snapshot, commit_projection=True,
        )
    assert _git(root, 'rev-parse', 'HEAD') == base
    assert (root / 'intent').read_text() == 'concurrent\n'
    assert not (root / 'derived.txt').exists()


def test_candidate_file_projection_failure_preserves_original_tree(tmp_path):
    root = _authority_transition_repository(tmp_path)
    base = _git(root, 'rev-parse', 'HEAD')
    original = _transition_snapshot(root)

    def steps(candidate):
        def fail():
            (candidate / 'derived.txt').write_text('partial\n')
            raise ReconcileError('injected projection failure')
        return (ReconcileStep('projection', lambda: None, fail), _candidate_projection_steps(candidate)[1])

    with pytest.raises(ReconcileError, match='injected projection failure'):
        apply_workflow_authority_transition(
            root, step_factory=steps, converge=converge,
            snapshot=_transition_snapshot, commit_projection=True,
        )
    assert _git(root, 'rev-parse', 'HEAD') == base
    assert _transition_snapshot(root) == original
    assert _git(root, 'status', '--porcelain') == ''


def test_candidate_file_projection_rejects_late_trusted_workflow_change(tmp_path):
    root = _authority_transition_repository(tmp_path)
    original = _transition_snapshot(root)

    def steps(candidate):
        def late():
            (candidate / '.github/workflows/admission.yml').write_text('name: late\n')
        return (*_candidate_projection_steps(candidate), ReconcileStep('late', lambda: None, late))

    with pytest.raises(ReconcileAuthorityTransitionError, match='file-only.*trusted workflow'):
        apply_workflow_authority_transition(
            root, step_factory=steps, converge=converge,
            snapshot=_transition_snapshot, commit_projection=True,
        )
    assert _transition_snapshot(root) == original
    assert _git(root, 'status', '--porcelain') == ''


def test_candidate_file_projection_supports_ordinary_adopter_without_authority_registry(tmp_path):
    root = _authority_transition_repository(tmp_path)
    (root / 'governance/ci-authority.yml').unlink()
    _git(root, 'add', '--all')
    _git(root, 'commit', '--quiet', '-m', 'ordinary adopter')
    result = apply_workflow_authority_transition(
        root, step_factory=lambda candidate: _candidate_projection_steps(candidate)[:1],
        converge=converge, snapshot=_transition_snapshot, commit_projection=True,
    )
    assert _git(root, 'rev-parse', 'HEAD') == result.projection_commit
    assert _git(root, 'status', '--porcelain') == ''
    assert not (root / 'governance/ci-authority.yml').exists()


def test_commit_derived_rejects_check_before_runtime_allocation(monkeypatch, tmp_path):
    monkeypatch.setattr(scaffold, 'ensure_local_project_python', lambda *_a, **_k: pytest.fail('allocated runtime for invalid assertion'))
    with pytest.raises(SystemExit) as error:
        scaffold.reconcile_main(['--repo-root', str(tmp_path), '--check', '--commit-derived'])
    assert error.value.code == 2


def test_commit_derived_rejects_dirty_before_runtime_allocation(monkeypatch, tmp_path):
    root = _authority_transition_repository(tmp_path)
    (root / 'intent').write_text('dirty\n')
    monkeypatch.setattr(scaffold, 'ensure_local_project_python', lambda *_a, **_k: pytest.fail('allocated runtime for dirty candidate'))
    with pytest.raises(SystemExit, match='clean committed'):
        scaffold.reconcile_main(['--repo-root', str(root), '--apply', '--commit-derived'])


def test_commit_derived_cli_preserves_existing_projection_owner_result(monkeypatch, tmp_path, capsys):
    import json

    root = _authority_transition_repository(tmp_path)
    base = _git(root, 'rev-parse', 'HEAD')
    monkeypatch.setattr(scaffold, 'declared_test_gates', lambda _root: ())
    monkeypatch.setattr(scaffold, 'reconcile_steps', lambda *_args: _candidate_projection_steps(root))
    monkeypatch.setattr(scaffold, 'record_reconcile_steps', lambda *_args: None)

    def project(observed_root, **kwargs):
        assert observed_root == root
        assert kwargs['commit_projection'] is True
        return authority_transition.ReconcileProjectionResult(2, base, 'a' * 40)

    monkeypatch.setattr(scaffold, 'apply_workflow_authority_transition', project)
    scaffold.reconcile_main(['--repo-root', str(root), '--apply', '--commit-derived'])
    report = json.loads(capsys.readouterr().out)
    assert report['status'] == 'committed_candidate_projection'
    assert report['authority'] is False
    assert report['source_commit'] == base


def test_commit_derived_preserves_trusted_workflow_definition_authority_pair(tmp_path):
    root = _authority_transition_repository(tmp_path)
    (root / 'intent').write_text('new\n')
    _git(root, 'add', 'intent')
    _git(root, 'commit', '--quiet', '-m', 'authored candidate')
    base = _git(root, 'rev-parse', 'HEAD')
    result = apply_workflow_authority_transition(
        root, step_factory=_transition_steps, converge=converge,
        snapshot=_transition_snapshot, commit_projection=True,
    )
    assert _git(root, 'rev-parse', result.definition_commit + '^') == base
    assert _git(root, 'rev-parse', result.authority_commit + '^') == result.definition_commit
    assert _git(root, 'rev-parse', 'HEAD') == result.authority_commit
    assert _git(root, 'status', '--porcelain') == ''


def test_candidate_file_projection_promotion_failure_restores_exact_source(tmp_path):
    root = _authority_transition_repository(tmp_path)
    base = _git(root, 'rev-parse', 'HEAD')
    original = _transition_snapshot(root)
    failed = False

    def snapshot(candidate):
        nonlocal failed
        if candidate == root and not failed and _git(root, 'rev-parse', 'HEAD') != base:
            failed = True
            raise ReconcileAuthorityTransitionError('injected file projection promotion failure')
        return _transition_snapshot(candidate)

    with pytest.raises(ReconcileAuthorityTransitionError, match='injected file projection promotion failure'):
        apply_workflow_authority_transition(
            root, step_factory=_candidate_projection_steps, converge=converge,
            snapshot=snapshot, commit_projection=True,
        )
    assert failed
    assert _git(root, 'rev-parse', 'HEAD') == base
    assert _transition_snapshot(root) == original
    assert _git(root, 'status', '--porcelain') == ''
    assert _git(root, 'for-each-ref', '--format=%(refname)', 'refs/bcf/') == ''


def test_reconcile_force_apply_rejects_before_runtime_allocation(monkeypatch, tmp_path):
    monkeypatch.setattr(scaffold, 'declared_test_gates', lambda _root: ('test',))
    monkeypatch.setattr(scaffold, 'ensure_local_project_python', lambda *_a, **_k: pytest.fail('allocated runtime for contradictory force/apply'))
    with pytest.raises(SystemExit, match='--force is valid only with --check'):
        scaffold.reconcile_main(['--repo-root', str(tmp_path), '--apply', '--force'])


def test_reconcile_authored_phase_rejects_before_runtime_or_shadow(monkeypatch, tmp_path):
    from bcf_governance.tooling.governance_validation import authored_phase_state

    (tmp_path / 'plans').mkdir()
    (tmp_path / 'plans/phase-ledger.yml').write_text('{}')

    def reject(_root):
        raise authored_phase_state.AuthoredPhaseStateError('authored phase contradiction')

    monkeypatch.setattr(authored_phase_state, 'validate_authored_phase_state', reject)
    monkeypatch.setattr(scaffold, 'declared_test_gates', lambda _root: ('test',))
    monkeypatch.setattr(scaffold, 'ensure_local_project_python', lambda *_a, **_k: pytest.fail('allocated runtime before authored phase rejection'))
    monkeypatch.setattr(scaffold, 'apply_workflow_authority_transition', lambda *_a, **_k: pytest.fail('created shadow before authored phase rejection'))
    with pytest.raises(SystemExit, match='authored phase contradiction'):
        scaffold.reconcile_main(['--repo-root', str(tmp_path), '--apply'])


def test_reconcile_authored_release_rejects_before_runtime_or_shadow(monkeypatch, tmp_path):
    def reject(_root, _version):
        raise ReleaseVersionProjectionError('authored release contradiction')

    monkeypatch.setattr(scaffold, 'validate_authored_release_target', reject)
    monkeypatch.setattr(scaffold, 'declared_test_gates', lambda _root: ('test',))
    monkeypatch.setattr(scaffold, 'ensure_local_project_python', lambda *_a, **_k: pytest.fail('allocated runtime before authored release rejection'))
    monkeypatch.setattr(scaffold, 'apply_workflow_authority_transition', lambda *_a, **_k: pytest.fail('created shadow before authored release rejection'))
    with pytest.raises(SystemExit, match='authored release contradiction'):
        scaffold.reconcile_main(['--repo-root', str(tmp_path), '--apply'])

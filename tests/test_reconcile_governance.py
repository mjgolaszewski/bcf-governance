from __future__ import annotations

from pathlib import Path
import hashlib
import subprocess
import sys

import pytest
import yaml

from bcf_governance.tooling import reconcile_authority_transition as authority_transition
from bcf_governance.cli import COMMANDS
from bcf_governance.tooling.scaffold_governance_artifacts import (
    ReconcileError,
    ReconcileStep,
    converge,
    reconcile_steps,
)
from bcf_governance.tooling.release_version_projection import (
    ReleaseVersionProjectionError,
    reconcile_release_version_surfaces,
)
from bcf_governance.tooling.profile_surface_generation import reconcile_makefile
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


def test_reconcile_declares_one_closed_dependency_order() -> None:
    root = Path(__file__).resolve().parents[1]
    ids = [step.step_id for step in reconcile_steps(root, Path(sys.executable))]
    assert ids[:6] == [
        "structural-limits",
        "release-version-surfaces",
        "profile-makefile",
        "ci-graph-post-merge-scope",
        "pack-projection",
        "semantic-lock",
    ]
    assert ids.index("ci-graph-lock") < ids.index("ci-graph-render")
    assert ids.index("ci-graph-render") < ids.index("workflow-authority")
    assert ids[-1] == "editorial-audit"


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

    with pytest.raises(ReleaseVersionProjectionError, match="manifest.yml"):
        reconcile_release_version_surfaces(tmp_path, version="2.1.5", apply=False)

    changed = reconcile_release_version_surfaces(
        tmp_path, version="2.1.5", apply=True
    )

    assert changed == ("manifest.yml", "governance/public-contracts.yml")
    assert yaml.safe_load((tmp_path / "manifest.yml").read_text())["document"]["version"] == "2.1.5"
    assert yaml.safe_load(contracts.read_text())["package"]["version"] == "2.1.5"
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
    assert observed[1][0] == str(Path(sys.executable).absolute())
    assert "--all" in observed[1]
    assert observed[1][observed[1].index("--python") + 1] == str(selected.absolute())


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

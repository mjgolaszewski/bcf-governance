from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest
import yaml

from bcf_governance.tooling.trusted_controller_compatibility import (
    TrustedControllerApplicabilityState,
    TrustedControllerBootstrapIncompatibleError,
    TrustedControllerCompatibilityError,
    TrustedControllerRuntimeStaleError,
    classify_trusted_controller_applicability,
    trusted_runtime_source_files,
    verify_pr_bootstrap_compatibility,
    verify_trusted_controller_compatibility,
)


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _write_runtime(root: Path) -> None:
    tooling = root / "bcf_governance/tooling"
    schemas = root / "bcf_governance/pack/template-repo/schemas"
    tooling.mkdir(parents=True)
    schemas.mkdir(parents=True)
    (root / "bcf_governance/__init__.py").write_text("", encoding="utf-8")
    (root / "bcf_governance/_version.py").write_text(
        '"""Single authoritative BCF release version."""\n\n'
        '__version__ = "1.0.0rc1"\n',
        encoding="utf-8",
    )
    (root / "bcf_governance/cli.py").write_text(
        "from bcf_governance.tooling import ci_github_commands\n", encoding="utf-8"
    )
    (tooling / "__init__.py").write_text("", encoding="utf-8")
    (tooling / "ci_github_commands.py").write_text(
        "from .ci_github_api import GitHubAPI\n", encoding="utf-8"
    )
    (tooling / "ci_github_api.py").write_text(
        "class GitHubAPI: pass\n", encoding="utf-8"
    )
    (schemas / "ci-authority.schema.json").write_text("{}\n", encoding="utf-8")
    (root / "AGENTS.yml").write_text(
        "governance:\n"
        "  structural_schema_contract:\n"
        "    required_schemas: [schemas/ci-authority.schema.json]\n",
        encoding="utf-8",
    )
    workflows = root / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "governance.yml").write_text(
        "name: governance\n"
        "jobs:\n"
        "  evidence:\n"
        "    name: Evidence / ${{ matrix.display_name }}\n"
        "    strategy:\n"
        "      matrix:\n"
        "        include: [{display_name: legacy}]\n"
        "    runs-on: ubuntu-latest\n"
        "    steps: []\n",
        encoding="utf-8",
    )


def _repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "BCF Test")
    _git(root, "config", "user.email", "bcf-test@example.invalid")
    _write_runtime(root)
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "trusted runtime")
    return root, _git(root, "rev-parse", "HEAD")


def test_trusted_runtime_inventory_is_source_derived(tmp_path: Path) -> None:
    root, _ = _repository(tmp_path)

    assert trusted_runtime_source_files(root) == (
        "bcf_governance/__init__.py",
        "bcf_governance/_version.py",
        "bcf_governance/cli.py",
        "bcf_governance/pack/template-repo/schemas/ci-authority.schema.json",
        "bcf_governance/tooling/ci_github_api.py",
        "bcf_governance/tooling/ci_github_commands.py",
    )


def test_target_may_lag_unrelated_files_but_not_trusted_runtime(
    tmp_path: Path,
) -> None:
    root, target = _repository(tmp_path)
    (root / "README.md").write_text("documentation only\n", encoding="utf-8")
    _git(root, "add", "README.md")
    _git(root, "commit", "-q", "-m", "unrelated change")

    report = verify_trusted_controller_compatibility(root, target_commit=target)
    assert report.target_commit == target
    assert report.as_dict()["source_file_count"] == 6

    api = root / "bcf_governance/tooling/ci_github_api.py"
    api.write_text("class GitHubAPI:\n    prerelease = True\n", encoding="utf-8")
    _git(root, "add", api.relative_to(root).as_posix())
    _git(root, "commit", "-q", "-m", "change trusted runtime")

    with pytest.raises(
        TrustedControllerCompatibilityError,
        match="target is stale.*ci_github_api.py",
    ):
        verify_trusted_controller_compatibility(root, target_commit=target)


def test_exact_main_applicability_is_derived_from_canonical_compatibility(
    tmp_path: Path,
) -> None:
    root, target = _repository(tmp_path)

    current = classify_trusted_controller_applicability(
        root, target_commit=target
    )
    assert current.state is TrustedControllerApplicabilityState.CURRENT
    assert current.as_dict() == {
        "controller_state": "current",
        "semantic_evidence_applicable": True,
        "target_commit": target,
    }

    api = root / "bcf_governance/tooling/ci_github_api.py"
    api.write_text("class GitHubAPI:\n    expanded = True\n", encoding="utf-8")
    _git(root, "add", api.relative_to(root).as_posix())
    _git(root, "commit", "-q", "-m", "expand trusted runtime")

    pending = classify_trusted_controller_applicability(
        root, target_commit=target
    )
    assert pending.state is TrustedControllerApplicabilityState.PENDING_ROTATION
    assert pending.as_dict() == {
        "controller_state": "pending_rotation",
        "semantic_evidence_applicable": False,
        "target_commit": target,
    }


def test_target_may_lag_canonical_inert_version_metadata(tmp_path: Path) -> None:
    root, target = _repository(tmp_path)
    version = root / "bcf_governance/_version.py"
    version.write_text(
        '"""Single authoritative BCF release version."""\n\n'
        '__version__ = "1.0.0"\n',
        encoding="utf-8",
    )
    _git(root, "add", version.relative_to(root).as_posix())
    _git(root, "commit", "-q", "-m", "promote stable metadata")

    report = verify_trusted_controller_compatibility(root, target_commit=target)
    assert report.target_commit == target


def test_version_module_executable_drift_is_trusted_runtime_drift(
    tmp_path: Path,
) -> None:
    root, target = _repository(tmp_path)
    version = root / "bcf_governance/_version.py"
    version.write_text(
        '"""Single authoritative BCF release version."""\n\n'
        '__version__ = "1.0.0"\nraise RuntimeError("candidate code")\n',
        encoding="utf-8",
    )
    _git(root, "add", version.relative_to(root).as_posix())
    _git(root, "commit", "-q", "-m", "change executable version module")

    with pytest.raises(
        TrustedControllerCompatibilityError,
        match="target is stale.*_version.py",
    ):
        verify_trusted_controller_compatibility(root, target_commit=target)


def test_noncanonical_version_module_drift_is_trusted_runtime_drift(
    tmp_path: Path,
) -> None:
    root, target = _repository(tmp_path)
    version = root / "bcf_governance/_version.py"
    version.write_text('__version__ = "1.0.0"\n', encoding="utf-8")
    _git(root, "add", version.relative_to(root).as_posix())
    _git(root, "commit", "-q", "-m", "remove canonical metadata contract")

    with pytest.raises(
        TrustedControllerCompatibilityError,
        match="target is stale.*_version.py",
    ):
        verify_trusted_controller_compatibility(root, target_commit=target)


def test_target_must_be_in_current_history(tmp_path: Path) -> None:
    root, _ = _repository(tmp_path)

    with pytest.raises(TrustedControllerCompatibilityError):
        verify_trusted_controller_compatibility(root, target_commit="f" * 40)


def _change_governance_job_inventory(root: Path, value: str) -> None:
    workflow = root / ".github/workflows/governance.yml"
    workflow.write_text(workflow.read_text().replace("legacy", value), encoding="utf-8")
    _git(root, "add", workflow.relative_to(root).as_posix())
    _git(root, "commit", "-q", "-m", "change provider job inventory")


def _install_inventory_capability(root: Path) -> str:
    tooling = root / "bcf_governance/tooling"
    (tooling / "prior_evidence_transport.py").write_text(
        "from .provider_job_inventory import candidate_governance_job_inventory\n",
        encoding="utf-8",
    )
    (tooling / "provider_job_inventory.py").write_text(
        "def candidate_governance_job_inventory(): return ()\n", encoding="utf-8"
    )
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "install candidate inventory capability")
    return _git(root, "rev-parse", "HEAD")


def test_pr_job_inventory_transition_rejects_controller_without_capability(
    tmp_path: Path,
) -> None:
    root, controller_n = _repository(tmp_path)
    base = controller_n
    _change_governance_job_inventory(root, "successor")

    with pytest.raises(
        TrustedControllerBootstrapIncompatibleError,
        match="changed before installed controller support.*provider_job_inventory.py",
    ):
        verify_pr_bootstrap_compatibility(
            root, base_commit=base, target_commit=controller_n
        )


def test_pr_bootstrap_allows_capability_expansion_without_topology_activation(
    tmp_path: Path,
) -> None:
    root, controller_n = _repository(tmp_path)
    base = controller_n
    _install_inventory_capability(root)

    verify_pr_bootstrap_compatibility(
        root, base_commit=base, target_commit=controller_n
    )


def test_pr_job_inventory_transition_accepts_installed_capability_and_rejects_drift(
    tmp_path: Path,
) -> None:
    root, _ = _repository(tmp_path)
    controller_n_plus_one = _install_inventory_capability(root)
    base = controller_n_plus_one
    _change_governance_job_inventory(root, "successor")

    verify_pr_bootstrap_compatibility(
        root, base_commit=base, target_commit=controller_n_plus_one
    )

    capability = root / "bcf_governance/tooling/provider_job_inventory.py"
    capability.write_text("def candidate_governance_job_inventory(): return None\n")
    _git(root, "add", capability.relative_to(root).as_posix())
    _git(root, "commit", "-q", "-m", "mutate inventory capability")
    with pytest.raises(TrustedControllerBootstrapIncompatibleError):
        verify_pr_bootstrap_compatibility(
            root, base_commit=base, target_commit=controller_n_plus_one
        )


def _add_successor_schema(root: Path, *, activate: bool) -> None:
    schema = root / "bcf_governance/pack/template-repo/schemas/reuse.schema.json"
    schema.write_text('{"type": "object"}\n', encoding="utf-8")
    if activate:
        (root / "AGENTS.yml").write_text(
            "governance:\n"
            "  structural_schema_contract:\n"
            "    required_schemas: [schemas/ci-authority.schema.json, schemas/reuse.schema.json]\n",
            encoding="utf-8",
        )
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "add successor schema")


def test_dormant_successor_schema_is_compatible_with_controller_n(
    tmp_path: Path,
) -> None:
    root, controller_n = _repository(tmp_path)
    _add_successor_schema(root, activate=False)

    report = verify_trusted_controller_compatibility(
        root, target_commit=controller_n
    )

    assert not any("reuse.schema.json" in path for path in report.source_files)


def test_schema_activation_is_rejected_by_incompatible_controller_n(
    tmp_path: Path,
) -> None:
    root, controller_n = _repository(tmp_path)
    _add_successor_schema(root, activate=True)

    with pytest.raises(
        TrustedControllerCompatibilityError,
        match="target is stale.*reuse.schema.json",
    ):
        verify_trusted_controller_compatibility(root, target_commit=controller_n)


def test_schema_activation_is_compatible_with_controller_n_plus_one(
    tmp_path: Path,
) -> None:
    root, _ = _repository(tmp_path)
    _add_successor_schema(root, activate=False)
    controller_n_plus_one = _git(root, "rev-parse", "HEAD")
    agents = root / "AGENTS.yml"
    agents.write_text(
        "governance:\n"
        "  structural_schema_contract:\n"
        "    required_schemas: [schemas/ci-authority.schema.json, schemas/reuse.schema.json]\n",
        encoding="utf-8",
    )
    _git(root, "add", "AGENTS.yml")
    _git(root, "commit", "-q", "-m", "activate successor schema")

    report = verify_trusted_controller_compatibility(
        root, target_commit=controller_n_plus_one
    )

    assert any("reuse.schema.json" in path for path in report.source_files)


@pytest.mark.parametrize("change", ["mutate", "remove"])
def test_active_schema_mutation_or_removal_is_rejected(
    tmp_path: Path, change: str
) -> None:
    root, _ = _repository(tmp_path)
    _add_successor_schema(root, activate=True)
    controller_n_plus_one = _git(root, "rev-parse", "HEAD")
    schema = root / "bcf_governance/pack/template-repo/schemas/reuse.schema.json"
    if change == "mutate":
        schema.write_text('{"type": "string"}\n', encoding="utf-8")
    else:
        schema.unlink()
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", f"{change} active schema")

    with pytest.raises(
        TrustedControllerCompatibilityError,
        match="reuse.schema.json",
    ):
        verify_trusted_controller_compatibility(
            root, target_commit=controller_n_plus_one
        )


def _install_rotation_authority_contract(root: Path) -> str:
    source_root = Path(__file__).resolve().parents[1]
    validator = root / "bcf_governance/tooling/ci_authority_contracts.py"
    validator.write_text(
        (source_root / validator.relative_to(root)).read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    schema_path = root / "bcf_governance/pack/template-repo/schemas/ci-authority.schema.json"
    schema = json.loads(
        (source_root / schema_path.relative_to(root)).read_text(encoding="utf-8")
    )
    required = schema["$defs"]["roles"]["required"]
    required.extend(["bootstrap", "probe"])
    schema_path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
    authority = root / "governance/ci-authority.yml"
    authority.parent.mkdir()
    authority_payload = yaml.safe_load(
        (source_root / authority.relative_to(root)).read_text(encoding="utf-8")
    )
    authority_payload["roles"].setdefault(
        "bootstrap", authority_payload["roles"]["finalizer"]
    )
    authority_payload["roles"].setdefault(
        "probe", authority_payload["roles"]["finalizer"]
    )
    authority.write_text(
        yaml.safe_dump(authority_payload, sort_keys=False), encoding="utf-8"
    )
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "install controller N authority contract")
    return _git(root, "rev-parse", "HEAD")


def test_pending_rotation_requires_candidate_authority_consumable_by_installed_n(
    tmp_path: Path,
) -> None:
    root, _ = _repository(tmp_path)
    controller_n = _install_rotation_authority_contract(root)
    schema_path = root / "bcf_governance/pack/template-repo/schemas/ci-authority.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    schema["$defs"]["roles"]["required"] = [
        value
        for value in schema["$defs"]["roles"]["required"]
        if value not in {"bootstrap", "probe"}
    ]
    schema_path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
    authority_path = root / "governance/ci-authority.yml"
    authority = yaml.safe_load(authority_path.read_text(encoding="utf-8"))
    del authority["roles"]["bootstrap"]
    del authority["roles"]["probe"]
    authority_path.write_text(yaml.safe_dump(authority, sort_keys=False), encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "contract rotation roles before N plus one")

    with pytest.raises(
        TrustedControllerBootstrapIncompatibleError,
        match="cannot be consumed by installed controller.*bootstrap.*required",
    ):
        verify_trusted_controller_compatibility(root, target_commit=controller_n)

    with pytest.raises(
        TrustedControllerBootstrapIncompatibleError,
        match="cannot be consumed by installed controller.*bootstrap.*required",
    ):
        classify_trusted_controller_applicability(
            root, target_commit=controller_n
        )


def test_pending_rotation_allows_schema_expansion_when_installed_n_consumes_candidate(
    tmp_path: Path,
) -> None:
    root, _ = _repository(tmp_path)
    controller_n = _install_rotation_authority_contract(root)
    schema_path = root / "bcf_governance/pack/template-repo/schemas/ci-authority.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    schema["$defs"]["roles"]["required"] = [
        value
        for value in schema["$defs"]["roles"]["required"]
        if value not in {"bootstrap", "probe"}
    ]
    schema_path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "expand N plus one authority schema")

    with pytest.raises(TrustedControllerRuntimeStaleError):
        verify_trusted_controller_compatibility(root, target_commit=controller_n)
    classify_trusted_controller_applicability,

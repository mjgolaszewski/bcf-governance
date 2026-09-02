"""Isolated migration from readable legacy contracts to active 1.0 contracts."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import yaml

from .governance_install.transaction import apply_transaction
from .governance_profiles import apply_profile_contract, load_contract, promote
from .profile_governance import MANAGED_PROFILE_PATHS


class ContractMigrationError(ValueError):
    """Raised when a legacy repository is not mechanically migration-ready."""


@dataclass(frozen=True)
class ContractMigrationPlan:
    status: str
    source_profile_version: str
    target_profile_version: str
    authority_version: str
    changed_paths: tuple[str, ...]
    blockers: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def _yaml(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ContractMigrationError(f"required migration input is missing or unsafe: {path}")
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContractMigrationError(f"migration input must be a mapping: {path}")
    return value


def _git_root(repo_root: Path) -> None:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode or Path(result.stdout.strip()).resolve() != repo_root:
        raise ContractMigrationError("contract migration requires a repository root")


def _migration_contract(repo_root: Path, profile: str) -> dict[str, Any]:
    if profile == "lite":
        return load_contract(repo_root, "lite", None, contract_version="2.0")
    return promote(repo_root, profile, None, contract_version="2.0")


def plan_contract_migration(repo_root: Path) -> tuple[ContractMigrationPlan, dict[str, Any] | None]:
    """Plan one fail-closed legacy migration without mutating the repository."""

    repo_root = repo_root.resolve()
    _git_root(repo_root)
    profile_payload = _yaml(repo_root / "governance-profile.yml")
    selected = str(profile_payload.get("profile", {}).get("selected", ""))
    if selected not in {"lite", "standard", "regulated"}:
        raise ContractMigrationError("governance profile must be lite, standard, or regulated")
    source_version = str(profile_payload.get("profile_contract_version", "1.0"))
    if source_version not in {"1.0", "2.0"}:
        raise ContractMigrationError("profile contract version is not readable")

    blockers: list[str] = []
    authority_version = "absent"
    authority_path = repo_root / "governance/ci-authority.yml"
    if authority_path.exists():
        authority_version = str(_yaml(authority_path).get("schema_version", ""))
        if authority_version != "1.1":
            blockers.append(
                "CI authority 1.0 needs mechanically pinned 1.1 workflow identities before migration"
            )
    graph_path = repo_root / "governance/ci-graph.yml"
    if graph_path.exists() and str(_yaml(graph_path).get("profile_contract_version", "1.0")) != "2.0":
        blockers.append(
            "CI graph must be explicitly upgraded to profile contract 2.0 and rendered before migration"
        )
    if source_version == "2.0":
        status = "current" if not blockers else "blocked"
        return (
            ContractMigrationPlan(status, source_version, "2.0", authority_version, (), tuple(blockers)),
            None,
        )
    contract: dict[str, Any] | None = None
    if not blockers:
        try:
            contract = _migration_contract(repo_root, selected)
        except (ValueError, OSError) as exc:
            blockers.append(str(exc))
    status = "blocked" if blockers else "ready"
    return (
        ContractMigrationPlan(
            status,
            source_version,
            "2.0",
            authority_version,
            tuple(MANAGED_PROFILE_PATHS) if not blockers else (),
            tuple(blockers),
        ),
        contract,
    )


def apply_contract_migration(repo_root: Path) -> ContractMigrationPlan:
    """Apply one prevalidated profile migration as an atomic file transaction."""

    plan, contract = plan_contract_migration(repo_root)
    if plan.status == "current":
        return plan
    if plan.status != "ready" or contract is None:
        raise ContractMigrationError("; ".join(plan.blockers))

    def mutate(shadow: Path) -> None:
        apply_profile_contract(shadow, contract, write_workflow=False)
        validation = subprocess.run(
            [
                sys.executable,
                str(shadow / "scripts/validate_governance_yaml.py"),
                "--repo-root",
                str(shadow),
                "--format",
                "json",
                "--compact",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if validation.returncode:
            raise ContractMigrationError(
                "migrated repository failed validation: "
                + (validation.stdout or validation.stderr).strip()
            )

    apply_transaction(
        repo_root.resolve(),
        managed_paths=MANAGED_PROFILE_PATHS,
        mutate_shadow=mutate,
        preserve_git_history=True,
    )
    applied, _ = plan_contract_migration(repo_root)
    if applied.status != "current":
        raise ContractMigrationError("migration did not produce active profile contract 2.0")
    return ContractMigrationPlan(
        "applied", "1.0", "2.0", applied.authority_version, plan.changed_paths, ()
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Migrate readable legacy BCF contracts.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        plan = (
            plan_contract_migration(args.repo_root)[0]
            if args.check
            else apply_contract_migration(args.repo_root)
        )
    except ContractMigrationError as exc:
        print(f"contract-migration-failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    payload = plan.as_dict()
    if args.format == "json":
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"contract-migration-{plan.status}")
        for blocker in plan.blockers:
            print(f"blocker: {blocker}")
    if plan.status == "blocked":
        raise SystemExit(1)

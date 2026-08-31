"""Safely promote a repository to a stricter operational governance profile."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from .governance_install.transaction import apply_transaction, copy_repository_shadow
from .governance_profiles import apply_profile_contract, promote


MANAGED_PROFILE_PATHS = (
    "governance-profile.yml",
    "governance/evidence-policy.yml",
    "governance/gate-contracts.yml",
    "Makefile.fragment",
    "governance/MODEL_RISK_AND_PROVENANCE.md",
    "governance/HOTFIX_LANE.md",
)


def _render_in_shadow(
    repo_root: Path,
    target: str,
    config: Path | None,
    shadow: Path,
    contract_version: str | None,
) -> dict:
    contract = promote(
        repo_root, target, config, contract_version=contract_version
    )
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
    if validation.returncode != 0:
        raise ValueError(
            "promoted profile does not pass structural validation: "
            + (validation.stdout or validation.stderr).strip()
        )
    return contract


def _check(
    repo_root: Path,
    target: str,
    config: Path | None,
    contract_version: str | None,
) -> dict:
    with tempfile.TemporaryDirectory(prefix="bcf-profile-check-") as temporary:
        shadow = Path(temporary) / "repo"
        copy_repository_shadow(repo_root, shadow, preserve_git_history=True)
        return _render_in_shadow(repo_root, target, config, shadow, contract_version)


def main(argv: list[str] | None = None) -> None:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if raw_args and raw_args[0] == "promote":
        raw_args = raw_args[1:]
    parser = argparse.ArgumentParser(
        prog="bcf profile promote",
        description="Promote BCF governance without rescaffolding state.",
    )
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--to", choices=("standard", "regulated"), required=True)
    parser.add_argument(
        "--config",
        type=Path,
        help="Optional replacement gate config; otherwise promote canonical existing contracts.",
    )
    parser.add_argument("--contract-version", choices=("1.0", "2.0"))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(raw_args)
    repo_root = args.repo_root.resolve()
    git_root = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if git_root.returncode != 0 or Path(git_root.stdout.strip()).resolve() != repo_root:
        raise SystemExit("profile promotion requires the root of an initialized Git repository")
    if args.check:
        contract = _check(
            repo_root, args.to, args.config, args.contract_version
        )
        status = "profile-promotion-check-pass"
    else:
        contract = promote(
            repo_root,
            args.to,
            args.config,
            contract_version=args.contract_version,
        )

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
            if validation.returncode != 0:
                raise ValueError(
                    "promoted profile does not pass structural validation: "
                    + (validation.stdout or validation.stderr).strip()
                )

        apply_transaction(
            repo_root,
            managed_paths=MANAGED_PROFILE_PATHS,
            mutate_shadow=mutate,
            preserve_git_history=True,
        )
        status = "profile-promotion-applied"
    payload = {
        "status": "pass",
        "operation": status,
        "target_profile": args.to,
        "profile_contract_version": contract["profile_contract_version"],
        "required_gates": sorted(contract["gates"]),
    }
    if args.format == "json":
        print(json.dumps(payload, sort_keys=True))
    else:
        print(status)
        print(f"target_profile: {args.to}")
        print(f"profile_contract_version: {contract['profile_contract_version']}")
        print("required_gates: " + ", ".join(payload["required_gates"]))


if __name__ == "__main__":
    main()

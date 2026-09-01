"""Operator CLI for CI adoption, local PR parity, and runtime capacity."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .ci_adopt_github import (
    GithubAdoptionError,
    apply_github_adoption,
    plan_github_adoption,
    render_github_adoption,
)
from .ci_authority_pins import CIAuthorityPinError, pin_workflow_authority
from .ci_github_identity import GitHubControllerError
from .ci_self_controller import project_self_controller_pin
from .local_pr import LocalPRError, run_local_pr_validation
from .runtime_capacity import (
    RuntimeCapacityError,
    check_runtime_capacity,
    load_runtime_contract,
)


def _local_pr_command(command: tuple[str, ...]) -> tuple[str, ...]:
    if command and command[0] == "--":
        command = command[1:]
    if command:
        return command
    return (
        sys.executable,
        "scripts/preflight_governance.py",
        "--repo-root",
        ".",
        "--mode",
        "pr",
        "--python",
        sys.executable,
        "--format",
        "text",
    )


def _adopt_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    adopt = subparsers.add_parser("adopt", help="Adopt an explicit CI provider topology.")
    providers = adopt.add_subparsers(dest="provider", required=True)
    github = providers.add_parser("github")
    github.add_argument("--repo-root", type=Path, default=Path.cwd())
    github.add_argument("--default-branch", default="main")
    github.add_argument("--candidate-label", action="append", required=True)
    github.add_argument("--trusted-label", action="append", required=True)
    github.add_argument("--producer-arg", action="append", required=True)
    mode = github.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    github.add_argument("--format", choices=("text", "json"), default="text")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BCF CI authority operations.")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    _adopt_parser(subparsers)
    local = subparsers.add_parser("local-pr", help="Run exact local PR validation.")
    local.add_argument("--repo-root", type=Path, default=Path.cwd())
    local.add_argument("--remote", default="origin")
    local.add_argument("command", nargs=argparse.REMAINDER)
    runtime = subparsers.add_parser("runtime-check", help="Check capacity before heavy CI.")
    runtime.add_argument("--repo-root", type=Path, default=Path.cwd())
    runtime.add_argument("--contract", type=Path, required=True)
    runtime.add_argument("--owned-containers", type=int, required=True)
    runtime.add_argument("--format", choices=("text", "json"), default="text")
    pin = subparsers.add_parser(
        "pin-authority", help="Derive exact workflow authority pins from Git."
    )
    pin.add_argument("--repo-root", type=Path, default=Path.cwd())
    pin.add_argument(
        "--authority", type=Path, default=Path("governance/ci-authority.yml")
    )
    pin.add_argument("--definition-commit", required=True)
    pin.add_argument(
        "--workflow",
        action="append",
        help="Registry reference to pin; omit to derive every registered workflow.",
    )
    pin_mode = pin.add_mutually_exclusive_group(required=True)
    pin_mode.add_argument("--check", action="store_true")
    pin_mode.add_argument("--apply", action="store_true")
    pin.add_argument("--format", choices=("text", "json"), default="text")
    sync = subparsers.add_parser(
        "sync-self-controller",
        help="Project one mechanically compiled self-controller pin.",
    )
    sync.add_argument("--repo-root", type=Path, default=Path.cwd())
    sync.add_argument("--pin", type=Path, required=True)
    sync.add_argument(
        "--confirmation",
        type=Path,
        help="Provider-compiled installation proof; omit while rotation is pending.",
    )
    sync_mode = sync.add_mutually_exclusive_group(required=True)
    sync_mode.add_argument("--check", action="store_true")
    sync_mode.add_argument("--apply", action="store_true")
    sync.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def _print(payload: dict[str, object], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True))
    else:
        for key, value in payload.items():
            print(f"{key}: {value}")


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    try:
        if args.operation == "adopt":
            desired = render_github_adoption(
                default_branch=args.default_branch,
                candidate_labels=tuple(args.candidate_label),
                trusted_labels=tuple(args.trusted_label),
                producer_argv=tuple(args.producer_arg),
            )
            result = (
                apply_github_adoption(args.repo_root.resolve(), desired=desired)
                if args.apply
                else plan_github_adoption(args.repo_root.resolve(), desired=desired)
            )
            _print(
                {"status": result.status, "changed_paths": list(result.changed_paths)},
                args.format,
            )
            return
        if args.operation == "runtime-check":
            contract_path = args.contract
            if not contract_path.is_absolute():
                contract_path = args.repo_root / contract_path
            report = check_runtime_capacity(
                args.repo_root.resolve(),
                load_runtime_contract(contract_path),
                owned_containers=args.owned_containers,
            )
            _print(report.as_dict(), args.format)
            return
        if args.operation == "pin-authority":
            result = pin_workflow_authority(
                args.repo_root,
                authority_path=args.authority,
                definition_commit=args.definition_commit,
                references=tuple(args.workflow or ()),
                apply=args.apply,
            )
            _print(result.as_dict(), args.format)
            if args.check and result.status != "clean":
                raise SystemExit(1)
            return
        if args.operation == "sync-self-controller":
            payload = json.loads(args.pin.read_text(encoding="utf-8"))
            value = payload.get("trusted_controller_artifact")
            confirmation = None
            if args.confirmation is not None:
                confirmation_payload = json.loads(
                    args.confirmation.read_text(encoding="utf-8")
                )
                confirmation = confirmation_payload.get(
                    "trusted_controller_installation"
                )
            result = project_self_controller_pin(
                args.repo_root,
                pin=value,
                confirmation=confirmation,
                apply=args.apply,
            )
            _print(result.as_dict(), args.format)
            if args.check and result.status != "clean":
                raise SystemExit(1)
            return
        command = _local_pr_command(tuple(args.command))
        result = run_local_pr_validation(
            args.repo_root.resolve(), command=command, remote=args.remote
        )
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(result.returncode)
    except (
        CIAuthorityPinError,
        GitHubControllerError,
        GithubAdoptionError,
        LocalPRError,
        RuntimeCapacityError,
    ) as exc:
        raise SystemExit(str(exc)) from exc

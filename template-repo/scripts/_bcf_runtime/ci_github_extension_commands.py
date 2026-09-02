"""CLI adapters for automation, PR certification, and provider protection."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .automation_contracts import AutomationContractError
from .ci_github_api import GitHubAPI, GitHubAPIError
from .ci_github_automation import admit_automation_pr, reconcile_automation_changelog
from .ci_github_cli_io import github_output, github_output_path, required_environment
from .ci_github_controller import environment_api
from .ci_github_identity import GitHubControllerError
from .ci_github_pr import finalize_pr, publish_pr
from .github_protection import apply_protection, inspect_protection


def _event() -> dict[str, object]:
    path = Path(required_environment("GITHUB_EVENT_PATH"))
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_048_576:
        raise GitHubControllerError("GITHUB_EVENT_PATH must be a bounded regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GitHubControllerError("GitHub event payload is invalid") from exc
    if not isinstance(value, dict):
        raise GitHubControllerError("GitHub event payload must be an object")
    return value


def _automation(argv: list[str]) -> dict[str, object]:
    parser = argparse.ArgumentParser(description="Reconcile a trusted automation PR.")
    operations = parser.add_subparsers(dest="operation", required=True)
    for operation in (operations.add_parser("admit"), operations.add_parser("reconcile")):
        operation.add_argument("--repository", required=True)
    args = parser.parse_args(argv)
    if args.operation == "admit":
        return admit_automation_pr(
            environment_api(),
            repository=args.repository,
            admission_run_id=required_environment("GITHUB_RUN_ID"),
            admission_run_attempt=required_environment("GITHUB_RUN_ATTEMPT"),
        )
    writer = GitHubAPI(
        token=required_environment("BCF_AUTOMATION_APP_TOKEN"),
        api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
    )
    return reconcile_automation_changelog(
        environment_api(),
        writer,
        repository=args.repository,
        event=_event(),
        reconciler_run_id=required_environment("GITHUB_RUN_ID"),
        reconciler_run_attempt=required_environment("GITHUB_RUN_ATTEMPT"),
    )


def _pr(argv: list[str]) -> dict[str, object]:
    parser = argparse.ArgumentParser(description="BCF exact-head PR authority.")
    operations = parser.add_subparsers(dest="operation", required=True)
    finalize = operations.add_parser("finalize")
    finalize.add_argument("--repository", required=True)
    finalize.add_argument("--output", type=Path, required=True)
    publish = operations.add_parser("publish")
    publish.add_argument("--repository", required=True)
    publish.add_argument("--bundle", type=Path, required=True)
    publish.add_argument("--target-url", required=True)
    args = parser.parse_args(argv)
    common = {
        "api": environment_api(),
        "repository": args.repository,
        "event": _event(),
    }
    if args.operation == "finalize":
        return finalize_pr(
            **common,
            finalizer_run_id=required_environment("GITHUB_RUN_ID"),
            finalizer_run_attempt=required_environment("GITHUB_RUN_ATTEMPT"),
            output_root=args.output,
        )
    return publish_pr(
        **common,
        publisher_run_id=required_environment("GITHUB_RUN_ID"),
        publisher_run_attempt=required_environment("GITHUB_RUN_ATTEMPT"),
        bundle_root=args.bundle,
        target_url=args.target_url,
    )


def _protection(argv: list[str]) -> dict[str, object]:
    parser = argparse.ArgumentParser(description="Inspect or apply GitHub protection.")
    operations = parser.add_subparsers(dest="operation", required=True)
    for operation in (operations.add_parser("inspect"), operations.add_parser("apply")):
        operation.add_argument("--repository", required=True)
        operation.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    function = apply_protection if args.operation == "apply" else inspect_protection
    return function(
        environment_api(), repo_root=args.repo_root, repository=args.repository
    ).as_dict()


def run_extension_command(argv: list[str]) -> None:
    """Dispatch additive trusted commands without expanding the legacy parser."""

    try:
        operation, remaining = argv[0], argv[1:]
        if operation == "automation":
            result = _automation(remaining)
            output = github_output_path()
        elif operation == "pr":
            result = _pr(remaining)
            output = github_output_path()
        else:
            result = _protection(remaining)
            output = None
        if output is not None:
            github_output(result, path=output)
        print(json.dumps(result, sort_keys=True))
    except (AutomationContractError, GitHubAPIError, GitHubControllerError, OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc

"""CLI for trusted GitHub kickoff, finalization, and publication."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .ci_authority_certification import CICertificationError
from .ci_authority_contracts import CIAuthorityContractError
from .ci_github_api import GitHubAPIError
from .ci_github_controller import (
    GitHubControllerError,
    environment_api,
    finalize,
    kickoff,
    publish,
    result_dict,
)


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise GitHubControllerError(f"trusted workflow environment is missing {name}")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BCF trusted GitHub control plane.")
    operations = parser.add_subparsers(dest="operation", required=True)
    kickoff_parser = operations.add_parser("kickoff")
    kickoff_parser.add_argument("--repository", required=True)
    kickoff_parser.add_argument("--sha", required=True)
    kickoff_parser.add_argument("--control-workflow-id", required=True)
    kickoff_parser.add_argument("--control-workflow-path", required=True)
    kickoff_parser.add_argument("--control-workflow-sha256", required=True)
    kickoff_parser.add_argument("--dispatch-exact-ref", action="store_true")
    finalize_parser = operations.add_parser("finalize")
    finalize_parser.add_argument("--repository", required=True)
    finalize_parser.add_argument("--control-run-id", required=True)
    finalize_parser.add_argument("--control-run-attempt", type=int, required=True)
    finalize_parser.add_argument("--control-workflow-id", required=True)
    finalize_parser.add_argument("--control-workflow-path", required=True)
    finalize_parser.add_argument("--control-workflow-sha256", required=True)
    finalize_parser.add_argument("--output", type=Path, required=True)
    publish_parser = operations.add_parser("publish")
    publish_parser.add_argument("--repository", required=True)
    publish_parser.add_argument("--bundle", type=Path, required=True)
    publish_parser.add_argument("--target-url", required=True)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    try:
        api = environment_api()
        if args.operation == "kickoff":
            result = result_dict(
                kickoff(
                    api,
                    repository=args.repository,
                    expected_sha=args.sha,
                    control_run_id=_required_environment("GITHUB_RUN_ID"),
                    control_run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
                    control_workflow_id=args.control_workflow_id,
                    control_workflow_path=args.control_workflow_path,
                    control_workflow_sha256=args.control_workflow_sha256,
                    dispatch_exact_ref=args.dispatch_exact_ref,
                )
            )
        elif args.operation == "finalize":
            result = result_dict(
                finalize(
                    api,
                    repository=args.repository,
                    control_run_id=args.control_run_id,
                    control_run_attempt=args.control_run_attempt,
                    control_workflow_id=args.control_workflow_id,
                    control_workflow_path=args.control_workflow_path,
                    control_workflow_sha256=args.control_workflow_sha256,
                    collector_run_id=_required_environment("GITHUB_RUN_ID"),
                    collector_run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
                    output_dir=args.output,
                )
            )
        else:
            result = publish(
                api,
                repository=args.repository,
                bundle_dir=args.bundle,
                target_url=args.target_url,
            )
        print(json.dumps(result, sort_keys=True))
    except (
        CIAuthorityContractError,
        CICertificationError,
        GitHubAPIError,
        GitHubControllerError,
        OSError,
        ValueError,
    ) as exc:
        raise SystemExit(str(exc)) from exc

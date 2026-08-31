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
from .ci_github_identity import resolve_main, resolve_trusted_run


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
    kickoff_parser.add_argument("--control-workflow-id")
    kickoff_parser.add_argument("--control-workflow-path", required=True)
    kickoff_parser.add_argument("--control-workflow-sha256")
    kickoff_parser.add_argument("--dispatch-exact-ref", action="store_true")
    finalize_parser = operations.add_parser("finalize")
    finalize_parser.add_argument("--repository", required=True)
    finalize_parser.add_argument("--control-run-id")
    finalize_parser.add_argument("--control-run-attempt", type=int)
    finalize_parser.add_argument("--resolve-control-run", action="store_true")
    finalize_parser.add_argument("--control-workflow-id")
    finalize_parser.add_argument("--control-workflow-path", required=True)
    finalize_parser.add_argument("--control-workflow-sha256")
    finalize_parser.add_argument("--collector-workflow-id")
    finalize_parser.add_argument("--collector-workflow-path", required=True)
    finalize_parser.add_argument("--collector-workflow-sha256")
    finalize_parser.add_argument("--output", type=Path, required=True)
    publish_parser = operations.add_parser("publish")
    publish_parser.add_argument("--repository", required=True)
    publish_parser.add_argument("--bundle", type=Path, required=True)
    publish_parser.add_argument("--target-url", required=True)
    publish_parser.add_argument("--collector-run-id", required=True)
    publish_parser.add_argument("--collector-run-attempt", type=int, required=True)
    publish_parser.add_argument("--collector-workflow-id")
    publish_parser.add_argument("--collector-workflow-path", required=True)
    publish_parser.add_argument("--collector-workflow-sha256")
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
            explicit_control = args.control_run_id is not None or (
                args.control_run_attempt is not None
            )
            if args.resolve_control_run and explicit_control:
                raise GitHubControllerError(
                    "finalize accepts resolved or explicit control identity, not both"
                )
            if args.resolve_control_run:
                main = resolve_main(api, args.repository)
                control_identity = resolve_trusted_run(
                    api,
                    repository=args.repository,
                    main=main,
                    workflow_path=args.control_workflow_path,
                    expected_event="push",
                    require_success=True,
                    expected_workflow_id=args.control_workflow_id,
                    expected_workflow_sha256=args.control_workflow_sha256,
                )
                control_run_id = control_identity.run_id
                control_run_attempt = control_identity.run_attempt
                control_workflow_id = control_identity.workflow.workflow_id
                control_workflow_sha256 = (
                    control_identity.workflow.trusted_workflow_sha256
                )
            else:
                if args.control_run_id is None or args.control_run_attempt is None:
                    raise GitHubControllerError(
                        "finalize requires --resolve-control-run or an explicit run and attempt"
                    )
                control_run_id = args.control_run_id
                control_run_attempt = args.control_run_attempt
                control_workflow_id = args.control_workflow_id
                control_workflow_sha256 = args.control_workflow_sha256
            result = result_dict(
                finalize(
                    api,
                    repository=args.repository,
                    control_run_id=control_run_id,
                    control_run_attempt=control_run_attempt,
                    control_workflow_id=control_workflow_id,
                    control_workflow_path=args.control_workflow_path,
                    control_workflow_sha256=control_workflow_sha256,
                    collector_run_id=_required_environment("GITHUB_RUN_ID"),
                    collector_run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
                    collector_workflow_id=args.collector_workflow_id,
                    collector_workflow_path=args.collector_workflow_path,
                    collector_workflow_sha256=args.collector_workflow_sha256,
                    output_dir=args.output,
                )
            )
        else:
            result = publish(
                api,
                repository=args.repository,
                bundle_dir=args.bundle,
                target_url=args.target_url,
                collector_run_id=args.collector_run_id,
                collector_run_attempt=args.collector_run_attempt,
                collector_workflow_id=args.collector_workflow_id,
                collector_workflow_path=args.collector_workflow_path,
                collector_workflow_sha256=args.collector_workflow_sha256,
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

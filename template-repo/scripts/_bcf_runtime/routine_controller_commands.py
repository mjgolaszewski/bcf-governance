"""CLI adapter for provider-authenticated routine controller rotation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .ci_github_bundle import write_exclusive
from .ci_github_cli_io import (
    github_output,
    github_output_path,
    required_environment,
)
from .ci_github_controller import environment_api
from .routine_controller_provider import (
    advance_provider_transition,
    authorize_transition,
    dispatch_post_rotation_certification,
    resolve_effective_controller,
)
from .routine_controller_rotation import run_rotation_command


def run_controller_rotation_command(argv: list[str]) -> None:
    """Run the legacy validators or the dormant provider-backed commands."""

    if argv and argv[0] in {"verify", "derive-id"}:
        run_rotation_command(argv)
        return
    parser = argparse.ArgumentParser(
        description="BCF provider-backed controller rotation."
    )
    operations = parser.add_subparsers(dest="operation", required=True)
    authorize = operations.add_parser("authorize")
    authorize.add_argument("--repository", required=True)
    authorize.add_argument("--admission-run-id", required=True)
    authorize.add_argument("--admission-run-attempt", required=True)
    authorize.add_argument("--artifact-dir", type=Path, required=True)
    authorize.add_argument("--output", type=Path, required=True)
    advance = operations.add_parser("advance")
    advance.add_argument("--repository", required=True)
    advance.add_argument("--receipt", type=Path, required=True)
    advance.add_argument(
        "--stage", choices=("bootstrap", "probe", "promotion"), required=True
    )
    advance.add_argument("--rotation-run-id", required=True)
    advance.add_argument("--rotation-run-attempt", required=True)
    advance.add_argument("--output", type=Path, required=True)
    operations.add_parser("resolve").add_argument("--repository", required=True)
    dispatch = operations.add_parser("dispatch-certification")
    dispatch.add_argument("--repository", required=True)
    dispatch.add_argument("--rotation-run-id", required=True)
    dispatch.add_argument("--rotation-run-attempt", required=True)
    args = parser.parse_args(argv)
    api = environment_api()
    output_path = github_output_path()
    if args.operation == "authorize":
        result = authorize_transition(
            api,
            repository=args.repository,
            admission_run_id=args.admission_run_id,
            admission_run_attempt=args.admission_run_attempt,
            artifact_dir=args.artifact_dir,
        )
        outputs = {
            "applicable": str(result["applicable"]).lower(),
            "decision": result["decision"],
            "transition_class": result["transition_class"],
        }
        if result["applicable"]:
            transition = result["transition"]
            write_exclusive(args.output, transition)
            outputs.update(
                {
                    "transition_id": transition["transition_id"],
                    **{
                        f"target_{key}": str(value)
                        for key, value in transition["artifact"].items()
                    },
                }
            )
        else:
            write_exclusive(args.output, result)
            outputs["reason"] = result["reason"]
            if result["decision"] == "alternate_lane_required":
                outputs["alternate_lane"] = result["alternate_lane"]["id"]
    elif args.operation == "advance":
        payload = json.loads(args.receipt.read_text(encoding="utf-8"))
        result = advance_provider_transition(
            api,
            repository=args.repository,
            receipt=payload,
            stage=args.stage,
            rotation_run_id=args.rotation_run_id,
            rotation_run_attempt=args.rotation_run_attempt,
        )
        write_exclusive(args.output, result)
        outputs = {
            "transition_id": result["transition_id"],
            "state": result["state"],
        }
    elif args.operation == "resolve":
        result = resolve_effective_controller(api, repository=args.repository)
        outputs = {
            "controller_source": result["source"],
            **{key: str(value) for key, value in result["pin"].items()},
        }
    else:
        result = dispatch_post_rotation_certification(
            api,
            repository=args.repository,
            callback_run_id=required_environment("GITHUB_RUN_ID"),
            callback_run_attempt=required_environment("GITHUB_RUN_ATTEMPT"),
            rotation_run_id=args.rotation_run_id,
            rotation_run_attempt=args.rotation_run_attempt,
        )
        outputs = result
    github_output(outputs, path=output_path)
    print(json.dumps(result, sort_keys=True))

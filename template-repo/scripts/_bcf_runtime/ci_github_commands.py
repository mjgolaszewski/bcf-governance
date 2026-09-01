"""CLI for trusted GitHub kickoff, finalization, and publication."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sys

from .ci_authority_certification import CICertificationError
from .ci_authority_contracts import CIAuthorityContractError
from .ci_github_api import GitHubAPIError
from .ci_github_bootstrap import install_controller
from .ci_github_callbacks import finalize_callback, publish_callback
from .ci_github_canary import admit_authority_canary, observe_authority_canary
from .ci_github_controller import (
    GitHubControllerError,
    environment_api,
    finalize,
    kickoff,
    publish,
    result_dict,
)
from .ci_github_identity import resolve_main, resolve_trusted_run
from .ci_github_exact_main import (
    admit_exact_main,
    finalize_exact_main,
    publish_exact_main,
)
from .ci_github_release import (
    authorize_release,
    collect_release,
    inspect_release,
    publish_certified_release,
    record_release_build,
    verify_release_build_provider,
)
from .ci_self_controller import (
    compile_self_controller_confirmation,
    compile_self_controller_pin,
    resolve_self_controller_artifact,
)
from .ci_github_bundle import write_exclusive


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise GitHubControllerError(f"trusted workflow environment is missing {name}")
    return value


def _github_output(payload: dict[str, object]) -> None:
    """Write validated scalar controller results directly to GitHub's output file."""

    path_value = _required_environment("GITHUB_OUTPUT")
    path = Path(path_value)
    if path.is_symlink() or not path.is_file():
        raise GitHubControllerError("GITHUB_OUTPUT must be an existing regular file")
    lines: list[str] = []
    for key, value in sorted(payload.items()):
        if not key.replace("_", "").isalnum() or not key[0].isalpha():
            raise GitHubControllerError("controller output name is unsafe")
        if value is None:
            rendered = ""
        elif isinstance(value, bool):
            rendered = str(value).lower()
        elif isinstance(value, (str, int)):
            rendered = str(value)
        else:
            continue
        if "\n" in rendered or "\r" in rendered:
            raise GitHubControllerError("controller output value is multiline")
        lines.append(f"{key}={rendered}\n")
    with path.open("a", encoding="utf-8") as stream:
        stream.writelines(lines)


def _exact_main_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BCF authority-v1.1 exact-main control.")
    operations = parser.add_subparsers(dest="operation", required=True)
    admit = operations.add_parser("admit")
    admit.add_argument("--repository", required=True)
    admit.add_argument("--sha", required=True)
    admit.add_argument("--target-url", required=True)
    finalize_parser = operations.add_parser("finalize")
    finalize_parser.add_argument("--repository", required=True)
    finalize_parser.add_argument("--output", type=Path, required=True)
    publish_parser = operations.add_parser("publish")
    publish_parser.add_argument("--repository", required=True)
    publish_parser.add_argument("--bundle", type=Path, required=True)
    publish_parser.add_argument("--target-url", required=True)
    publish_parser.add_argument("--collector-run-id", required=True)
    publish_parser.add_argument("--collector-run-attempt", type=int, required=True)
    return parser


def _bootstrap(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description="BCF trusted controller bootstrap.")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--artifact-id", required=True)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--provider-digest", required=True)
    parser.add_argument("--producer-run-id", required=True)
    parser.add_argument("--producer-run-attempt", required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--wheel-sha256", required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--tool-cache", type=Path, required=True)
    args = parser.parse_args(argv)
    result = install_controller(
        environment_api(),
        repository=args.repository,
        artifact_dir=args.artifact_dir,
        artifact_id=args.artifact_id,
        artifact_name=args.artifact_name,
        provider_digest=args.provider_digest,
        producer_run_id=args.producer_run_id,
        producer_run_attempt=args.producer_run_attempt,
        repository_id=args.repository_id,
        commit_sha=args.commit,
        tree_sha=args.tree,
        wheel_sha256=args.wheel_sha256,
        selected_python=args.python,
        tool_cache=args.tool_cache,
    )
    _github_output(result)
    print(json.dumps(result, sort_keys=True))


def _exact_main(argv: list[str]) -> None:
    args = _exact_main_parser().parse_args(argv)
    api = environment_api()
    if args.operation == "admit":
        result = admit_exact_main(
            api,
            repository=args.repository,
            expected_sha=args.sha,
            run_id=_required_environment("GITHUB_RUN_ID"),
            run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
            target_url=args.target_url,
        )
    elif args.operation == "finalize":
        result = asdict(
            finalize_exact_main(
                api,
                repository=args.repository,
                collector_run_id=_required_environment("GITHUB_RUN_ID"),
                collector_run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
                output_dir=args.output,
            )
        )
    else:
        result = publish_exact_main(
            api,
            repository=args.repository,
            bundle_dir=args.bundle,
            target_url=args.target_url,
            collector_run_id=args.collector_run_id,
            collector_run_attempt=args.collector_run_attempt,
            publisher_run_id=_required_environment("GITHUB_RUN_ID"),
            publisher_run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
        )
    _github_output(result)
    print(json.dumps(result, sort_keys=True))


def _canary(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description="BCF isolated authority canary.")
    operations = parser.add_subparsers(dest="operation", required=True)
    for operation in (operations.add_parser("admit"), operations.add_parser("observe")):
        operation.add_argument("--repository", required=True)
        operation.add_argument("--sha", required=True)
        operation.add_argument("--target-url", required=True)
    args = parser.parse_args(argv)
    operation = (
        admit_authority_canary if args.operation == "admit" else observe_authority_canary
    )
    result = operation(
        environment_api(),
        repository=args.repository,
        expected_sha=args.sha,
        run_id=_required_environment("GITHUB_RUN_ID"),
        run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
        target_url=args.target_url,
    )
    _github_output(result)
    print(json.dumps(result, sort_keys=True))


def _controller_pin(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description="BCF self-controller pin compiler.")
    operations = parser.add_subparsers(dest="operation", required=True)
    resolve = operations.add_parser("resolve")
    resolve.add_argument("--repository", required=True)
    compile_pin = operations.add_parser("compile")
    compile_pin.add_argument("--repository", required=True)
    compile_pin.add_argument("--artifact-dir", type=Path, required=True)
    compile_pin.add_argument("--output", type=Path, required=True)
    confirm = operations.add_parser("confirm")
    confirm.add_argument("--repository", required=True)
    confirm.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    api = environment_api()
    if args.operation == "resolve":
        subject, artifact = resolve_self_controller_artifact(
            api, repository=args.repository
        )
        result = {**subject, **artifact.as_dict()}
    elif args.operation == "compile":
        pin = compile_self_controller_pin(
            api, repository=args.repository, artifact_dir=args.artifact_dir
        )
        write_exclusive(
            args.output,
            {"schema_version": "1.0", "trusted_controller_artifact": pin},
        )
        result = {**pin, "output": str(args.output)}
    else:
        confirmation = compile_self_controller_confirmation(
            api, repository=args.repository
        )
        write_exclusive(
            args.output,
            {
                "schema_version": "1.0",
                "trusted_controller_installation": confirmation,
            },
        )
        result = {**confirmation, "output": str(args.output)}
    _github_output(result)
    print(json.dumps(result, sort_keys=True))


def _release_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BCF authority-v1.1 release control.")
    operations = parser.add_subparsers(dest="operation", required=True)
    authorize = operations.add_parser("authorize")
    authorize.add_argument("--repository", required=True)
    authorize.add_argument("--bundle", type=Path, required=True)
    authorize.add_argument("--controller-artifact-id", required=True)
    authorize.add_argument("--controller-artifact-name", required=True)
    authorize.add_argument("--controller-run-id", required=True)
    authorize.add_argument("--controller-run-attempt", required=True)
    authorize.add_argument("--controller-provider-digest", required=True)
    authorize.add_argument("--controller-wheel-sha256", required=True)
    authorize.add_argument("--controller-wheel", type=Path, required=True)
    authorize.add_argument("--controller-commit", required=True)
    authorize.add_argument("--controller-tree", required=True)
    authorize.add_argument("--certification-artifact-id", required=True)
    authorize.add_argument("--certification-artifact-name", required=True)
    authorize.add_argument("--certification-run-id", required=True)
    authorize.add_argument("--certification-run-attempt", required=True)
    authorize.add_argument("--certification-provider-digest", required=True)
    authorize.add_argument("--output", type=Path, required=True)
    verify = operations.add_parser("verify")
    verify.add_argument("--repository", required=True)
    verify.add_argument("--authorization", type=Path, required=True)
    verify.add_argument("--build-manifest", type=Path, required=True)
    verify.add_argument("--wheelhouse-manifest", type=Path, required=True)
    verify.add_argument("--lock", type=Path, required=True)
    verify.add_argument("--wheelhouse", type=Path, required=True)
    verify.add_argument("--release-artifact", type=Path, action="append", required=True)
    verify.add_argument("--output", type=Path, required=True)
    build = operations.add_parser("build")
    build.add_argument("--authorization", type=Path, required=True)
    build.add_argument("--wheelhouse-manifest", type=Path, required=True)
    build.add_argument("--lock", type=Path, required=True)
    build.add_argument("--release-artifact", type=Path, action="append", required=True)
    build.add_argument("--artifact-name", required=True)
    build.add_argument("--output", type=Path, required=True)
    collect = operations.add_parser("collect")
    collect.add_argument("--repository", required=True)
    collect.add_argument("--bundle", type=Path, required=True)
    collect.add_argument("--authorization", type=Path, required=True)
    collect.add_argument("--build-manifest", type=Path, required=True)
    collect.add_argument("--verification", type=Path, required=True)
    collect.add_argument("--release-artifact", type=Path, action="append", required=True)
    collect.add_argument("--output", type=Path, required=True)
    collect.add_argument("--verification-artifact-name", required=True)
    for operation in (operations.add_parser("inspect"), operations.add_parser("publish")):
        operation.add_argument("--repository", required=True)
        operation.add_argument("--tag", required=True)
        operation.add_argument("--commit", required=True)
        operation.add_argument("--release-artifact", type=Path, action="append", required=True)
    publish = operations.choices["publish"]
    publish.add_argument("--release-notes", type=Path, required=True)
    publish.add_argument("--receipt", type=Path, required=True)
    publish.add_argument("--receipt-artifact-id", required=True)
    publish.add_argument("--receipt-artifact-name", required=True)
    publish.add_argument("--receipt-provider-digest", required=True)
    return parser


def _release(argv: list[str]) -> None:
    args = _release_parser().parse_args(argv)
    if args.operation == "verify":
        result = verify_release_build_provider(
            environment_api(),
            repository=args.repository,
            authorization_path=args.authorization,
            build_manifest_path=args.build_manifest,
            manifest_path=args.wheelhouse_manifest,
            lock_path=args.lock,
            wheelhouse=args.wheelhouse,
            release_artifacts=args.release_artifact,
            verifier_run_id=_required_environment("GITHUB_RUN_ID"),
            verifier_run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
            output_path=args.output,
        )
    elif args.operation == "build":
        result = record_release_build(
            authorization_path=args.authorization,
            manifest_path=args.wheelhouse_manifest,
            lock_path=args.lock,
            release_artifacts=args.release_artifact,
            run_id=_required_environment("GITHUB_RUN_ID"),
            run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
            artifact_name=args.artifact_name,
            output_path=args.output,
        )
    else:
        api = environment_api()
        if args.operation == "authorize":
            result = authorize_release(
                api,
                repository=args.repository,
                bundle_dir=args.bundle,
                run_id=_required_environment("GITHUB_RUN_ID"),
                run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
                controller={
                    "run_id": args.controller_run_id,
                    "run_attempt": args.controller_run_attempt,
                    "artifact_id": args.controller_artifact_id,
                    "artifact_name": args.controller_artifact_name,
                    "provider_digest": args.controller_provider_digest,
                    "wheel_sha256": args.controller_wheel_sha256,
                    "commit_sha": args.controller_commit,
                    "tree_sha": args.controller_tree,
                },
                certification_artifact={
                    "run_id": args.certification_run_id,
                    "run_attempt": args.certification_run_attempt,
                    "artifact_id": args.certification_artifact_id,
                    "artifact_name": args.certification_artifact_name,
                    "provider_digest": args.certification_provider_digest,
                },
                controller_wheel_path=args.controller_wheel,
                output_path=args.output,
            )
        elif args.operation == "collect":
            result = collect_release(
                api,
                repository=args.repository,
                bundle_dir=args.bundle,
                authorization_path=args.authorization,
                build_manifest_path=args.build_manifest,
                verification_path=args.verification,
                release_artifacts=args.release_artifact,
                collector_run_id=_required_environment("GITHUB_RUN_ID"),
                collector_run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
                verification_artifact_name=args.verification_artifact_name,
                output_path=args.output,
            )
        else:
            assets = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in args.release_artifact
            }
            if len(assets) != len(args.release_artifact):
                raise GitHubControllerError("release asset inventory contains duplicates")
            if args.operation == "inspect":
                result = inspect_release(
                    api, repository=args.repository, tag=args.tag,
                    expected_commit=args.commit, expected_assets=assets,
                )
            else:
                result = publish_certified_release(
                    api, repository=args.repository, tag=args.tag,
                    expected_commit=args.commit,
                    release_artifacts=args.release_artifact,
                    body=args.release_notes.read_text(encoding="utf-8"),
                    receipt_path=args.receipt,
                    receipt_artifact_id=args.receipt_artifact_id,
                    receipt_artifact_name=args.receipt_artifact_name,
                    receipt_provider_digest=args.receipt_provider_digest,
                    publisher_run_id=_required_environment("GITHUB_RUN_ID"),
                    publisher_run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
                )
    _github_output(result)
    print(json.dumps(result, sort_keys=True))


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
    callback_parser = operations.add_parser("finalize-callback")
    callback_parser.add_argument("--repository", required=True)
    callback_parser.add_argument("--control-run-id")
    callback_parser.add_argument("--control-run-attempt", type=int)
    callback_parser.add_argument("--resolve-control-run", action="store_true")
    callback_parser.add_argument("--control-workflow-id")
    callback_parser.add_argument("--control-workflow-path", required=True)
    callback_parser.add_argument("--control-workflow-sha256")
    callback_parser.add_argument("--collector-workflow-id")
    callback_parser.add_argument("--collector-workflow-path", required=True)
    callback_parser.add_argument("--collector-workflow-sha256")
    callback_parser.add_argument("--output", type=Path, required=True)
    publish_parser = operations.add_parser("publish")
    publish_parser.add_argument("--repository", required=True)
    publish_parser.add_argument("--bundle", type=Path, required=True)
    publish_parser.add_argument("--target-url", required=True)
    publish_parser.add_argument("--collector-run-id", required=True)
    publish_parser.add_argument("--collector-run-attempt", type=int, required=True)
    publish_parser.add_argument("--collector-workflow-id")
    publish_parser.add_argument("--collector-workflow-path", required=True)
    publish_parser.add_argument("--collector-workflow-sha256")
    publish_callback_parser = operations.add_parser("publish-callback")
    publish_callback_parser.add_argument("--repository", required=True)
    publish_callback_parser.add_argument("--callback", type=Path, required=True)
    publish_callback_parser.add_argument("--target-url", required=True)
    publish_callback_parser.add_argument("--collector-run-id", required=True)
    publish_callback_parser.add_argument(
        "--collector-run-attempt", type=int, required=True
    )
    publish_callback_parser.add_argument("--collector-workflow-id")
    publish_callback_parser.add_argument("--collector-workflow-path", required=True)
    publish_callback_parser.add_argument("--collector-workflow-sha256")
    return parser


def main(argv: list[str] | None = None) -> None:
    raw = list(sys.argv[1:] if argv is None else argv)
    try:
        if raw and raw[0] == "bootstrap":
            _bootstrap(raw[1:])
            return
        if raw and raw[0] == "exact-main":
            _exact_main(raw[1:])
            return
        if raw and raw[0] == "canary":
            _canary(raw[1:])
            return
        if raw and raw[0] == "controller-pin":
            _controller_pin(raw[1:])
            return
        if raw and raw[0] == "release":
            _release(raw[1:])
            return
        args = _parser().parse_args(raw)
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
        elif args.operation in {"finalize", "finalize-callback"}:
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
            collector_run_id = _required_environment("GITHUB_RUN_ID")
            collector_run_attempt = _required_environment("GITHUB_RUN_ATTEMPT")
            if args.operation == "finalize-callback":
                result = finalize_callback(
                    api,
                    repository=args.repository,
                    control_run_id=control_run_id,
                    control_run_attempt=control_run_attempt,
                    control_workflow_id=control_workflow_id,
                    control_workflow_path=args.control_workflow_path,
                    control_workflow_sha256=control_workflow_sha256,
                    collector_run_id=collector_run_id,
                    collector_run_attempt=collector_run_attempt,
                    collector_workflow_id=args.collector_workflow_id,
                    collector_workflow_path=args.collector_workflow_path,
                    collector_workflow_sha256=args.collector_workflow_sha256,
                    output_root=args.output,
                )
            else:
                result = result_dict(
                    finalize(
                        api,
                        repository=args.repository,
                        control_run_id=control_run_id,
                        control_run_attempt=control_run_attempt,
                        control_workflow_id=control_workflow_id,
                        control_workflow_path=args.control_workflow_path,
                        control_workflow_sha256=control_workflow_sha256,
                        collector_run_id=collector_run_id,
                        collector_run_attempt=collector_run_attempt,
                        collector_workflow_id=args.collector_workflow_id,
                        collector_workflow_path=args.collector_workflow_path,
                        collector_workflow_sha256=args.collector_workflow_sha256,
                        output_dir=args.output,
                    )
                )
        elif args.operation == "publish-callback":
            result = publish_callback(
                api,
                repository=args.repository,
                callback_dir=args.callback,
                target_url=args.target_url,
                collector_run_id=args.collector_run_id,
                collector_run_attempt=args.collector_run_attempt,
                collector_workflow_id=args.collector_workflow_id,
                collector_workflow_path=args.collector_workflow_path,
                collector_workflow_sha256=args.collector_workflow_sha256,
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

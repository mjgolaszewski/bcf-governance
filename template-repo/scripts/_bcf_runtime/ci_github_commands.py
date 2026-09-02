"""CLI for trusted GitHub kickoff, finalization, and publication."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any
from .ci_authority_certification import CICertificationError
from .ci_authority_contracts import CIAuthorityContractError
from .ci_github_api import GitHubAPIError
from .ci_github_bootstrap import install_controller, verify_controller_inventory
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
from .ci_github_release_inputs import (
    load_release_authorization_inputs,
    release_input_outputs,
    release_publication_outputs,
    resolve_release_authorization_inputs,
    resolve_release_publication_inputs,
)
from .ci_github_release_staging import stage_receipt_bundle, stage_verifier_bundle
from .ci_self_controller import (
    compile_self_controller_confirmation,
    compile_self_controller_pin,
    resolve_self_controller_artifact,
)
from .ci_github_bundle import write_exclusive
from .release_asset_inventory import release_asset_paths
from .release_runtime_verification import (
    run_release_runtime_verification,
    runtime_evidence_paths,
)

def _required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise GitHubControllerError(f"trusted workflow environment is missing {name}")
    return value

def _github_output_path() -> Path:
    """Validate the trusted GitHub output channel before authority work begins."""

    path_value = _required_environment("GITHUB_OUTPUT")
    path = Path(path_value)
    if path.is_symlink() or not path.is_file():
        raise GitHubControllerError("GITHUB_OUTPUT must be an existing regular file")
    return path

def _github_output(payload: dict[str, object], *, path: Path) -> None:
    """Write validated scalar controller results to a preflighted output channel."""

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
    github_output = _github_output_path()
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
    _github_output(result, path=github_output)
    print(json.dumps(result, sort_keys=True))


def _exact_main(argv: list[str]) -> None:
    args = _exact_main_parser().parse_args(argv)
    github_output = _github_output_path()
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
    _github_output(result, path=github_output)
    print(json.dumps(result, sort_keys=True))


def _canary(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description="BCF isolated authority canary.")
    operations = parser.add_subparsers(dest="operation", required=True)
    for operation in (operations.add_parser("admit"), operations.add_parser("observe")):
        operation.add_argument("--repository", required=True)
        operation.add_argument("--sha", required=True)
        operation.add_argument("--target-url", required=True)
    args = parser.parse_args(argv)
    github_output = _github_output_path()
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
    _github_output(result, path=github_output)
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
    controller_output = _github_output_path()
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
        result = {**pin, "output": str(args.output)}
        _github_output(result, path=controller_output)
        write_exclusive(
            args.output,
            {"schema_version": "1.0", "trusted_controller_artifact": pin},
        )
    else:
        confirmation = compile_self_controller_confirmation(
            api, repository=args.repository
        )
        result = {**confirmation, "output": str(args.output)}
        _github_output(result, path=controller_output)
        write_exclusive(
            args.output,
            {
                "schema_version": "1.0",
                "trusted_controller_installation": confirmation,
            },
        )
    if args.operation == "resolve":
        _github_output(result, path=controller_output)
    print(json.dumps(result, sort_keys=True))


def _release_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BCF authority-v1.1 release control.")
    operations = parser.add_subparsers(dest="operation", required=True)
    resolve = operations.add_parser("resolve")
    resolve.add_argument("--repository", required=True)
    resolve.add_argument("--output", type=Path, required=True)
    publication = operations.add_parser("resolve-publication")
    publication.add_argument("--repository", required=True)
    publication.add_argument("--output", type=Path, required=True)
    authorize = operations.add_parser("authorize")
    authorize.add_argument("--repository", required=True)
    authorize.add_argument("--bundle", type=Path, required=True)
    authorize.add_argument("--inputs", type=Path)
    authorize.add_argument("--controller-artifact-id")
    authorize.add_argument("--controller-artifact-name")
    authorize.add_argument("--controller-run-id")
    authorize.add_argument("--controller-run-attempt")
    authorize.add_argument("--controller-provider-digest")
    authorize.add_argument("--controller-wheel-sha256")
    controller_input = authorize.add_mutually_exclusive_group(required=True)
    controller_input.add_argument("--controller-wheel", type=Path)
    controller_input.add_argument("--controller-wheel-dir", type=Path)
    authorize.add_argument("--controller-commit")
    authorize.add_argument("--controller-tree")
    authorize.add_argument("--certification-artifact-id")
    authorize.add_argument("--certification-artifact-name")
    authorize.add_argument("--certification-run-id")
    authorize.add_argument("--certification-run-attempt")
    authorize.add_argument("--certification-provider-digest")
    authorize.add_argument("--output", type=Path, required=True)
    verify = operations.add_parser("verify")
    verify.add_argument("--repository", required=True)
    verify.add_argument("--authorization", type=Path, required=True)
    verify.add_argument("--build-manifest", type=Path, required=True)
    verify.add_argument("--wheelhouse-manifest", type=Path, required=True)
    verify.add_argument("--lock", type=Path, required=True)
    verify.add_argument("--wheelhouse", type=Path, required=True)
    _release_artifact_arguments(verify)
    verify.add_argument("--python", type=Path, required=True)
    verify.add_argument("--runtime-output", type=Path, required=True)
    verify.add_argument("--output", type=Path, required=True)
    runtime = operations.add_parser("runtime")
    runtime.add_argument("--wheelhouse-manifest", type=Path, required=True)
    runtime.add_argument("--lock", type=Path, required=True)
    runtime.add_argument("--wheelhouse", type=Path, required=True)
    _release_artifact_arguments(runtime)
    runtime.add_argument("--python", type=Path, required=True)
    runtime.add_argument("--output", type=Path, required=True)
    evidence = operations.add_parser("verify-evidence")
    evidence.add_argument("--repository", required=True)
    evidence.add_argument("--authorization", type=Path, required=True)
    evidence.add_argument("--build-manifest", type=Path, required=True)
    evidence.add_argument("--wheelhouse-manifest", type=Path, required=True)
    evidence.add_argument("--lock", type=Path, required=True)
    evidence.add_argument("--wheelhouse", type=Path, required=True)
    _release_artifact_arguments(evidence)
    evidence.add_argument("--runtime-report", type=Path, required=True)
    _runtime_evidence_arguments(evidence)
    evidence.add_argument("--output", type=Path, required=True)
    evidence.add_argument("--bundle-output", type=Path)
    build = operations.add_parser("build")
    build.add_argument("--authorization", type=Path, required=True)
    build.add_argument("--wheelhouse-manifest", type=Path, required=True)
    build.add_argument("--lock", type=Path, required=True)
    _release_artifact_arguments(build)
    build.add_argument("--artifact-name", required=True)
    build.add_argument("--output", type=Path, required=True)
    collect = operations.add_parser("collect")
    collect.add_argument("--repository", required=True)
    collect.add_argument("--bundle", type=Path, required=True)
    collect.add_argument("--authorization", type=Path, required=True)
    collect.add_argument("--build-manifest", type=Path, required=True)
    collect.add_argument("--verification", type=Path, required=True)
    collect.add_argument("--runtime-report", type=Path, required=True)
    _runtime_evidence_arguments(collect)
    _release_artifact_arguments(collect)
    collect.add_argument("--output", type=Path, required=True)
    collect.add_argument("--bundle-output", type=Path)
    collect.add_argument("--verification-artifact-name", required=True)
    for operation in (operations.add_parser("inspect"), operations.add_parser("publish")):
        operation.add_argument("--repository", required=True)
        operation.add_argument("--tag", required=True)
        operation.add_argument("--commit", required=True)
        _release_artifact_arguments(operation)
    publish = operations.choices["publish"]
    release_notes = publish.add_mutually_exclusive_group(required=True)
    release_notes.add_argument("--release-notes", type=Path)
    release_notes.add_argument("--release-notes-text")
    publish.add_argument("--receipt", type=Path, required=True)
    publish.add_argument("--receipt-artifact-id", required=True)
    publish.add_argument("--receipt-artifact-name", required=True)
    publish.add_argument("--receipt-provider-digest", required=True)
    return parser


def _release_artifact_arguments(parser: argparse.ArgumentParser) -> None:
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--release-artifact", type=Path, action="append")
    inputs.add_argument("--release-artifact-dir", type=Path)


def _runtime_evidence_arguments(parser: argparse.ArgumentParser) -> None:
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--runtime-evidence", type=Path, action="append")
    inputs.add_argument("--runtime-evidence-dir", type=Path)


def _release_artifacts(args: argparse.Namespace) -> tuple[Path, ...]:
    directory = getattr(args, "release_artifact_dir", None)
    return (
        release_asset_paths(directory)
        if directory is not None
        else tuple(args.release_artifact)
    )


def _runtime_evidence(args: argparse.Namespace) -> tuple[Path, ...]:
    directory = getattr(args, "runtime_evidence_dir", None)
    return (
        runtime_evidence_paths(args.runtime_report, directory)
        if directory is not None
        else tuple(args.runtime_evidence)
    )


def _authorization_inputs(args: argparse.Namespace) -> dict[str, Any]:
    legacy = {
        "controller": {
            "run_id": args.controller_run_id,
            "run_attempt": args.controller_run_attempt,
            "artifact_id": args.controller_artifact_id,
            "artifact_name": args.controller_artifact_name,
            "provider_digest": args.controller_provider_digest,
            "wheel_sha256": args.controller_wheel_sha256,
            "commit_sha": args.controller_commit,
            "tree_sha": args.controller_tree,
        },
        "certification_artifact": {
            "run_id": args.certification_run_id,
            "run_attempt": args.certification_run_attempt,
            "artifact_id": args.certification_artifact_id,
            "artifact_name": args.certification_artifact_name,
            "provider_digest": args.certification_provider_digest,
        },
    }
    supplied = [value for section in legacy.values() for value in section.values()]
    if args.inputs is not None:
        if any(value is not None for value in supplied):
            raise GitHubControllerError(
                "resolved release inputs cannot be combined with caller provider fields"
            )
        return load_release_authorization_inputs(args.inputs)
    if any(value is None for value in supplied):
        raise GitHubControllerError(
            "release authorization requires resolved inputs or the complete legacy fields"
        )
    return legacy


def _release(argv: list[str]) -> None:
    args = _release_parser().parse_args(argv)
    github_output = _github_output_path()
    if args.operation == "resolve":
        result = resolve_release_authorization_inputs(
            environment_api(), repository=args.repository, output_path=args.output
        )
        _github_output(release_input_outputs(result), path=github_output)
        print(json.dumps(result, sort_keys=True))
        return
    if args.operation == "resolve-publication":
        result = resolve_release_publication_inputs(
            environment_api(), repository=args.repository, output_path=args.output
        )
        _github_output(release_publication_outputs(result), path=github_output)
        print(json.dumps(result, sort_keys=True))
        return
    elif args.operation in {"verify", "runtime"}:
        release_artifacts = _release_artifacts(args)
        wheels = [path for path in release_artifacts if path.suffix == ".whl"]
        sdists = [
            path for path in release_artifacts if path.name.endswith(".tar.gz")
        ]
        if len(wheels) != 1 or len(sdists) != 1:
            raise GitHubControllerError("release verification requires one wheel and one sdist")
        runtime = run_release_runtime_verification(
            selected_python=args.python,
            manifest_path=args.wheelhouse_manifest,
            lock_path=args.lock,
            wheelhouse=args.wheelhouse,
            wheel=wheels[0],
            sdist=sdists[0],
            output_dir=(args.runtime_output if args.operation == "verify" else args.output),
        )
        if args.operation == "runtime":
            result = runtime
            _github_output(result, path=github_output)
            print(json.dumps(result, sort_keys=True))
            return
        result = verify_release_build_provider(
            environment_api(),
            repository=args.repository,
            authorization_path=args.authorization,
            build_manifest_path=args.build_manifest,
            manifest_path=args.wheelhouse_manifest,
            lock_path=args.lock,
            wheelhouse=args.wheelhouse,
            release_artifacts=release_artifacts,
            verifier_run_id=_required_environment("GITHUB_RUN_ID"),
            verifier_run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
            output_path=args.output,
            runtime_report_path=args.runtime_output / "runtime-verification.json",
            runtime_evidence=[
                args.runtime_output / name for name in runtime["evidence"]
            ],
        )
    elif args.operation == "verify-evidence":
        result = verify_release_build_provider(
            environment_api(),
            repository=args.repository,
            authorization_path=args.authorization,
            build_manifest_path=args.build_manifest,
            manifest_path=args.wheelhouse_manifest,
            lock_path=args.lock,
            wheelhouse=args.wheelhouse,
            release_artifacts=_release_artifacts(args),
            verifier_run_id=_required_environment("GITHUB_RUN_ID"),
            verifier_run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
            output_path=args.output,
            runtime_report_path=args.runtime_report,
            runtime_evidence=_runtime_evidence(args),
        )
        if args.bundle_output is not None:
            stage_verifier_bundle(
                args.bundle_output,
                build_manifest=args.build_manifest,
                runtime_report=args.runtime_report,
                verification=args.output,
            )
    elif args.operation == "build":
        result = record_release_build(
            authorization_path=args.authorization,
            manifest_path=args.wheelhouse_manifest,
            lock_path=args.lock,
            release_artifacts=_release_artifacts(args),
            run_id=_required_environment("GITHUB_RUN_ID"),
            run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
            artifact_name=args.artifact_name,
            output_path=args.output,
        )
    else:
        api = environment_api()
        if args.operation == "authorize":
            inputs = _authorization_inputs(args)
            controller_wheel = args.controller_wheel
            if args.controller_wheel_dir is not None:
                controller_wheel, _ = verify_controller_inventory(
                    args.controller_wheel_dir
                )
            if controller_wheel is None:
                raise GitHubControllerError("controller wheel input is absent")
            result = authorize_release(
                api,
                repository=args.repository,
                bundle_dir=args.bundle,
                run_id=_required_environment("GITHUB_RUN_ID"),
                run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
                controller=inputs["controller"],
                certification_artifact=inputs["certification_artifact"],
                controller_wheel_path=controller_wheel,
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
                release_artifacts=_release_artifacts(args),
                collector_run_id=_required_environment("GITHUB_RUN_ID"),
                collector_run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
                verification_artifact_name=args.verification_artifact_name,
                runtime_report_path=args.runtime_report,
                runtime_evidence=_runtime_evidence(args),
                output_path=args.output,
            )
            if args.bundle_output is not None:
                if args.release_artifact_dir is None:
                    raise GitHubControllerError(
                        "release receipt bundle requires --release-artifact-dir"
                    )
                stage_receipt_bundle(
                    args.bundle_output,
                    asset_root=args.release_artifact_dir,
                    build_manifest=args.build_manifest,
                    verification=args.verification,
                    receipt=args.output,
                )
        else:
            release_artifacts = _release_artifacts(args)
            assets = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in release_artifacts
            }
            if len(assets) != len(release_artifacts):
                raise GitHubControllerError("release asset inventory contains duplicates")
            if args.operation == "inspect":
                result = inspect_release(
                    api, repository=args.repository, tag=args.tag,
                    expected_commit=args.commit, expected_assets=assets,
                )
            else:
                release_body = (
                    args.release_notes_text
                    if args.release_notes_text is not None
                    else args.release_notes.read_text(encoding="utf-8")
                )
                result = publish_certified_release(
                    api, repository=args.repository, tag=args.tag,
                    expected_commit=args.commit,
                    release_artifacts=release_artifacts,
                    body=release_body,
                    receipt_path=args.receipt,
                    receipt_artifact_id=args.receipt_artifact_id,
                    receipt_artifact_name=args.receipt_artifact_name,
                    receipt_provider_digest=args.receipt_provider_digest,
                    publisher_run_id=_required_environment("GITHUB_RUN_ID"),
                    publisher_run_attempt=_required_environment("GITHUB_RUN_ATTEMPT"),
                )
    _github_output(result, path=github_output)
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

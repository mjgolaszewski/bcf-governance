"""Operator commands for content-addressed evidence-input storage."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tarfile
import zipfile

from .ci_github_api import GitHubAPIError
from .evidence_storage_contracts import (
    EvidenceStorageError,
    load_storage_contract,
    write_canonical_json,
)
from .evidence_storage_github import publish_action_handoff, resolve_input_reference
from .evidence_storage_github_api import GitHubEvidenceAPI
from .evidence_storage_graph import prepare_graph_artifact
from .evidence_storage_retention import apply_actions_retention, plan_retention


def _schemas(repo_root: Path | None = None) -> Path:
    if repo_root is not None and (repo_root / "schemas/evidence-storage.schema.json").is_file():
        return repo_root
    packaged = Path(__file__).resolve().parents[1] / "pack/template-repo"
    if not (packaged / "schemas/evidence-storage.schema.json").is_file():
        raise EvidenceStorageError("installed controller lacks evidence storage schemas")
    return packaged


def _api(token: str | None = None) -> GitHubEvidenceAPI:
    return GitHubEvidenceAPI(
        token=os.environ.get("GITHUB_TOKEN", "") if token is None else token,
        api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
    )


def _required_tokens(*names: str) -> dict[str, str]:
    values = {name: os.environ.get(name, "") for name in names}
    missing = sorted(name for name, value in values.items() if not value)
    if missing:
        raise EvidenceStorageError(
            "required provider credentials are missing: " + ", ".join(missing)
        )
    return values


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bcf evidence-store")
    operations = parser.add_subparsers(dest="operation", required=True)
    validate = operations.add_parser("validate")
    validate.add_argument("--repo-root", type=Path, default=Path("."))
    prepare = operations.add_parser("prepare")
    prepare.add_argument("--repo-root", type=Path, default=Path("."))
    prepare.add_argument("--artifact", required=True)
    prepare.add_argument("--output", type=Path, required=True)
    publish = operations.add_parser("publish-github")
    publish.add_argument("--repository", required=True)
    publish.add_argument("--run-id", required=True)
    publish.add_argument("--run-attempt", type=int, required=True)
    publish.add_argument("--artifact-name", required=True)
    publish.add_argument("--output", type=Path, required=True)
    resolve = operations.add_parser("resolve-github")
    resolve.add_argument("--repo-root", type=Path, default=Path("."))
    resolve.add_argument("--reference", type=Path, required=True)
    resolve.add_argument("--output", type=Path, required=True)
    retention = operations.add_parser("retention-plan")
    retention.add_argument("--repo-root", type=Path, default=Path("."))
    retention.add_argument("--snapshot", type=Path, required=True)
    retention.add_argument("--output", type=Path, required=True)
    apply_retention = operations.add_parser("retention-apply-actions")
    apply_retention.add_argument("--repo-root", type=Path, default=Path("."))
    apply_retention.add_argument("--snapshot", type=Path, required=True)
    apply_retention.add_argument("--output", type=Path, required=True)
    return parser


def run(args: argparse.Namespace) -> None:
    if args.operation == "validate":
        load_storage_contract(args.repo_root.resolve())
        print("status: valid")
    elif args.operation == "prepare":
        path = prepare_graph_artifact(
            args.repo_root, artifact_id=args.artifact, output_dir=args.output
        )
        print(path.resolve())
    elif args.operation == "publish-github":
        tokens = _required_tokens(
            "GITHUB_TOKEN",
            "BCF_EVIDENCE_WRITE_TOKEN",
            "BCF_EVIDENCE_SETTINGS_READ_TOKEN",
        )
        publish_action_handoff(
            _api(tokens["GITHUB_TOKEN"]),
            publication_api=_api(tokens["BCF_EVIDENCE_WRITE_TOKEN"]),
            configuration_api=_api(tokens["BCF_EVIDENCE_SETTINGS_READ_TOKEN"]),
            schema_root=_schemas(),
            repository=args.repository,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            artifact_name=args.artifact_name,
            output_path=args.output,
        )
        print(args.output.resolve())
    elif args.operation == "resolve-github":
        resolved = resolve_input_reference(
            _api(),
            repo_root=args.repo_root.resolve(),
            reference_path=args.reference,
            output_root=args.output,
        )
        for path in resolved:
            print(path.resolve())
    elif args.operation == "retention-plan":
        write_canonical_json(
            args.output,
            plan_retention(args.repo_root, args.snapshot, api=_api()),
        )
        print(args.output.resolve())
    elif args.operation == "retention-apply-actions":
        write_canonical_json(
            args.output,
            apply_actions_retention(args.repo_root, args.snapshot, api=_api()),
        )
        print(args.output.resolve())


def main(argv: list[str] | None = None) -> None:
    try:
        run(_parser().parse_args(argv))
    except (
        EvidenceStorageError,
        GitHubAPIError,
        OSError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as exc:
        print(f"evidence-store failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

"""Operator CLI for deterministic CI graph validation and generation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .ci_graph_contracts import validate_ci_graph
from .ci_graph_diagnostics import diagnose_ci_graph
from .ci_graph_import import check_workflow_inventory, write_workflow_inventory
from .ci_graph_locks import apply_ci_graph_locks, check_ci_graph_locks
from .ci_graph_render import apply_ci_graph, check_ci_graph, diff_ci_graph


def add_graph_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    graph = subparsers.add_parser("graph", help="Validate and render the governed CI graph.")
    operations = graph.add_subparsers(dest="graph_operation", required=True)
    for name in ("validate", "diagnose", "explain", "diff"):
        parser = operations.add_parser(name)
        parser.add_argument("--repo-root", type=Path, default=Path.cwd())
        parser.add_argument("--format", choices=("text", "json"), default="text")
    render = operations.add_parser("render")
    render.add_argument("--repo-root", type=Path, default=Path.cwd())
    mode = render.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    render.add_argument("--format", choices=("text", "json"), default="text")
    lock = operations.add_parser("lock")
    lock.add_argument("--repo-root", type=Path, default=Path.cwd())
    lock_mode = lock.add_mutually_exclusive_group(required=True)
    lock_mode.add_argument("--check", action="store_true")
    lock_mode.add_argument("--apply", action="store_true")
    lock.add_argument("--format", choices=("text", "json"), default="text")
    importer = operations.add_parser("import")
    providers = importer.add_subparsers(dest="graph_provider", required=True)
    github = providers.add_parser("github")
    github.add_argument("--repo-root", type=Path, default=Path.cwd())
    github.add_argument(
        "--output", type=Path, default=Path("governance/ci-workflow-inventory.yml")
    )
    import_mode = github.add_mutually_exclusive_group(required=True)
    import_mode.add_argument("--check", action="store_true")
    import_mode.add_argument("--write", action="store_true")
    github.add_argument("--format", choices=("text", "json"), default="text")


def _print(payload: dict[str, object], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True))
        return
    for key, value in payload.items():
        print(f"{key}: {value}")


def run_graph_command(args: argparse.Namespace) -> None:
    repo_root = args.repo_root.resolve()
    if args.graph_operation == "validate":
        compiled = validate_ci_graph(repo_root)
        _print(
            {
                "status": "valid",
                "graph_sha256": compiled.graph_sha256,
                "workflows": len(compiled.workflows),
                "jobs": sum(len(item["jobs"]) for item in compiled.workflows),
                "extensions": len(compiled.extension_sha256),
            },
            args.format,
        )
        return
    if args.graph_operation == "diagnose":
        report = diagnose_ci_graph(repo_root)
        _print(report, args.format)
        if report["status"] != "pass":
            raise SystemExit(1)
        return
    if args.graph_operation == "explain":
        compiled = validate_ci_graph(repo_root)
        _print(
            {
                "status": "valid",
                "graph_sha256": compiled.graph_sha256,
                "workflow_paths": [item["path"] for item in compiled.workflows],
                "semantic_roles": [
                    job["semantic_role"]
                    for workflow in compiled.workflows
                    for job in workflow["jobs"]
                ],
                "extension_digests": dict(compiled.extension_sha256),
            },
            args.format,
        )
        return
    if args.graph_operation == "diff":
        difference = diff_ci_graph(repo_root)
        if args.format == "json":
            _print({"status": "clean" if not difference else "drift", "diff": difference}, args.format)
        else:
            print(difference, end="")
        if difference:
            raise SystemExit(1)
        return
    if args.graph_operation == "render":
        result = apply_ci_graph(repo_root) if args.apply else check_ci_graph(repo_root)
        _print({"status": result.status, "changed_paths": list(result.changed_paths)}, args.format)
        if args.check and result.status != "clean":
            raise SystemExit(1)
        return
    if args.graph_operation == "lock":
        result = (
            apply_ci_graph_locks(repo_root)
            if args.apply
            else check_ci_graph_locks(repo_root)
        )
        _print(
            {"status": result.status, "changed_inputs": list(result.changed_inputs)},
            args.format,
        )
        if args.check and result.status != "clean":
            raise SystemExit(1)
        return
    result = (
        write_workflow_inventory(repo_root, args.output)
        if args.write
        else check_workflow_inventory(repo_root, args.output)
    )
    _print({"status": result.status, "path": result.path}, args.format)
    if args.check and result.status != "clean":
        raise SystemExit(1)

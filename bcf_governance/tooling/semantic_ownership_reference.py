"""Verify a consumer SOIP report with BCF's generalized source engines.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from .semantic_ownership_cross_language import build_endpoint_traces
from .semantic_ownership_inventory import discover_python_source
from .semantic_ownership_typescript import (
    TypeScriptDiscoveryError,
    contract_from_mapping,
    discover_typescript_source,
    tracked_typescript_files,
)


class ReferenceProofError(RuntimeError):
    """Raised when the exact consumer proof cannot be reconstructed."""


def _git(repo_root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ReferenceProofError(f"git {' '.join(arguments)} failed")
    return result.stdout.strip()


def _object(path: Path, *, yaml_document: bool = False) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
        value = yaml.safe_load(text) if yaml_document else json.loads(text)
    except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ReferenceProofError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReferenceProofError(f"{path} must contain an object")
    return value


def _rows(payload: object, *, label: str) -> list[dict[str, str]]:
    if not isinstance(payload, list):
        raise ReferenceProofError(f"{label} must be a list")
    rows: list[dict[str, str]] = []
    for value in payload:
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("path"), str)
            or not isinstance(value.get("sha256"), str)
        ):
            raise ReferenceProofError(f"{label} contains an invalid source row")
        rows.append({"path": value["path"], "sha256": value["sha256"]})
    return sorted(rows, key=lambda value: value["path"])


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def prove_reference(
    consumer_root: Path,
    *,
    expected_commit: str,
    expected_tree: str,
    expected_representations: int,
    consumer_report_path: Path,
    contract_path: Path,
) -> dict[str, Any]:
    """Reconstruct exact source, compiler, trace, and report claims."""
    started = time.monotonic()
    consumer_root = consumer_root.resolve()
    commit = _git(consumer_root, "rev-parse", "HEAD")
    tree = _git(consumer_root, "rev-parse", "HEAD^{tree}")
    status = _git(consumer_root, "status", "--porcelain=v1", "--untracked-files=all")
    if commit != expected_commit or tree != expected_tree or status:
        raise ReferenceProofError("consumer worktree is not the exact clean expected subject")
    report = _object(consumer_report_path)
    subject = report.get("subject")
    if not isinstance(subject, dict):
        raise ReferenceProofError("consumer report has no subject")
    if subject.get("commit_sha") != commit or subject.get("tree_sha") != tree:
        raise ReferenceProofError("consumer report is not bound to the expected subject")
    coverage = report.get("registry_coverage")
    if not isinstance(coverage, list) or len(coverage) != expected_representations:
        raise ReferenceProofError("consumer report has the wrong representation population")
    semantic_ids = [value.get("semantic_id") for value in coverage if isinstance(value, dict)]
    if len(semantic_ids) != len(set(semantic_ids)):
        raise ReferenceProofError("consumer report duplicates a semantic identity")
    if (
        report.get("verdict") != "conformant"
        or report.get("blocking_violation_count") != 0
        or report.get("unresolved_escapes") != []
    ):
        raise ReferenceProofError("consumer report is not conformant and fully resolved")
    source = report.get("source_inventory")
    if not isinstance(source, dict):
        raise ReferenceProofError("consumer report has no source inventory")
    python_report = source.get("python")
    typescript_report = source.get("typescript")
    if not isinstance(python_report, dict) or not isinstance(typescript_report, dict):
        raise ReferenceProofError("consumer report lacks language inventories")
    expected_python = _rows(python_report.get("files"), label="consumer Python files")
    python_paths = [consumer_root / value["path"] for value in expected_python]
    generalized_python = discover_python_source(consumer_root, python_paths)
    if generalized_python["files"] != expected_python:
        raise ReferenceProofError("generalized Python source inventory differs from consumer")
    discovered_typescript = tracked_typescript_files(consumer_root)
    contract_document = _object(contract_path, yaml_document=True)
    contract = contract_from_mapping(contract_document.get("typescript_engine"))
    generalized_typescript = discover_typescript_source(
        consumer_root, contract, discovered_typescript
    )
    expected_typescript = _rows(
        typescript_report.get("files"), label="consumer TypeScript files"
    )
    if generalized_typescript["files"] != expected_typescript:
        raise ReferenceProofError("generalized TypeScript inventory differs from consumer")
    if generalized_typescript.get("compiler_version") != typescript_report.get(
        "compiler_version"
    ):
        raise ReferenceProofError("generalized and consumer compiler versions differ")
    traces = build_endpoint_traces(
        python_report,
        generalized_typescript,
        browser_contract_roots=contract.browser_contract_roots,
    )
    expected_traces = source.get("cross_language_endpoint_traces")
    if traces != expected_traces:
        raise ReferenceProofError("generalized cross-language traces differ from consumer")
    required = [value for value in traces if value.get("browser_contract_required") is True]
    if not required or any(value.get("decoder_coverage") is not True for value in required):
        raise ReferenceProofError("a required browser endpoint lacks decoder coverage")
    return {
        "document": {"kind": "bcf_semantic_reference_proof", "version": "1.0.0"},
        "subject": {"commit_sha": commit, "tree_sha": tree, "clean": True},
        "consumer_report": {
            "sha256": hashlib.sha256(consumer_report_path.read_bytes()).hexdigest(),
            "verdict": "conformant",
            "representation_count": len(coverage),
            "unresolved_escape_count": 0,
        },
        "generalized_inventory": {
            "python_file_count": len(expected_python),
            "typescript_file_count": len(expected_typescript),
            "typescript_version": generalized_typescript["compiler_version"],
            "source_digest": _digest([*expected_python, *expected_typescript]),
            "cross_language_trace_count": len(traces),
            "required_browser_trace_count": len(required),
            "uncovered_required_trace_count": 0,
        },
        "environment": generalized_typescript["toolchain"],
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "verdict": "conformant",
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Prove an exact consumer SOIP report.")
    parser.add_argument("--consumer-root", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-representations", type=int, required=True)
    parser.add_argument("--consumer-report", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        proof = prove_reference(
            args.consumer_root,
            expected_commit=args.expected_commit,
            expected_tree=args.expected_tree,
            expected_representations=args.expected_representations,
            consumer_report_path=args.consumer_report,
            contract_path=args.contract,
        )
    except (ReferenceProofError, TypeScriptDiscoveryError) as exc:
        raise SystemExit(f"semantic reference proof failed: {exc}") from exc
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("semantic-reference-conformant")


if __name__ == "__main__":
    main()

"""Compile an authenticated Identity reference audit from provider and proof inputs."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import stat
import zipfile
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

import yaml


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_PROOF_ARCHIVE_BYTES = 64 * 1024 * 1024


def _object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def load_proof_archive(
    payload: bytes, artifact: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, str]]:
    """Authenticate and decode one provider artifact without trusting extraction."""

    provider_digest = str(artifact.get("digest"))
    actual_digest = _sha256(payload)
    if provider_digest != f"sha256:{actual_digest}":
        raise ValueError("proof archive bytes differ from the provider digest")
    validations: list[dict[str, Any]] = []
    member_hashes: dict[str, str] = {}
    total_size = 0
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for info in archive.infolist():
            path = PurePosixPath(info.filename)
            mode = info.external_attr >> 16
            if (
                info.is_dir()
                or path.is_absolute()
                or ".." in path.parts
                or len(path.parts) != 1
                or path.suffix != ".json"
                or stat.S_ISLNK(mode)
                or info.filename in member_hashes
            ):
                raise ValueError("proof archive contains an unsafe or duplicate member")
            total_size += info.file_size
            if total_size > MAX_PROOF_ARCHIVE_BYTES:
                raise ValueError("proof archive exceeds its extraction budget")
            member = archive.read(info)
            member_hashes[info.filename] = _sha256(member)
            value = json.loads(member)
            if not isinstance(value, dict):
                raise ValueError("proof archive JSON members must contain objects")
            document = value.get("document")
            if isinstance(document, dict) and (
                document.get("kind") == "bcf_hosted_identity_reference_validation"
            ):
                validations.append(value)
    if len(validations) != 1:
        raise ValueError("proof archive must contain one hosted validation document")
    validation = validations[0]
    referenced_hashes = {
        validation.get("benchmark", {}).get("artifact_sha256"),
        validation.get("reference", {}).get("artifact_sha256"),
        validation.get("reference", {}).get("consumer_report", {}).get("sha256"),
    }
    if None in referenced_hashes or not referenced_hashes.issubset(set(member_hashes.values())):
        raise ValueError("proof archive does not contain every digest-linked result")
    return validation, dict(sorted(member_hashes.items()))


def compile_audit(
    contract: dict[str, Any],
    validation: dict[str, Any],
    run: dict[str, Any],
    artifact: dict[str, Any],
    archive_members: dict[str, str],
) -> dict[str, Any]:
    subject = contract.get("subject")
    provider = validation.get("provider")
    proof_subject = validation.get("subject")
    reference = validation.get("reference")
    benchmark = validation.get("benchmark")
    if not all(isinstance(value, dict) for value in (
        subject, provider, proof_subject, reference, benchmark
    )):
        raise ValueError("Identity reference proof shape is incomplete")
    if validation.get("status") != "hosted_pass":
        raise ValueError("Identity reference proof did not pass on the hosted substrate")
    if proof_subject != {
        "repository": subject.get("repository"),
        "commit_sha": subject.get("commit_sha"),
        "tree_sha": subject.get("tree_sha"),
        "clean": True,
    }:
        raise ValueError("Identity reference proof subject differs from its contract")
    report = reference.get("consumer_report")
    inventory = reference.get("generalized_inventory")
    if (
        reference.get("verdict") != "conformant"
        or not isinstance(report, dict)
        or report.get("representation_count") != subject.get("expected_representations")
        or report.get("unresolved_escape_count") != 0
        or not isinstance(inventory, dict)
        or inventory.get("uncovered_required_trace_count") != 0
    ):
        raise ValueError("Identity semantic reference is not conformant")
    expected_benchmark = contract.get("benchmark", {})
    if (
        benchmark.get("verdict") != "pass"
        or benchmark.get("measured_run_count") != expected_benchmark.get("measured_runs")
        or benchmark.get("median_seconds", float("inf"))
        > expected_benchmark.get("median_ceiling_seconds", 0)
        or benchmark.get("p95_seconds", float("inf"))
        > expected_benchmark.get("p95_ceiling_seconds", 0)
        or benchmark.get("compact_proof_bytes", float("inf"))
        > expected_benchmark.get("compact_report_ceiling_bytes", 0)
    ):
        raise ValueError("Identity hosted benchmark differs from its contract")

    run_id = str(run.get("id"))
    attempt = str(run.get("run_attempt"))
    repository = run.get("repository")
    if (
        run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("event") != "workflow_dispatch"
        or run.get("path") != ".github/workflows/governance.yml"
        or not isinstance(repository, dict)
        or repository.get("full_name") != subject.get("repository")
        or str(repository.get("id")) != str(provider.get("repository_id"))
        or run_id != str(provider.get("run_id"))
        or attempt != str(provider.get("run_attempt"))
        or run.get("head_sha") != provider.get("workflow_definition_commit")
    ):
        raise ValueError("provider run does not authenticate the hosted proof")

    artifact_run = artifact.get("workflow_run")
    expected_name = f"bcf-p13-identity-reference-{run_id}-{attempt}"
    if not isinstance(artifact_run, dict):
        raise ValueError("provider artifact has no workflow-run identity")
    if str(artifact_run.get("id")) != run_id:
        raise ValueError("provider artifact belongs to a different run")
    if (
        artifact_run.get("head_sha") != run.get("head_sha")
        or str(artifact_run.get("repository_id")) != str(repository.get("id"))
        or artifact.get("name") != expected_name
        or artifact.get("expired") is not False
        or not DIGEST_RE.fullmatch(str(artifact.get("digest")))
    ):
        raise ValueError("provider artifact custody differs from the hosted proof")

    return {
        "document": {
            "kind": "bcf_hosted_identity_reference_audit",
            "version": "1.0.0",
            "status": "hosted_pass",
        },
        "provider_custody": {
            "repository": repository.get("full_name"),
            "repository_id": str(repository.get("id")),
            "workflow_id": str(run.get("workflow_id")),
            "workflow_path": run.get("path"),
            "run_id": run_id,
            "run_attempt": attempt,
            "event": run.get("event"),
            "head_branch": run.get("head_branch"),
            "head_sha": run.get("head_sha"),
            "artifact_id": str(artifact.get("id")),
            "artifact_name": artifact.get("name"),
            "artifact_provider_digest": artifact.get("digest"),
            "artifact_size_bytes": artifact.get("size_in_bytes"),
            "artifact_members": archive_members,
        },
        "validation": validation,
    }


def promote_legacy_validation(
    legacy: dict[str, Any], audit: dict[str, Any]
) -> dict[str, Any]:
    """Replace the provisional benchmark only from an authenticated hosted audit."""

    validation = audit["validation"]
    if audit["document"]["status"] != "hosted_pass" or (
        legacy.get("subject") != validation.get("subject")
    ):
        raise ValueError("legacy validation subject differs from the hosted audit")
    reference = validation["reference"]
    inventory = reference["generalized_inventory"]
    report = reference["consumer_report"]
    benchmark = validation["benchmark"]
    environment = benchmark["environment"]
    legacy["document"]["status"] = "hosted_pass"
    legacy["results"] = {
        "representations": report["representation_count"],
        "blocking_violations": 0,
        "unresolved_escapes": report["unresolved_escape_count"],
        "python_files": inventory["python_file_count"],
        "typescript_files": inventory["typescript_file_count"],
        "cross_language_traces": inventory["cross_language_trace_count"],
        "required_browser_traces": inventory["required_browser_trace_count"],
        "uncovered_required_browser_traces": inventory["uncovered_required_trace_count"],
        "compact_generalized_proof_bytes": benchmark["compact_proof_bytes"],
        "consumer_report_sha256": report["sha256"],
        "generalized_proof_sha256": reference["artifact_sha256"],
    }
    legacy["benchmark"] = {
        "substrate": "github_hosted_ubuntu_24_04",
        "architecture": environment["architecture"],
        "vcpus": environment["vcpus"],
        "python": environment["python_version"],
        "node": environment["node_version"],
        "typescript": environment["typescript_version"],
        "warmups": benchmark["warmup_count"],
        "measured_runs": benchmark["measured_run_count"],
        "median_seconds": benchmark["median_seconds"],
        "p95_seconds": benchmark["p95_seconds"],
        "median_ceiling_seconds": benchmark["median_ceiling_seconds"],
        "p95_ceiling_seconds": benchmark["p95_ceiling_seconds"],
        "benchmark_sha256": benchmark["artifact_sha256"],
    }
    legacy["hosted_audit"] = "audits/p13-identity-hosted-validation.json"
    legacy["limitations"] = [
        value for value in legacy.get("limitations", [])
        if "disposable candidate VM image proof" not in str(value)
    ]
    return legacy


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--legacy-validation", type=Path)
    args = parser.parse_args()
    contract = yaml.safe_load(args.contract.read_text(encoding="utf-8"))
    if not isinstance(contract, dict):
        raise ValueError("Identity reference contract must contain an object")
    artifact = _object(args.artifact)
    validation, archive_members = load_proof_archive(args.archive.read_bytes(), artifact)
    audit = compile_audit(contract, validation, _object(args.run), artifact, archive_members)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.legacy_validation is not None:
        legacy = yaml.safe_load(args.legacy_validation.read_text(encoding="utf-8"))
        if not isinstance(legacy, dict):
            raise ValueError("legacy validation must contain an object")
        promoted = promote_legacy_validation(legacy, audit)
        args.legacy_validation.write_text(
            yaml.safe_dump(promoted, sort_keys=False), encoding="utf-8"
        )
    print("identity-reference-audit-compiled")


if __name__ == "__main__":
    main()

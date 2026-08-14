"""Validation and loading for evidence-backed phase truth reports."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_truth_reports(
    repo_root: Path, paths: list[Path] | None
) -> dict[str, dict[str, Any]]:
    reports: dict[str, dict[str, Any]] = {}
    for supplied_path in paths or []:
        path = supplied_path if supplied_path.is_absolute() else repo_root / supplied_path
        if not path.is_file():
            raise FileNotFoundError(f"truth report does not exist: {supplied_path}")
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"truth report is not valid JSON: {supplied_path}: {exc}") from exc
        if not isinstance(report, dict):
            raise ValueError(f"truth report must be an object: {supplied_path}")
        phase_id = report.get("phase_id")
        subject = report.get("subject")
        verifier = report.get("verifier")
        release = report.get("release_readiness")
        checks = report.get("checks")
        claims = report.get("claims")
        reconciliation = report.get("reconciliation")
        findings = report.get("findings")
        durable_ref = report.get("durable_ref")
        valid = (
            isinstance(phase_id, str)
            and report.get("schema_version") == "2.0"
            and report.get("engine") == "evidence_truthfulness"
            and report.get("status") == "pass"
            and report.get("effective_state") == "closed"
            and report.get("issues") == []
            and isinstance(checks, dict)
            and bool(checks)
            and all(value == "pass" for value in checks.values())
            and isinstance(claims, dict)
            and bool(claims)
            and all(
                isinstance(claim, dict)
                and claim.get("effective_state") in {"verified", "not_applicable"}
                for claim in claims.values()
            )
            and isinstance(reconciliation, dict)
            and reconciliation.get("effective_state") == "verified"
            and isinstance(findings, dict)
            and findings.get("open_count") == 0
            and findings.get("issues") == []
            and isinstance(release, dict)
            and release.get("effective_state") == "closed"
            and isinstance(subject, dict)
            and subject.get("tracked_clean") is True
            and subject.get("untracked_clean") is True
            and re.fullmatch(r"[a-f0-9]{40,64}", str(subject.get("commit_sha", "")))
            and re.fullmatch(r"[a-f0-9]{40,64}", str(subject.get("tree_sha", "")))
            and re.fullmatch(r"[a-f0-9]{64}", str(report.get("bundle_sha256", "")))
            and isinstance(verifier, dict)
            and isinstance(verifier.get("kind"), str)
            and bool(verifier.get("kind"))
            and isinstance(verifier.get("id"), str)
            and bool(verifier.get("id"))
            and isinstance(durable_ref, str)
            and bool(durable_ref)
        )
        if not valid:
            raise ValueError(
                "truth report must be a passing internally consistent closed computation with "
                f"subject, bundle, release, and verifier provenance: {supplied_path}"
            )
        commit_check = subprocess.run(
            ["git", "-C", str(repo_root), "cat-file", "-e", f"{subject['commit_sha']}^{{commit}}"],
            capture_output=True,
            check=False,
        )
        tree_check = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", f"{subject['commit_sha']}^{{tree}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if commit_check.returncode != 0 or tree_check.returncode != 0:
            raise ValueError(
                f"truth report subject is not present in repository git history: {supplied_path}"
            )
        if tree_check.stdout.strip() != subject["tree_sha"]:
            raise ValueError(f"truth report tree does not match its commit: {supplied_path}")
        if phase_id in reports:
            raise ValueError(f"duplicate truth report for phase {phase_id}")
        reports[phase_id] = {
            "report": report,
            "verification_snapshot": {
                "commit_sha": subject["commit_sha"],
                "tree_sha": subject["tree_sha"],
                "truth_report_sha256": _file_sha256(path),
                "evidence_bundle_sha256": report["bundle_sha256"],
                "durable_ref": durable_ref,
                "verifier": {"kind": verifier["kind"], "id": verifier["id"]},
            },
        }
    return reports

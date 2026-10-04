"""Canonical post-install governance validation adapter."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys


def run_validation(
    target_root: Path,
    *,
    allow_placeholders: bool,
    allow_release_gate_placeholders: bool,
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(target_root / "scripts" / "validate_governance_yaml.py"),
        "--repo-root",
        str(target_root),
        "--format",
        "json",
        "--compact",
    ]
    if allow_placeholders:
        command.append("--allow-placeholders")
    if allow_release_gate_placeholders:
        command.append("--allow-release-gate-placeholders")
    return subprocess.run(command, capture_output=True, text=True)

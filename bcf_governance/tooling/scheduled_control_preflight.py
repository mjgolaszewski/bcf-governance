"""Provider-bound preflight owner for non-certifying scheduled controls."""

from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Any

from .ci_github_api import GitHubAPI
from .preflight import run_preflight
from .governance_validation.preflight_diagnostics import write_preflight_diagnostic
from .routine_controller_provider import resolve_effective_controller


class ScheduledControlPreflightError(ValueError):
    """Scheduled control state cannot reach mutation execution."""


def run_scheduled_control_preflight(
    api: GitHubAPI,
    *,
    repository: str,
    repo_root: Path,
    python_executable: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Resolve provider controller custody and run one exact scheduled preflight."""

    try:
        effective = resolve_effective_controller(api, repository=repository)
        pin = effective["pin"]
        authority = {
            "controller_commit_sha": pin["BCF_BOOTSTRAP_COMMIT_SHA"],
            "controller_bundle_sha256": pin["BCF_BOOTSTRAP_WHEEL_SHA256"],
        }
        report = run_preflight(
            repo_root,
            mode="release",
            python_executable=python_executable,
            evaluation_mode="pr",
            transported_authority=authority,
        )
        if report["subject"] != effective["subject"]:
            raise ScheduledControlPreflightError(
                "scheduled checkout differs from provider-effective main subject"
            )
    except (KeyError, OSError, subprocess.SubprocessError, ValueError) as exc:
        write_preflight_diagnostic(
            output_path,
            mode="release",
            evaluation_mode="pr",
            error=str(exc),
        )
        if isinstance(exc, ScheduledControlPreflightError):
            raise
        raise ScheduledControlPreflightError(str(exc)) from exc
    write_preflight_diagnostic(
        output_path,
        mode="release",
        evaluation_mode="pr",
        report=report,
    )
    return {
        "status": "success",
        "subject": report["subject"],
        "controller": authority,
        "release_authority": False,
        "output": str(output_path),
    }

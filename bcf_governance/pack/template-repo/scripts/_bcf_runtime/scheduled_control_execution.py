"""One deterministic execution owner for each complete scheduled control profile."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Callable, Mapping, Sequence


class ScheduledControlExecutionError(ValueError):
    """A scheduled profile was incomplete or did not satisfy its controls."""


PROFILE_SETS: dict[str, tuple[tuple[str, str], ...]] = {
    "nightly": (
        ("high-value", "nightly-validator.json"),
        ("semantic-high-value", "nightly-semantic.json"),
    ),
    "weekly": (
        ("full", "weekly-validator.json"),
        ("semantic-full", "weekly-semantic.json"),
    ),
}


Runner = Callable[..., subprocess.CompletedProcess[str]]


def _write(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)


def _load_result(path: Path, *, profile: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ScheduledControlExecutionError(
            f"scheduled profile {profile} emitted no readable result"
        ) from exc
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != "1.0"
        or value.get("kind") != "scheduled_mutant_result"
        or value.get("profile") != profile
        or value.get("result") not in {"passed", "failed", "infrastructure_failure"}
        or not isinstance(value.get("subject"), dict)
    ):
        raise ScheduledControlExecutionError(
            f"scheduled profile {profile} result contract is invalid"
        )
    return value


def run_scheduled_control_profiles(
    *,
    repo_root: Path,
    python_executable: Path,
    schedule: str,
    output_dir: Path,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Execute every declared profile and emit one aggregate terminal result."""

    profiles = PROFILE_SETS.get(schedule)
    if profiles is None:
        raise ScheduledControlExecutionError("scheduled control profile set is unknown")
    root = repo_root.resolve()
    harness = root / ".github/scripts/run_validator_mutants.py"
    observations: list[dict[str, Any]] = []
    subjects: list[Mapping[str, Any]] = []
    for profile, filename in profiles:
        output = output_dir / filename
        result = runner(
            [
                str(python_executable),
                str(harness),
                "--profile",
                profile,
                "--output",
                str(output),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        try:
            payload = _load_result(output, profile=profile)
            subject = payload["subject"]
            subjects.append(subject)
            payload_result = str(payload["result"])
            contract_error = None
            expected_exit = {"passed": 0, "failed": 1, "infrastructure_failure": 2}[
                payload_result
            ]
            if result.returncode != expected_exit:
                contract_error = "profile exit status contradicts its typed result"
        except ScheduledControlExecutionError as exc:
            payload_result = "infrastructure_failure"
            contract_error = str(exc)
        observations.append(
            {
                "profile": profile,
                "result": payload_result,
                "exit_code": result.returncode,
                "output": filename,
                "output_sha256": (
                    hashlib.sha256(output.read_bytes()).hexdigest()
                    if output.is_file()
                    else None
                ),
                "contract_error": contract_error,
                "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-4000:],
            }
        )
    subject = dict(subjects[0]) if subjects else None
    if any(value != subject for value in subjects):
        observations.append(
            {
                "profile": "aggregate",
                "result": "infrastructure_failure",
                "exit_code": 2,
                "output": None,
                "output_sha256": None,
                "contract_error": "scheduled profiles disagree on exact subject",
                "stdout": "",
                "stderr": "",
            }
        )
    passed = (
        len(observations) == len(profiles)
        and subject is not None
        and all(
            value["result"] == "passed" and value["contract_error"] is None
            for value in observations
        )
    )
    report = {
        "schema_version": "1.0",
        "kind": "scheduled_control_profile_set",
        "schedule": schedule,
        "subject": subject,
        "profiles": observations,
        "result": "passed" if passed else "failed",
        "release_authority": False,
    }
    _write(output_dir / f"{schedule}-result.json", report)
    if not passed:
        failures = ", ".join(
            str(value["profile"])
            for value in observations
            if value["result"] != "passed" or value["contract_error"] is not None
        )
        raise ScheduledControlExecutionError(
            f"scheduled control profiles failed: {failures}"
        )
    return report

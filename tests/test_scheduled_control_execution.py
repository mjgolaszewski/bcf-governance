from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from bcf_governance.tooling.scheduled_control_execution import (
    ScheduledControlExecutionError,
    run_scheduled_control_profiles,
)


SUBJECT = {
    "commit_sha": "a" * 40,
    "tree_sha": "b" * 40,
    "status_porcelain": "",
}


def _runner(results: dict[str, tuple[str, int]], calls: list[str]):
    def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        profile = command[command.index("--profile") + 1]
        output = Path(command[command.index("--output") + 1])
        calls.append(profile)
        result, exit_code = results[profile]
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "kind": "scheduled_mutant_result",
                    "profile": profile,
                    "subject": SUBJECT,
                    "result": result,
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, exit_code, profile, "")

    return run


def test_scheduled_control_executes_complete_profile_set(tmp_path: Path) -> None:
    calls: list[str] = []
    report = run_scheduled_control_profiles(
        repo_root=tmp_path,
        python_executable=Path("python"),
        schedule="nightly",
        output_dir=tmp_path / "results",
        runner=_runner(
            {"high-value": ("passed", 0), "semantic-high-value": ("passed", 0)},
            calls,
        ),
    )
    assert calls == ["high-value", "semantic-high-value"]
    assert report["result"] == "passed"
    assert report["subject"] == SUBJECT
    assert report["release_authority"] is False


def test_first_profile_failure_cannot_erase_second_diagnostic(tmp_path: Path) -> None:
    calls: list[str] = []
    with pytest.raises(ScheduledControlExecutionError, match="high-value"):
        run_scheduled_control_profiles(
            repo_root=tmp_path,
            python_executable=Path("python"),
            schedule="nightly",
            output_dir=tmp_path / "results",
            runner=_runner(
                {"high-value": ("failed", 1), "semantic-high-value": ("passed", 0)},
                calls,
            ),
        )
    assert calls == ["high-value", "semantic-high-value"]
    report = json.loads(
        (tmp_path / "results/nightly-result.json").read_text(encoding="utf-8")
    )
    assert [value["profile"] for value in report["profiles"]] == [
        "high-value",
        "semantic-high-value",
    ]
    assert report["result"] == "failed"


def test_profile_exit_must_match_typed_result(tmp_path: Path) -> None:
    with pytest.raises(ScheduledControlExecutionError, match="semantic-full"):
        run_scheduled_control_profiles(
            repo_root=tmp_path,
            python_executable=Path("python"),
            schedule="weekly",
            output_dir=tmp_path / "results",
            runner=_runner(
                {"full": ("passed", 0), "semantic-full": ("passed", 2)}, []
            ),
        )

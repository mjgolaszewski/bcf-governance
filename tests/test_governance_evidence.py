from __future__ import annotations

import json
import subprocess
from pathlib import Path

import yaml

from scripts.governance_evidence import capture_gate


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


def test_evidence_run_captures_process_artifacts_test_counts_and_negative_control(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "governance").mkdir()
    (repo / "gate.py").write_text(
        "import sys\nPASS = True\nprint('collected 1 item')\nprint('1 passed')\nsys.exit(0 if PASS else 1)\n",
        encoding="utf-8",
    )
    (repo / "Makefile").write_text("test:\n\tpython gate.py\n", encoding="utf-8")
    (repo / "governance-profile.yml").write_text(
        yaml.safe_dump(
            {
                "release_gate_profile": {
                    "gates": {
                        "test": {
                            "target": "test",
                            "status": "required",
                            "command_policy": "automated_tests",
                        }
                    }
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (repo / "governance/evidence-policy.yml").write_text(
        yaml.safe_dump(
            {
                "gate_overrides": {
                    "test": {
                        "evidence_kind": "test_suite",
                        "test_contract": {
                            "min_collected": 1,
                            "min_executed": 1,
                            "max_skipped": 0,
                        },
                        "negative_controls": [
                            {
                                "id": "break-test",
                                "mutation": {
                                    "path": "gate.py",
                                    "search": "PASS = True",
                                    "replace": "PASS = False",
                                },
                            }
                        ],
                    }
                }
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    _git(repo, "init")
    _git(repo, "config", "user.email", "evidence@example.test")
    _git(repo, "config", "user.name", "Evidence Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "gate")

    receipt_path = capture_gate(repo, "test", tmp_path / "evidence")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

    assert receipt["subject"]["binding"] == "exact_tree"
    assert receipt["subject"]["tracked_clean"] is True
    assert receipt["observations"]["exit_code"] == 0
    assert receipt["observations"]["test_counts"]["executed"] == 1
    assert receipt["observations"]["test_counts"]["skipped"] == 0
    assert receipt["behavioral_probes"][0]["mutation_applied"] is True
    assert receipt["behavioral_probes"][0]["observed_exit_code"] != 0
    assert all(len(artifact["sha256"]) == 64 for artifact in receipt["artifacts"])

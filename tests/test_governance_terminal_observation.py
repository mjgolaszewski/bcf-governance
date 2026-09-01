from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / ".github/scripts/governance_terminal_observation.py"
)


def _module():
    spec = importlib.util.spec_from_file_location("governance_terminal_observation", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_failed_preflight_emits_exact_causal_terminal_observation(
    tmp_path: Path,
) -> None:
    module = _module()
    output = tmp_path / ".artifacts/bcf/truth-report.json"

    assert module.ensure_terminal_observation(
        tmp_path,
        output,
        preflight_result="failure",
        evidence_result="skipped",
        repository="owner/repository",
        commit_sha="a" * 40,
        run_id="101",
        run_attempt="2",
    ) is False

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["computed_state"] == "failed"
    assert report["reasons"] == ["preflight:failure", "evidence:skipped"]
    assert report["subject"] == {
        "commit_sha": "a" * 40,
        "repository": "owner/repository",
        "run_attempt": "2",
        "run_id": "101",
    }


def test_existing_truth_report_is_never_rewritten(tmp_path: Path) -> None:
    module = _module()
    output = tmp_path / "truth-report.json"
    output.write_text('{"computed_state":"closed"}\n', encoding="utf-8")

    assert module.ensure_terminal_observation(
        tmp_path,
        output,
        preflight_result="success",
        evidence_result="success",
        repository="owner/repository",
        commit_sha="b" * 40,
        run_id="102",
        run_attempt="1",
    ) is True
    assert output.read_text(encoding="utf-8") == '{"computed_state":"closed"}\n'


def test_terminal_observation_rejects_unknown_conclusion_and_escape(
    tmp_path: Path,
) -> None:
    module = _module()
    arguments = {
        "preflight_result": "success",
        "evidence_result": "unknown",
        "repository": "owner/repository",
        "commit_sha": "c" * 40,
        "run_id": "103",
        "run_attempt": "1",
    }
    with pytest.raises(ValueError, match="unsafe"):
        module.ensure_terminal_observation(tmp_path, Path("../truth.json"), **arguments)
    with pytest.raises(ValueError, match="conclusion is invalid"):
        module.ensure_terminal_observation(tmp_path, Path("truth.json"), **arguments)

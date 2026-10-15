from __future__ import annotations

import json
from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source, SemanticInventoryError,
)


def _discover(root: Path, source: str):
    path = root / "model.py"
    path.write_text(source)
    return discover_python_source(root, files=[path], call_contracts_version="1.0")


def _calls(inventory):
    return [call for function in inventory["functions"] for call in function["calls"]]


def test_call_contracts_cover_all_calls_and_retain_unknowns(tmp_path):
    inventory = _discover(tmp_path, "def work(fn):\n    fn(1)\n    __import__('unknown')\n")
    assert inventory["call_contracts_version"] == "1.0"
    assert inventory["authority"] is False
    assert len(_calls(inventory)) == 2
    assert all(call["call_contract"]["authority"] is False for call in _calls(inventory))
    assert inventory["unresolved"]


def test_call_contracts_retain_slots_without_plaintext_literals(tmp_path):
    inventory = _discover(tmp_path, "def work(fn, args, options):\n    fn('secret-token-123', *args, timeout=3, **options)\n")
    fact = _calls(inventory)[0]["call_contract"]
    assert [(row["kind"], row["slot"]) for row in fact["arguments"]] == [
        ("positional", 0), ("starred", 1), ("keyword", "timeout"), ("double_starred", 1)
    ]
    assert "secret-token-123" not in json.dumps(fact)
    assert all(len(row["expression_sha256"]) == 64 for row in fact["arguments"])


def test_call_contracts_are_stable_under_line_movement_and_observe_mutation(tmp_path):
    source = "def work(fn):\n    fn('first')\n"
    first = _calls(_discover(tmp_path, source))[0]["call_contract"]
    assert _calls(_discover(tmp_path, "\n\n" + source))[0]["call_contract"] == first
    changed = _calls(_discover(tmp_path, source.replace("first", "second")))[0]["call_contract"]
    assert changed["expression_sha256"] != first["expression_sha256"]
    assert changed["arguments"] != first["arguments"]


def test_identical_call_occurrences_are_distinct_per_function(tmp_path):
    calls = _calls(_discover(tmp_path, "def work(fn):\n    fn(1)\n    fn(1)\ndef other(fn):\n    fn(1)\n"))
    assert [call["call_contract"]["occurrence"] for call in calls] == [0, 1, 0]
    assert len({call["call_contract"]["expression_sha256"] for call in calls}) == 1


@pytest.mark.parametrize("version", ["0.9", "2.0", "", 1, True, []])
def test_unknown_call_contract_version_rejects_before_source_reads(tmp_path, version):
    with pytest.raises(SemanticInventoryError, match="call contract version"):
        discover_python_source(tmp_path, files=[tmp_path / "missing.py"], call_contracts_version=version)

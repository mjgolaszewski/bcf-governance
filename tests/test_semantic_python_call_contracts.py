from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source, resolve_python_imports, SemanticInventoryError,
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


def test_call_contracts_validate_and_reject_authority_and_missing_calls(tmp_path):
    inventory = _discover(tmp_path, "def work(fn):\n    fn()\n")
    schema = json.loads((Path(__file__).parents[1] / "schemas/semantic-call-contracts.schema.json").read_text())
    validator = Draft202012Validator(schema)
    validator.validate(inventory)
    fact = _calls(inventory)[0]["call_contract"]
    fact["authority"] = True
    assert list(validator.iter_errors(inventory))
    fact["authority"] = False
    del _calls(inventory)[0]["call_contract"]
    assert list(validator.iter_errors(inventory))


def test_explicit_none_preserves_default_inventory(tmp_path):
    path = tmp_path / "model.py"
    path.write_text("def work(fn):\n    fn('value')\n")
    default = discover_python_source(tmp_path, files=[path])
    assert discover_python_source(tmp_path, files=[path], call_contracts_version=None) == default
    assert "authority" not in default
    assert all("call_contract" not in call for call in _calls(default))


def test_nested_calls_each_receive_facts_without_source_mutation(tmp_path):
    path = tmp_path / "model.py"
    source = "def work(fn, nested):\n    fn(nested(1))\n"
    inventory = _discover(tmp_path, source)
    assert len(_calls(inventory)) == 2
    assert all(call["call_contract"]["occurrence"] == 0 for call in _calls(inventory))
    assert path.read_text() == source


def test_import_resolution_preserves_lexical_call_contracts(tmp_path):
    owner = tmp_path / "owner.py"
    owner.write_text("def execute(value):\n    return value\n")
    caller = tmp_path / "caller.py"
    caller.write_text("from owner import execute as run\ndef work():\n    return run('value')\n")
    discovered = discover_python_source(tmp_path, files=[owner, caller], call_contracts_version="1.0")
    before = _calls(discovered)[0]["call_contract"]
    resolved = resolve_python_imports(tmp_path, discovered)
    assert _calls(resolved)[0]["called_symbol"] == "owner.py::execute"
    assert _calls(resolved)[0]["call_contract"] == before
    assert resolved["call_contracts_version"] == "1.0"
    assert resolved["authority"] is False

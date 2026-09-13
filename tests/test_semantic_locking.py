"""Semantic lock candidates must preserve their value before persistence."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling import semantic_locking as locking


ROOT = Path(__file__).resolve().parents[1]


def _payload() -> dict:
    return {
        "schema_version": "1.0",
        "document": {
            "kind": "semantic_authority_lock", "version": "1.0.0",
            "status": "active", "path": "governance/semantic-lock.yml",
        },
        "contracts": dict.fromkeys(
            ("semantic_families", "application_operations", "canonical_representations"),
            "a" * 64,
        ),
        "source_inventory_sha256": "b" * 64,
        "projection_outputs": [],
    }


def test_empty_projection_outputs_round_trip_as_an_array() -> None:
    payload = _payload()
    candidate = locking.render_lock_yaml(payload)
    assert candidate.endswith(b"projection_outputs: []\n")
    assert yaml.safe_load(candidate) == payload


def test_nonempty_projection_rendering_retains_the_canonical_flow_rows() -> None:
    payload = _payload()
    row = {
        "path": "generated/output.py", "canonical_source": "src/input.py",
        "recipe_sha256": "c" * 64, "source_sha256": "d" * 64,
        "output_sha256": "e" * 64,
    }
    payload["projection_outputs"] = [row]
    before = copy.deepcopy(payload)
    header = {key: value for key, value in payload.items() if key != "projection_outputs"}
    expected = yaml.safe_dump(header, sort_keys=False, width=1000)
    expected += "projection_outputs:\n- " + yaml.safe_dump(
        row, sort_keys=False, default_flow_style=True, width=1000,
    ).strip() + "\n"
    assert locking.render_lock_yaml(payload) == expected.encode()
    assert payload == before


def test_validated_empty_lock_is_schema_valid_and_deterministic() -> None:
    payload = _payload()
    assert locking.validated_lock_bytes(ROOT, payload) == locking.render_lock_yaml(payload)
    assert locking.validated_lock_bytes(ROOT, payload) == locking.validated_lock_bytes(ROOT, payload)


@pytest.mark.parametrize("corruption", ["null", "different", "invalid_yaml"])
def test_rendered_candidate_must_decode_to_the_requested_value(monkeypatch, corruption) -> None:
    payload = _payload()
    changed = copy.deepcopy(payload)
    if corruption == "null":
        changed["projection_outputs"] = None
    elif corruption == "different":
        changed["source_inventory_sha256"] = "f" * 64
    candidate = b"[unclosed" if corruption == "invalid_yaml" else yaml.safe_dump(changed).encode()
    monkeypatch.setattr(locking, "render_lock_yaml", lambda value: candidate)
    with pytest.raises(locking.SemanticLockError, match="candidate"):
        locking.validated_lock_bytes(ROOT, payload)


@pytest.mark.parametrize("mutation", ["missing", "unknown", "digest", "wrong_kind"])
def test_equivalent_but_schema_invalid_lock_candidate_is_rejected(mutation) -> None:
    payload = _payload()
    if mutation == "missing":
        del payload["contracts"]
    elif mutation == "unknown":
        payload["extra"] = True
    elif mutation == "digest":
        payload["source_inventory_sha256"] = "invalid"
    else:
        payload["document"]["kind"] = "wrong"
    with pytest.raises(locking.SemanticLockError, match="schema"):
        locking.validated_lock_bytes(ROOT, payload)


def test_missing_schema_fails_before_persistence(tmp_path) -> None:
    with pytest.raises(locking.SemanticLockError, match="schema"):
        locking.validated_lock_bytes(tmp_path, _payload())


@pytest.mark.parametrize("schema", ['{"type":"not-a-type"}', "["])
def test_invalid_schema_is_a_local_lock_error(tmp_path, schema) -> None:
    path = tmp_path / "schemas/semantic-lock.schema.json"
    path.parent.mkdir()
    path.write_text(schema)
    with pytest.raises(locking.SemanticLockError, match="schema"):
        locking.validated_lock_bytes(tmp_path, _payload())

"""Focused neutral-flow contracts; UNRUN until an allocated qualification."""
from __future__ import annotations

import ast
from typing import Any

import pytest

from bcf_governance.tooling.semantic_python_return_facts import discover_return_facts


def _fact(source: str, symbol: str = "sample.py::produce") -> dict[str, Any]:
    return next(row for row in discover_return_facts(ast.parse(source), path="sample.py")
                if row["symbol"] == symbol)


def test_constructor_syntax_never_grants_identity() -> None:
    row = _fact("class Model: pass\ndef produce(): return Model()\n")
    origin = row["returns"][0]["alternatives"][0]
    assert origin["kind"] == "call_result"
    assert origin["constructor_syntax_candidate"] is True
    assert origin["identity_authority"] is False
    assert origin["line"] == 2 and origin["column"] == 22
    assert row["identity_authority"] is False


def test_real_self_and_parameter_alias_are_distinct() -> None:
    row = _fact("class Model:\n def produce(self):\n  alias = self\n  return alias\n",
                "sample.py::Model.produce")
    assert row["returns"][0]["alternatives"] == [{"kind": "self", "name": "self"}]
    row = _fact("def produce(value):\n alias = value\n return alias\n")
    assert row["returns"][0]["alternatives"] == [{"kind": "parameter", "name": "value"}]
    assert row["local_bindings"][0]["name"] == "alias"


def test_conditional_join_keeps_all_alternatives() -> None:
    row = _fact("class Model: pass\ndef produce(flag, other):\n if flag:\n  value = Model()\n else:\n  value = other\n return value\n")
    origins = row["returns"][0]["alternatives"]
    assert {origin["kind"] for origin in origins} == {"call_result", "parameter"}


def test_possible_fallthrough_none_and_raise_are_distinct() -> None:
    row = _fact("def produce(flag, value):\n if flag:\n  return value\n")
    assert any(ret["implicit"] and ret["alternatives"] == [{"kind": "none"}]
               for ret in row["returns"])
    row = _fact("def produce():\n raise ValueError('rejected')\n")
    assert not row["returns"]


def test_reassignment_and_escape_do_not_keep_stale_origin() -> None:
    row = _fact("class Model: pass\ndef produce(other):\n value = Model()\n value = other\n return value\n")
    assert row["returns"][0]["alternatives"] == [{"kind": "parameter", "name": "other"}]
    row = _fact("class Model: pass\ndef produce():\n value = Model()\n external(value)\n return value\n")
    assert row["returns"][0]["alternatives"][0]["reason"] == "escaped_to_call"
    assert {call["callee"] for call in row["call_sites"]} == {"Model", "external"}


@pytest.mark.parametrize("source", [
    "async def produce(): return Model()\n",
    "def produce(): return produce()\n",
    "def produce():\n def nested(): return Model()\n return nested()\n",
    "def produce():\n for item in values:\n  return Model()\n",
    "def produce():\n try:\n  return Model()\n finally:\n  replace_model()\n",
    "def produce():\n global Model\n return Model()\n",
])
def test_unsupported_flow_is_explicit(source: str) -> None:
    row = _fact(source)
    assert row["unsupported"]
    assert all(origin["kind"] == "unknown"
               for ret in row["returns"] for origin in ret["alternatives"])


def test_annotations_do_not_create_receiver_origins() -> None:
    row = _fact("def produce(value: Model) -> Model: return value\n")
    assert row["returns"][0]["alternatives"] == [{"kind": "parameter", "name": "value"}]
    assert not row["call_sites"]

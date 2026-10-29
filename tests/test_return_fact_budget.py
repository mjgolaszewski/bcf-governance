"""Symbolic origin growth has a finite conservative refusal, source-only UNRUN."""
from __future__ import annotations

import ast

from bcf_governance.tooling.semantic_python_return_facts import discover_return_facts


def test_repeated_origin_fanout_refuses_within_budget() -> None:
    source = "def produce(value):\n" + "    value = combine(value, value)\n" * 10 + "    return value\n"
    facts = discover_return_facts(ast.parse(source), path="sample.py")[0]
    assert "origin_budget" in facts["unsupported"]
    assert all(origin["kind"] == "unknown"
               for row in facts["returns"] for origin in row["alternatives"])
    assert len(facts["call_sites"]) == 10

"""Optional specialization retains ordinary source effects and hard refusals."""
from pathlib import Path
from typing import Any

import pytest

from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, validate_operation_effects


def _observed(tmp_path: Path, source: str) -> dict[str, Any]:
    target = tmp_path / "owned.py"
    target.write_text(source + "\ndef entry():\n    return routine()\n")
    return resolve_python_imports(tmp_path, discover_python_source(tmp_path, [target]))


def _query() -> dict[str, Any]:
    return {"id": "query", "allowed_mutation_ports": [], "allowed_authority_ports": [],
            "non_authoritative_output_effects": [], "allowed_read_ports": ["owned.py::routine"],
            "authoritative_read": True}


def test_ordinary_pure_source_call_still_walks_its_body(tmp_path: Path) -> None:
    found = _observed(tmp_path, "def routine(value=1):\n    return str(value)\n")
    caller = next(row for row in found["functions"] if row["symbol"] == "owned.py::entry")
    edge = caller["calls"][0]
    assert edge["literal_default_applicability"] == "outside_literal_subset"
    assert edge.get("literal_default_admission") is not True
    assert validate_operation_effects(_query(), caller["symbol"], found) == (0, 0)


@pytest.mark.parametrize("source", [
    "def routine(target=None):\n    return target.get('x')\n",
    "def routine(target=None):\n    target.write_text('changed')\n    return str('ok')\n",
    "def routine(target=None):\n    target.enabled = True\n    return str('ok')\n",
    "def routine(target=None):\n    target['enabled'] = True\n    return str('ok')\n",
    "def routine(value=external()):\n    return str(value)\n",
    "def routine(value=1):\n    return str(value)\nroutine = external\n",
])
def test_optional_analysis_cannot_hide_opaque_write_default_or_binding_effects(tmp_path: Path, source: str) -> None:
    found = _observed(tmp_path, source)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(_query(), "owned.py::entry", found)

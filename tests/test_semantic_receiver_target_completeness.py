from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source,
    resolve_python_imports,
)


def inventory(tmp_path: Path, source: str) -> dict:
    path = tmp_path / "service.py"
    path.write_text(source, encoding="utf-8")
    return resolve_python_imports(
        tmp_path, discover_python_source(tmp_path, files=[path]), (".",),
    )


def operation() -> dict:
    return {
        "id": "fixture.query.v1",
        "allowed_mutation_ports": [],
        "allowed_authority_ports": [],
        "non_authoritative_output_effects": [],
    }


@pytest.mark.parametrize("statement,expected", [
    ("self.left, self.right = value", {"left", "right"}),
    ("[self.left, self.right] = value", {"left", "right"}),
    ("self.left, (self.middle, self.right) = value", {"left", "middle", "right"}),
    ("self.left, *self.rest = value", {"left", "rest"}),
    ("del (self.left, self.right)", {"left", "right"}),
    ("other.left, other.right = value", set()),
])
def test_inventory_retains_exact_destructured_receiver_fields(
    tmp_path: Path, statement: str, expected: set[str],
) -> None:
    facts = inventory(tmp_path, "class Service:\n    def change(self, value, other):\n        " + statement + "\n")
    row = next(f for f in facts["functions"] if f["symbol"] == "service.py::Service.change")
    assert set(row["receiver_attribute_mutations"]) == expected


@pytest.mark.parametrize("statement", [
    "self._read, self.other = value",
    "[self._read, self.other] = value",
    "self.other, (self._read, self.last) = value",
    "self.other, *self._read = value",
    "del (self._read, self.other)",
])
def test_destructured_method_write_refuses_exact_same_instance_dispatch(
    tmp_path: Path, statement: str,
) -> None:
    facts = inventory(tmp_path, (
        "class Service:\n"
        "    def query(self): return self._read()\n"
        "    def _read(self): return 1\n"
        "    def change(self, value):\n        " + statement + "\n"
    ))
    query = next(f for f in facts["functions"] if f["symbol"] == "service.py::Service.query")
    call = next(c for c in query["calls"] if c["call_name"] == "_read")
    assert call["dispatch_resolution"] == "unresolved"
    assert call["dispatch_port_eligible"] is False
    assert any(f["dispatch_kind"] == "receiver_attribute_rebound" for f in query["effect_unresolved"])
    with pytest.raises(SemanticOperationEffectError, match="unresolved effect call path"):
        validate_operation_effects(operation(), "service.py::Service.query", facts)


def test_healthy_same_instance_dispatch_still_traces_pure_body(tmp_path: Path) -> None:
    facts = inventory(tmp_path, "class Service:\n    def query(self): return self._read()\n    def _read(self): return 1\n")
    assert validate_operation_effects(operation(), "service.py::Service.query", facts) == (0, 0)

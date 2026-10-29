"""Native return-graph fanout must refuse without unbounded exploration."""
from __future__ import annotations

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


def test_factory_graph_fanout_remains_unknown_when_budget_exhausted(tmp_path: Path) -> None:
    source = "class Model:\n def has_capability(self, value): return True\n"
    source += "def factory0(flag): return Model()\n"
    for index in range(1, 17):
        previous = "factory" + str(index - 1) + "(flag)"
        source += f"def factory{index}(flag): return {previous} if flag else {previous}\n"
    source += "def check(flag): return factory16(flag).has_capability('read')\n"
    path = tmp_path / "sample.py"
    path.write_text(source)
    inventory = resolve_python_imports(tmp_path, discover_python_source(tmp_path, [path]))
    assert inventory.get("result_receiver_budget_exhausted") is True
    operation = {"id": "query", "allowed_mutation_ports": [],
                 "allowed_authority_ports": [], "non_authoritative_output_effects": []}
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(operation, "sample.py::check", inventory)

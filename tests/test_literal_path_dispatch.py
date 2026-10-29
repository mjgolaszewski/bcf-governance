"""Stdlib literal allocation does not erase method, argument or binding effects."""
from pathlib import Path
from typing import Any

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source,
    resolve_python_imports,
)

QUERY = {"id": "query", "allowed_mutation_ports": [], "allowed_authority_ports": [],
         "non_authoritative_output_effects": []}


def source_inventory(tmp_path: Path, source: str) -> dict[str, Any]:
    path = tmp_path / "subject.py"
    path.write_text(source)
    return resolve_python_imports(tmp_path, discover_python_source(tmp_path, [path]))


def test_literal_path_allocation_is_known_but_return_model_is_not(tmp_path: Path) -> None:
    found = source_inventory(tmp_path, "from pathlib import Path\ndef query(): return Path('state')\n")
    function = next(row for row in found["functions"] if row["symbol"] == "subject.py::query")
    call = next(call for call in function["calls"] if call["call_name"] == "Path")
    assert call["dispatch_resolution"] == "exact_stdlib_literal_path_constructor"
    assert call["result_identity"] == "unresolved_external"
    assert validate_operation_effects(QUERY, "subject.py::query", found) == (0, 0)


def test_literal_constructor_cannot_hide_actual_write(tmp_path: Path) -> None:
    found = source_inventory(tmp_path, "from pathlib import Path\ndef query(): Path('state').write_text('changed')\n")
    with pytest.raises(SemanticOperationEffectError, match="undeclared write effects"):
        validate_operation_effects(QUERY, "subject.py::query", found)


def test_pathlike_input_cannot_borrow_literal_constructor_contract(tmp_path: Path) -> None:
    found = source_inventory(tmp_path, "from pathlib import Path\ndef query(value): return Path(value)\n")
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(QUERY, "subject.py::query", found)


def test_rebound_path_class_does_not_receive_intrinsic_permission(tmp_path: Path) -> None:
    found = source_inventory(tmp_path, "from pathlib import Path\nPath = arbitrary\ndef query(): return Path('state')\n")
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(QUERY, "subject.py::query", found)


def test_mutated_imported_alias_does_not_receive_intrinsic_permission(tmp_path: Path) -> None:
    found = source_inventory(tmp_path, "import pathlib\nfrom pathlib import Path as P\nsetattr(pathlib, 'Path', arbitrary)\ndef query(): return P('state')\n")
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(QUERY, "subject.py::query", found)

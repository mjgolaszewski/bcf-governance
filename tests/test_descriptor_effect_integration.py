"""Native discovery/resolution/effect cases, source prepared and UNRUN."""
from __future__ import annotations

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


def _native(tmp_path: Path, source: str) -> dict[str, Any]:
    path = tmp_path / "sample.py"
    path.write_text(source)
    return resolve_python_imports(tmp_path, discover_python_source(tmp_path, [path]))


def _operation() -> dict[str, Any]:
    return {"id": "descriptor-query", "allowed_mutation_ports": [],
            "allowed_authority_ports": [], "non_authoritative_output_effects": []}


def test_native_exact_super_rewrites_real_dispatch_and_preserves_argument_effect(tmp_path: Path) -> None:
    inventory = _native(tmp_path, "class E(ValueError):\n    def __init__(self, path):\n        super().__init__(path.write_text('changed'))\n")
    function = next(row for row in inventory["functions"] if row["symbol"] == "sample.py::E.__init__")
    assert any(call["called_symbol"] == "builtin:ValueError.__init__"
               and call["dispatch_resolution"] == "exact_builtin_exception_constructor"
               for call in function["calls"])
    assert not any(failure.get("dispatch_kind") == "super" for failure in function["effect_unresolved"])
    assert any(call["call_name"] == "write_text" for call in function["calls"])
    with pytest.raises(SemanticOperationEffectError, match="undeclared write"):
        validate_operation_effects(_operation(), "sample.py::E.__init__", inventory)


def test_native_exact_super_pure_case_and_shadow_adversary(tmp_path: Path) -> None:
    source = "class E(ValueError):\n    def __init__(self, message):\n        super().__init__(message)\n"
    healthy = _native(tmp_path, source)
    assert validate_operation_effects(_operation(), "sample.py::E.__init__", healthy) == (0, 0)
    adversary = _native(tmp_path, "super = fake\n" + source)
    with pytest.raises(SemanticOperationEffectError, match="unresolved"):
        validate_operation_effects(_operation(), "sample.py::E.__init__", adversary)


@pytest.mark.parametrize("effect", ["path.write_text('changed')", "publish_release()", "self.cache = 1"])
def test_native_getter_hidden_effects_are_not_purity(tmp_path: Path, effect: str) -> None:
    source = "class C:\n    @property\n    def value(self):\n        " + effect + "\n        return 1\n    def read(self): return self.value\n"
    inventory = _native(tmp_path, source)
    function = next(row for row in inventory["functions"] if row["symbol"] == "sample.py::C.read")
    assert any(call["called_symbol"] == "sample.py::C.value" for call in function["calls"])
    with pytest.raises(SemanticOperationEffectError, match="undeclared (write|authority)"):
        validate_operation_effects(_operation(), "sample.py::C.read", inventory)




def test_native_getter_healthy_adverse_restored(tmp_path: Path) -> None:
    healthy = "class C:\n    @property\n    def value(self): return 1\n    def read(self): return self.value\n"
    assert validate_operation_effects(_operation(), "sample.py::C.read", _native(tmp_path, healthy)) == (0, 0)
    adverse = healthy.replace("def value(self): return 1", "def value(self): return path.write_text('changed')")
    with pytest.raises(SemanticOperationEffectError, match="undeclared write"):
        validate_operation_effects(_operation(), "sample.py::C.read", _native(tmp_path, adverse))
    assert validate_operation_effects(_operation(), "sample.py::C.read", _native(tmp_path, healthy)) == (0, 0)

"""Construction paths expand source obligations without earning effect-port authority."""
from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError, source_operation_call_population, validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports


def _source(tmp_path: Path, source: str):
    path = tmp_path / "service.py"
    path.write_text(source)
    return resolve_python_imports(
        tmp_path, discover_python_source(tmp_path, files=[path], call_contracts_version="1.0"),
    )


def _operation(port=None):
    return {
        "id": "source-construction.query.v1",
        "allowed_mutation_ports": [port] if port else [],
        "allowed_authority_ports": [],
        "non_authoritative_output_effects": [],
    }


def test_nested_constructor_call_keeps_full_source_spans(tmp_path):
    inventory = _source(tmp_path, (
        "class Owner:\n"
        "    def __init__(self):\n        pass\n"
        "    def read(self):\n        return 1\n"
        "def query():\n    return Owner().read()\n"
    ))
    query = next(row for row in inventory["functions"] if row["symbol"] == "service.py::query")
    calls = query["calls"]
    assert len(calls) == 2
    fields = ("line", "column", "end_line", "end_column")
    assert all(set(fields) <= call.keys() for call in calls), "full source spans absent"
    assert len({tuple(call[key] for key in fields) for call in calls}) == 2
    constructors = [call for call in calls if call.get("construction_effect_observation")]
    assert len(constructors) == 1 and constructors[0]["call_name"] == "Owner"
    assert constructors[0]["construction_effect_observation"]["authority"] is False


def test_source_population_adds_constructor_body_but_keeps_unresolved_status(tmp_path):
    inventory = _source(tmp_path, (
        "class Owner:\n    def __init__(self):\n        pass\n"
        "def query():\n    return Owner()\n"
    ))
    population = source_operation_call_population("service.py::query", inventory)
    assert "service.py::Owner.__init__" in population["functions"], "constructor source body omitted"
    assert population["authority"] is population["execution_qualified"] is False
    assert population["unresolved_calls"] >= 1


def test_constructor_only_path_cannot_earn_required_mutation_port_credit(tmp_path):
    inventory = _source(tmp_path, (
        "from pathlib import Path\n"
        "def store():\n    Path('state').write_text('changed')\n"
        "class Owner:\n    def __init__(self):\n        store()\n"
        "def query():\n    return Owner()\n"
    ))
    with pytest.raises(SemanticOperationEffectError, match="unreachable effect ports"):
        validate_operation_effects(_operation("service.py::store"), "service.py::query", inventory)


def test_independent_direct_port_path_retains_credit_with_constructor_obligation(tmp_path):
    inventory = _source(tmp_path, (
        "from pathlib import Path\n"
        "def store():\n    Path('state').write_text('changed')\n"
        "class Owner:\n    def __init__(self):\n        store()\n"
        "def query():\n    store()\n    return Owner()\n"
    ))
    assert validate_operation_effects(
        _operation("service.py::store"), "service.py::query", inventory,
    ) == (1, 0)


def test_forged_authority_in_constructor_observation_is_rejected(tmp_path):
    inventory = _source(tmp_path, (
        "class Owner:\n    def __init__(self):\n        pass\n"
        "def query():\n    return Owner()\n"
    ))
    query = next(row for row in inventory["functions"] if row["symbol"] == "service.py::query")
    query["calls"][0]["construction_effect_observation"] = {
        "authority": True, "source_class_resolved": True,
        "class_candidates": ["service.py::Owner"],
        "function_candidates": ["service.py::Owner.__init__"], "unresolved": [],
    }
    with pytest.raises(SemanticOperationEffectError, match="construction source"):
        validate_operation_effects(_operation(), "service.py::query", inventory)


def test_shadowed_staticmethod_cannot_supply_constructor_provenance(tmp_path):
    inventory = _source(tmp_path, (
        "from pathlib import Path\n"
        "def staticmethod(function):\n"
        "    def replacement(*args):\n        Path('state').write_text('changed')\n"
        "    return replacement\n"
        "class Owner:\n"
        "    @staticmethod\n    def __init__(self):\n        pass\n"
        "def query():\n    return Owner()\n"
    ))
    with pytest.raises(SemanticOperationEffectError, match="construction.*provenance"):
        validate_operation_effects(_operation(), "service.py::query", inventory)

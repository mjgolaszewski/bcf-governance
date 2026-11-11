"""Known class identities, not spelling or optional flags, determine source obligations."""
from copy import deepcopy
from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError, source_operation_call_population, validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports


def _inventory(tmp_path: Path, sources: dict[str, str]):
    paths = []
    for relative, source in sources.items():
        path = tmp_path / relative
        path.write_text(source)
        paths.append(path)
    return resolve_python_imports(
        tmp_path, discover_python_source(tmp_path, files=paths, call_contracts_version="1.0"),
    )


def _operation():
    return {
        "id": "construction-source.query.v1", "allowed_mutation_ports": [],
        "allowed_authority_ports": [], "non_authoritative_output_effects": [],
    }


@pytest.mark.parametrize("style", ("lower-import-alias", "qualified-module", "local-lower-class"))
def test_class_call_identity_exposes_constructor_write_independent_of_spelling(tmp_path, style):
    declaration = (
        "from pathlib import Path\n"
        "class Owner:\n    def __init__(self):\n        Path('state').write_text('changed')\n"
    )
    if style == "lower-import-alias":
        sources = {"owner.py": declaration, "service.py": "from owner import Owner as factory\ndef query():\n    return factory()\n"}
    elif style == "qualified-module":
        sources = {"owner.py": declaration, "service.py": "import owner as provider\ndef query():\n    return provider.Owner()\n"}
    else:
        sources = {"service.py": declaration.replace("class Owner:", "class factory:") + "def query():\n    return factory()\n"}
    inventory = _inventory(tmp_path, sources)
    expected = "undeclared write" if style == "lower-import-alias" else "(undeclared write|unresolved effect)"
    with pytest.raises(SemanticOperationEffectError, match=expected):
        validate_operation_effects(_operation(), "service.py::query", inventory)
    query = next(row for row in inventory["functions"] if row["symbol"] == "service.py::query")
    assert len(query["constructors"]) == 1
    assert query["constructors"][0]["construction_effect_observation"]["source_class_resolved"] is True


@pytest.mark.parametrize("consumer", ("effect", "population"))
@pytest.mark.parametrize("defect", ("missing-fact-and-observation", "false-class-flag", "duplicate-fact"))
def test_consumers_reject_inconsistent_constructor_source_population(tmp_path, consumer, defect):
    inventory = _inventory(tmp_path, {
        "service.py": "class Owner:\n    def __init__(self):\n        pass\ndef query():\n    return Owner()\n",
    })
    query = next(row for row in inventory["functions"] if row["symbol"] == "service.py::query")
    assert len(query["calls"]) == len(query["constructors"]) == 1
    if defect == "missing-fact-and-observation":
        query["calls"][0].pop("construction_effect_observation")
        query["constructors"].clear()
    elif defect == "false-class-flag":
        query["calls"][0]["construction_effect_observation"]["source_class_resolved"] = False
        query["constructors"][0]["construction_effect_observation"]["source_class_resolved"] = False
    else:
        query["constructors"].append(deepcopy(query["constructors"][0]))
    with pytest.raises(SemanticOperationEffectError, match="construction source"):
        if consumer == "effect":
            validate_operation_effects(_operation(), "service.py::query", inventory)
        else:
            source_operation_call_population("service.py::query", inventory)

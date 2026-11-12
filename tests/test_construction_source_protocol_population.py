"""Independent source-hook coverage and ordinary implicit-protocol consumers."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError, source_operation_call_population, validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports
from bcf_governance.tooling.semantic_source_discovery import merge_inventories
from bcf_governance.tooling.semantic_ownership_typescript import TypeScriptDiscoveryError

FIXTURE = Path(__file__).parent / "fixtures/cpython-31214-protocol-source-input.json"
LANGUAGE = json.loads(FIXTURE.read_text())
SOURCE_HOOKS = tuple(sorted(set(LANGUAGE["source"]["names"]) |
                           set(LANGUAGE["additional_documented_hooks"]["names"]))) + ("__future_protocol__",)
NATIVE_CASES = {
  "bool": [
    "    def __bool__(self):\n        Path('state').write_text('changed')\n        return True\n",
    "    return bool(TYPE())\n"
  ],
  "len": [
    "    def __len__(self):\n        Path('state').write_text('changed')\n        return 1\n",
    "    return len(TYPE())\n"
  ],
  "hash": [
    "    def __hash__(self):\n        Path('state').write_text('changed')\n        return 1\n",
    "    return hash(TYPE())\n"
  ],
  "str": [
    "    def __str__(self):\n        Path('state').write_text('changed')\n        return 'owner'\n",
    "    return str(TYPE())\n"
  ],
  "repr": [
    "    def __repr__(self):\n        Path('state').write_text('changed')\n        return 'owner'\n",
    "    return repr(TYPE())\n"
  ],
  "format": [
    "    def __format__(self, spec):\n        Path('state').write_text('changed')\n        return 'owner'\n",
    "    return f'{TYPE():x}'\n"
  ],
  "getitem": [
    "    def __getitem__(self, index):\n        Path('state').write_text('changed')\n        return 1\n",
    "    return TYPE()[0]\n"
  ],
  "setitem": [
    "    def __setitem__(self, index, value):\n        Path('state').write_text('changed')\n",
    "    owner = TYPE()\n    owner[0] = 1\n    return 1\n"
  ],
  "delitem": [
    "    def __delitem__(self, index):\n        Path('state').write_text('changed')\n",
    "    owner = TYPE()\n    del owner[0]\n    return 1\n"
  ],
  "add": [
    "    def __add__(self, value):\n        Path('state').write_text('changed')\n        return 1\n",
    "    return TYPE() + 1\n"
  ],
  "enter": [
    "    def __enter__(self):\n        Path('state').write_text('changed')\n        return self\n    def __exit__(self, *exc):\n        return False\n",
    "    with TYPE():\n        pass\n    return 1\n"
  ],
  "exit": [
    "    def __enter__(self):\n        return self\n    def __exit__(self, *exc):\n        Path('state').write_text('changed')\n        return False\n",
    "    with TYPE():\n        pass\n    return 1\n"
  ]
}

def _inventory(tmp_path, sources):
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
        "id": "source-protocol.query.v1", "allowed_mutation_ports": [],
        "allowed_authority_ports": [], "non_authoritative_output_effects": [],
    }

def _consume(consumer, inventory):
    if consumer == "effect":
        return validate_operation_effects(_operation(), "service.py::query", inventory)
    return source_operation_call_population("service.py::query", inventory)

def _sources(case, context):
    methods, query = NATIVE_CASES[case]
    declaration = "from pathlib import Path\nclass Owner:\n    def __init__(self):\n        pass\n" + methods
    if context in {"local", "inherited"}:
        if context == "inherited":
            declaration = declaration.replace("class Owner:", "class Base:") + "class Owner(Base):\n    pass\n"
        return {"service.py": declaration + "def query():\n" + query.replace("TYPE", "Owner")}
    name = "factory" if context == "lower-import-alias" else "Owner"
    return {
        "owner.py": declaration,
        "service.py": f"from owner import Owner as {name}\ndef query():\n" + query.replace("TYPE", name),
    }

def test_protocol_source_input_retains_exact_independent_bytes():
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == "422bed5776d398f8212984ea3f637c37c6865feafeb9da739fd1859ab17a356e"
    assert LANGUAGE["source"]["blob"] == "b0c79d34e6525bff2babe2de3d4cbf8cfeb08905"
    assert len(LANGUAGE["source"]["names"]) == len(set(LANGUAGE["source"]["names"])) == 81
    assert len(SOURCE_HOOKS) == 90
    assert LANGUAGE["authority"] is False

@pytest.mark.parametrize("hook", SOURCE_HOOKS)
def test_independent_language_population_retains_each_potential_source_body(tmp_path, hook):
    source = (
        "from pathlib import Path\nclass Owner:\n"
        f"    def {hook}(self, *args, **kwargs):\n"
        "        Path('state').write_text('changed')\n"
        "def query():\n    return Owner()\n"
    )
    inventory = _inventory(tmp_path, {"service.py": source})
    population = source_operation_call_population("service.py::query", inventory)
    assert "service.py::Owner." + hook in population["functions"], "potential protocol source body omitted"
    assert population["authority"] is population["execution_qualified"] is False
    if hook not in LANGUAGE["source_body_obligations_not_runtime_authority"]:
        assert _observation(inventory)["unresolved"], "unqualified protocol runtime provenance erased"

@pytest.mark.parametrize("case", tuple(NATIVE_CASES))
@pytest.mark.parametrize("context", ("local", "imported", "lower-import-alias", "inherited"))
def test_source_effect_consumer_cannot_hide_implicit_protocol_write(tmp_path, case, context):
    inventory = _inventory(tmp_path, _sources(case, context))
    with pytest.raises(SemanticOperationEffectError, match="(source construction|construction source|undeclared write|unresolved effect)"):
        _consume("effect", inventory)

@pytest.mark.parametrize("case", tuple(NATIVE_CASES))
@pytest.mark.parametrize("context", ("local", "inherited"))
def test_ordinary_isolated_consumer_witnesses_implicit_protocol_write(tmp_path, case, context):
    source = _sources(case, context)["service.py"] + (
        "value = query()\n"
        "assert Path('state').read_text() == 'changed'\n"
        "print('implicit-write-witnessed')\n"
    )
    fixture = tmp_path / "consumer.py"
    fixture.write_text(source)
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("PYTHON", "BCF_", "GIT_", "GITHUB_", "AGENTBUS_"))
                   and key not in {"GH_TOKEN", "VIRTUAL_ENV"}}
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(fixture)], cwd=tmp_path,
        env=environment, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "implicit-write-witnessed\n"
    assert not result.stderr

def _guard_inventory(tmp_path, hook, *, inherited=False, pure=False):
    if hook == "property":
        method = "    @property\n    def field(self):\n        Path('state').write_text('changed')\n        return 1\n"
        query = "def query():\n    return Owner().field\n"
        suffix = "field"
    else:
        value = "        return True\n" if pure else "        Path('state').write_text('changed')\n"
        method = f"    def {hook}(self, *args, **kwargs):\n" + value
        query = "def query():\n    return Owner()\n"
        suffix = hook
    initialization = "" if hook == "__init__" else "    def __init__(self):\n        pass\n"
    declaration = "from pathlib import Path\nclass Owner:\n" + initialization + method
    owner = "Owner"
    if inherited:
        declaration = declaration.replace("class Owner:", "class Base:") + "class Owner(Base):\n    pass\n"
        owner = "Base"
    return _inventory(tmp_path, {"service.py": declaration + query}), "service.py::" + owner + "." + suffix

def _observation(inventory):
    query = next(row for row in inventory["functions"] if row["symbol"] == "service.py::query")
    call = next(row for row in query["calls"] if row["call_name"] == "Owner")
    return call["construction_effect_observation"]

def _replace_observation(inventory, observation):
    query = next(row for row in inventory["functions"] if row["symbol"] == "service.py::query")
    for collection in (query["calls"], query["constructors"]):
        for fact in collection:
            if fact["called_symbol"] == "service.py::Owner":
                fact["construction_effect_observation"] = deepcopy(observation)

@pytest.mark.parametrize("consumer", ("effect", "population"))
@pytest.mark.parametrize("hook", ("__init__", "__del__", "__bool__", "property"))
def test_joint_class_edge_and_observation_omission_still_rejects(tmp_path, consumer, hook):
    inventory, body = _guard_inventory(tmp_path, hook)
    for row in inventory["classes"]:
        row["methods"] = [method for method in row["methods"] if method["symbol"] != body]
    observation = deepcopy(_observation(inventory))
    observation["function_candidates"] = [symbol for symbol in observation["function_candidates"] if symbol != body]
    observation["unresolved"] = []
    _replace_observation(inventory, observation)
    assert any(row["symbol"] == body for row in inventory["functions"]), "independent function body erased by control"
    with pytest.raises(SemanticOperationEffectError, match="construction source"):
        if consumer == "effect":
            validate_operation_effects(_operation(), "service.py::query", inventory, require_runtime_context=False)
        else:
            _consume(consumer, inventory)

@pytest.mark.parametrize("consumer", ("effect", "population"))
def test_joint_inherited_class_and_body_observation_omission_rejects(tmp_path, consumer):
    inventory, body = _guard_inventory(tmp_path, "__bool__", inherited=True)
    observation = deepcopy(_observation(inventory))
    observation["class_candidates"] = ["service.py::Owner"]
    observation["function_candidates"] = []
    observation["unresolved"] = []
    _replace_observation(inventory, observation)
    assert any(row["symbol"] == body for row in inventory["functions"])
    with pytest.raises(SemanticOperationEffectError, match="construction source"):
        _consume(consumer, inventory)

@pytest.mark.parametrize("consumer", ("effect", "population"))
@pytest.mark.parametrize("hook", ("__bool__", "__getattribute__", "__del__"))
def test_protocol_body_cannot_erase_runtime_uncertainty(tmp_path, consumer, hook):
    inventory, body = _guard_inventory(tmp_path, hook, pure=True)
    observation = deepcopy(_observation(inventory))
    if body not in observation["function_candidates"]:
        observation["function_candidates"].append(body)
    observation["unresolved"] = []
    _replace_observation(inventory, observation)
    with pytest.raises(SemanticOperationEffectError, match="construction source"):
        _consume(consumer, inventory)

@pytest.mark.parametrize("consumer", ("effect", "population"))
@pytest.mark.parametrize("cause", ("external-base", "class-decorator", "metaclass", "descriptor-binding"))
def test_source_context_uncertainty_cannot_be_erased(tmp_path, consumer, cause):
    declarations = {
        "external-base": "class Owner(ExternalBase):\n    pass\n",
        "class-decorator": "def model(cls):\n    return cls\n@model\nclass Owner:\n    pass\n",
        "metaclass": "class Meta(type):\n    pass\nclass Owner(metaclass=Meta):\n    pass\n",
        "descriptor-binding": "class Owner:\n    field = descriptor()\n",
    }
    inventory = _inventory(tmp_path, {"service.py": declarations[cause] + "def query():\n    return Owner()\n"})
    observation = deepcopy(_observation(inventory))
    assert observation["unresolved"], "source uncertainty absent from control"
    observation["unresolved"] = []
    _replace_observation(inventory, observation)
    with pytest.raises(SemanticOperationEffectError, match="construction source"):
        _consume(consumer, inventory)

@pytest.mark.parametrize("consumer", ("effect", "population"))
def test_cyclic_source_ancestry_cannot_erase_uncertainty(tmp_path, consumer):
    source = "class Base(Owner):\n    def __init__(self):\n        pass\nclass Owner(Base):\n    pass\ndef query():\n    return Owner()\n"
    inventory = _inventory(tmp_path, {"service.py": source})
    observation = deepcopy(_observation(inventory))
    observation["unresolved"] = []
    _replace_observation(inventory, observation)
    with pytest.raises(SemanticOperationEffectError, match="construction source"):
        _consume(consumer, inventory)

@pytest.mark.parametrize("consumer", ("effect", "population"))
@pytest.mark.parametrize("erase_types", (False, True))
def test_class_and_observation_cannot_hide_independent_method_scope(tmp_path, consumer, erase_types):
    inventory, body = _guard_inventory(tmp_path, "__init__")
    observation = deepcopy(_observation(inventory))
    inventory["classes"] = []
    if erase_types:
        inventory.pop("types")
    observation["source_class_resolved"] = False
    observation["unresolved"] = []
    _replace_observation(inventory, observation)
    assert any(row["symbol"] == body and row["class_symbol"] == "service.py::Owner"
               for row in inventory["functions"])
    with pytest.raises(SemanticOperationEffectError, match="construction source"):
        _consume(consumer, inventory)

def _mixed_inputs(tmp_path):
    python = _inventory(tmp_path, {"service.py": "class Owner:\n    def __init__(self):\n        pass\ndef query():\n    return Owner()\n"})
    typescript = {
        "language": "typescript",
        "files": [{"path": "src/query.ts", "sha256": "a" * 64}],
        "types": ["src/query.ts::Value"],
        "functions": [{"symbol": "src/query.ts::query", "language": "typescript", "calls": [], "effects": []}],
    }
    return python, typescript

def test_mixed_source_composition_retains_python_classes_and_both_consumers(tmp_path):
    python, typescript = _mixed_inputs(tmp_path)
    originals = deepcopy((python, typescript))
    combined = merge_inventories([python, typescript])
    assert combined["classes"] == python["classes"], "Python class facts lost in source composition"
    assert validate_operation_effects(_operation(), "service.py::query", combined) == (0, 0)
    assert validate_operation_effects(_operation(), "src/query.ts::query", combined) == (0, 0)
    assert (python, typescript) == originals

def test_identical_source_class_inputs_coalesce_without_changing_inputs(tmp_path):
    python, typescript = _mixed_inputs(tmp_path)
    combined = merge_inventories([python, deepcopy(python), typescript])
    assert combined["classes"] == python["classes"], "identical class population lost"

@pytest.mark.parametrize("field", ("bases", "methods", "class_decorators"))
def test_conflicting_source_class_identity_cannot_disappear_in_composition(tmp_path, field):
    python, _ = _mixed_inputs(tmp_path)
    contradictory = deepcopy(python)
    values = {
        "bases": [{"called_symbol": "service.py::Other", "line": 1}],
        "methods": [],
        "class_decorators": ["replace"],
    }
    contradictory["classes"][0][field] = values[field]
    with pytest.raises(TypeScriptDiscoveryError, match="classes"):
        merge_inventories([python, contradictory])

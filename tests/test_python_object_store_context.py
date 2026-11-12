"""Source subscript obligations stay neutral; local literals require a closed region."""
from copy import deepcopy
from pathlib import Path
import os
import subprocess
import sys

import pytest

from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, source_operation_call_population, validate_operation_effects
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports

PREFIX = "STATE = {'v': 0}\nHELD = []\ndef retain(value):\n    HELD.append(value)\n"
SHARED = {
    "global-set": ("def query():\n    STATE['v'] = 1\n    return 1\n", "query()", "STATE == {'v': 1}", False),
    "global-delete": ("def query():\n    del STATE['v']\n    return 1\n", "query()", "STATE == {}", False),
    "parameter-set": ("def query(value):\n    value['v'] = 1\n    return 1\n", "query(STATE)", "STATE == {'v': 1}", False),
    "parameter-augment": ("def query(value):\n    value['v'] += 1\n    return 1\n", "query(STATE)", "STATE == {'v': 1}", False),
    "parameter-delete": ("def query(value):\n    del value['v']\n    return 1\n", "query(STATE)", "STATE == {}", False),
    "parameter-alias": ("def query(value):\n    alias = value\n    alias['v'] = 1\n    return 1\n", "query(STATE)", "STATE == {'v': 1}", False),
    "escaped-literal": ("def query():\n    value = {}\n    retain(value)\n    value['v'] = 1\n    return 1\n", "query()", "HELD[0] == {'v': 1}", True),
    "opaque-key": ("class Key:\n    def __hash__(self):\n        STATE['v'] = 1\n        return 7\ndef query(key):\n    value = {}\n    value[key] = 1\n    return 1\n", "query(Key())", "STATE == {'v': 1}", False),
}
LOCAL = {
    "dict": "value = {}\nvalue['v'] = 1\nreturn value['v']",
    "list": "value = [0]\nvalue[0] = 1\nreturn value[0]",
    "dict-delete": "value = {'v': 0}\ndel value['v']\nreturn 1",
    "list-delete": "value = [0]\ndel value[0]\nreturn 1",
    "augment": "value = {'v': 0}\nvalue['v'] += 1\nreturn value['v']",
    "alias": "value = {}\nalias = value\nalias['v'] = 1\nreturn value['v']",
    "nested": "value = {'v': [0]}\nvalue['v'][0] = 1\nreturn value['v'][0]",
    "rebind": "value = {'v': 0}\nvalue = {}\nvalue['v'] = 1\nreturn value['v']",
}

def _fixture(case):
    if case in SHARED:
        source, call, witness, retained = SHARED[case]
        return PREFIX + source, call, witness, retained, "unresolved_object_binding"
    body = LOCAL[case]
    return PREFIX + "def query():\n    " + body.replace("\n", "\n    ") + "\n", "query()", "STATE == {'v': 0} and HELD == []", False, "closed_native_literal_region"


def _inventory(tmp_path, source):
    path = tmp_path / "service.py"
    path.write_text(source)
    return resolve_python_imports(tmp_path, discover_python_source(tmp_path, files=[path], call_contracts_version="1.0"))


def _operation(retained=False):
    return {"id": "object-store.query.v1", "allowed_mutation_ports": [],
            "allowed_authority_ports": [],
            "non_authoritative_output_effects": ["service.py::retain"] if retained else []}


@pytest.mark.parametrize("case", tuple(SHARED) + tuple(LOCAL))
def test_source_and_population_retain_every_store_disposition(tmp_path, case):
    source, _, _, _, expected = _fixture(case)
    inventory = _inventory(tmp_path, source)
    query = next(row for row in inventory["functions"] if row["symbol"] == "service.py::query")
    observations = query.get("source_store_observations", [])
    assert observations, "source subscript observations omitted"
    assert all(row["authority"] is row["execution_qualified"] is False for row in observations)
    assert all(row["disposition"] == expected for row in observations)
    population = source_operation_call_population("service.py::query", inventory)
    rows = [row for row in population.get("source_stores", ()) if row[0] == "service.py::query"]
    assert len(rows) == len(observations), "consumer omitted producer store obligations"
    assert all(row[3] == expected for row in rows)
    assert population["authority"] is population["execution_qualified"] is False


@pytest.mark.parametrize("case", tuple(SHARED))
def test_effect_consumer_rejects_unqualified_object_store(tmp_path, case):
    source, _, _, retained, _ = _fixture(case)
    inventory = _inventory(tmp_path, source)
    with pytest.raises(SemanticOperationEffectError, match="unresolved effect"):
        validate_operation_effects(_operation(retained), "service.py::query", inventory)


@pytest.mark.parametrize("case", tuple(LOCAL))
def test_closed_literal_region_preserves_local_behavior(tmp_path, case):
    source, _, _, _, _ = _fixture(case)
    inventory = _inventory(tmp_path, source)
    assert validate_operation_effects(_operation(), "service.py::query", inventory) == (0, 0)


@pytest.mark.parametrize("case", tuple(SHARED) + tuple(LOCAL))
def test_fresh_consumer_witnesses_object_store_context(tmp_path, case):
    source, call, witness, _, _ = _fixture(case)
    fixture = tmp_path / "consumer.py"
    fixture.write_text(source + "\nassert " + call + " == 1\nassert " + witness + "\nprint('object-context-witnessed')\n")
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("PYTHON", "BCF_", "GIT_", "GITHUB_", "AGENTBUS_"))
                   and key not in {"GH_TOKEN", "VIRTUAL_ENV"}}
    result = subprocess.run([sys.executable, "-I", "-B", str(fixture)], cwd=tmp_path,
                            env=environment, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "object-context-witnessed\n"
    assert not result.stderr

@pytest.mark.parametrize("consumer", ("population", "effects"))
@pytest.mark.parametrize("defect", ("authority", "execution", "duplicate", "drop-effect"))
def test_forged_or_unpaired_store_observation_is_rejected(tmp_path, consumer, defect):
    inventory = _inventory(tmp_path, _fixture("parameter-set")[0])
    query = next(row for row in inventory["functions"] if row["symbol"] == "service.py::query")
    observations = query.get("source_store_observations", [])
    assert observations, "source subscript observations omitted"
    if defect == "authority":
        observations[0]["authority"] = True
    elif defect == "execution":
        observations[0]["execution_qualified"] = True
    elif defect == "duplicate":
        observations.append(deepcopy(observations[0]))
    else:
        query["effects"] = []
    with pytest.raises(SemanticOperationEffectError, match="source store population"):
        if consumer == "population":
            source_operation_call_population("service.py::query", inventory)
        else:
            validate_operation_effects(_operation(), "service.py::query", inventory)

"""Explicit global bindings are source effects, never query-local writes."""
from pathlib import Path
import os
import subprocess
import sys

import pytest

from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, validate_operation_effects
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports

CASES = {
    "assign": ("    global state\n    state = 1\n    return 1\n", "state == 1"),
    "augmented": ("    global state\n    state += 1\n    return 1\n", "state == 1"),
    "delete": ("    global state\n    del state\n    return 1\n", "'state' not in globals()"),
    "walrus": ("    global state\n    return (state := 1)\n", "state == 1"),
    "unpack": ("    global state\n    state, local = (1, 2)\n    return 1\n", "state == 1"),
    "loop-target": ("    global state\n    for state in (1,):\n        pass\n    return 1\n", "state == 1"),
    "with-target": ("    global state\n    with nullcontext(1) as state:\n        pass\n    return 1\n", "state == 1"),
    "import-target": ("    global state\n    import math as state\n    return 1\n", "state.__name__ == 'math'"),
    "function-binding": ("    global state\n    def state():\n        return 1\n    return 1\n", "callable(state) and state() == 1"),
    "class-binding": ("    global state\n    class state:\n        pass\n    return 1\n", "isinstance(state, type)"),
    "nested-default": ("    global state\n    def deferred(value=(state := 1)):\n        return value\n    return 1\n", "state == 1"),
    "lexical-global": ("    if False:\n        global state\n    state = 1\n    return 1\n", "state == 1"),
}
POSITIVE = {
    "local": "def query():\n    state = 1\n    return state\n",
    "deferred-nested": "def query():\n    state = 1\n    def deferred():\n        global state\n        state = 2\n    return state\n",
    "definition-default": "def query(value=(state := 1)):\n    global state\n    return value\n",
}
PREFIX = "from contextlib import nullcontext\nstate = 0\n"


def _inventory(tmp_path, source):
    path = tmp_path / "service.py"
    path.write_text(source)
    return resolve_python_imports(tmp_path, discover_python_source(tmp_path, files=[path]))


def _operation():
    return {"id": "global-name.query.v1", "allowed_mutation_ports": [],
            "allowed_authority_ports": [], "non_authoritative_output_effects": []}


@pytest.mark.parametrize("case", tuple(CASES))
def test_producer_retains_explicit_global_store(tmp_path, case):
    body, _ = CASES[case]
    inventory = _inventory(tmp_path, PREFIX + "def query():\n" + body)
    function = next(row for row in inventory["functions"] if row["symbol"] == "service.py::query")
    assert any(effect.get("kind") == "write" and effect.get("target") == "state"
               and effect.get("scope") == "global" for effect in function.get("effects", [])), "explicit global binding omitted from source effects"


@pytest.mark.parametrize("case", tuple(CASES))
def test_effect_consumer_rejects_explicit_global_store(tmp_path, case):
    body, _ = CASES[case]
    inventory = _inventory(tmp_path, PREFIX + "def query():\n" + body)
    with pytest.raises(SemanticOperationEffectError, match="undeclared write"):
        validate_operation_effects(_operation(), "service.py::query", inventory)


def _run(tmp_path, source, marker):
    fixture = tmp_path / "consumer.py"
    fixture.write_text(source + "\nprint(" + repr(marker) + ")\n")
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("PYTHON", "BCF_", "GIT_", "GITHUB_", "AGENTBUS_"))
                   and key not in {"GH_TOKEN", "VIRTUAL_ENV"}}
    result = subprocess.run([sys.executable, "-I", "-B", str(fixture)], cwd=tmp_path,
                            env=environment, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == marker + "\n"
    assert not result.stderr


@pytest.mark.parametrize("case", tuple(CASES))
def test_fresh_consumer_witnesses_global_store(tmp_path, case):
    body, witness = CASES[case]
    _run(tmp_path, PREFIX + "def query():\n" + body + "\nassert query() == 1\nassert " + witness + "\n", "global-store-witnessed")


@pytest.mark.parametrize("case", tuple(POSITIVE))
def test_lexical_scope_preserves_local_and_deferred_behavior(tmp_path, case):
    inventory = _inventory(tmp_path, PREFIX + POSITIVE[case])
    assert validate_operation_effects(_operation(), "service.py::query", inventory) == (0, 0)


@pytest.mark.parametrize("case", tuple(POSITIVE))
def test_fresh_consumer_separates_definition_and_operation(tmp_path, case):
    _run(tmp_path, PREFIX + POSITIVE[case] + "\nstate = 0\nassert query() == 1\nassert state == 0\n", "local-definition-boundary-witnessed")

"""Ordinary mutations without write calls remain effect obligations."""
from pathlib import Path
import os
import subprocess
import sys

import pytest

from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, validate_operation_effects
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports

CASES = {
    "global-name": ("state = 0\ndef query():\n    global state\n    state = 1\n    return 1\n", "assert query() == 1\nassert state == 1\n", "service.py::query"),
    "global-augmented": ("state = 0\ndef query():\n    global state\n    state += 1\n    return 1\n", "assert query() == 1\nassert state == 1\n", "service.py::query"),
    "global-item": ("state = {'value': 0}\ndef query():\n    state['value'] = 1\n    return 1\n", "assert query() == 1\nassert state == {'value': 1}\n", "service.py::query"),
    "global-delete": ("state = {'value': 0}\ndef query():\n    del state['value']\n    return 1\n", "assert query() == 1\nassert state == {}\n", "service.py::query"),
    "parameter-item": ("def query(state):\n    state['value'] = 1\n    return 1\n", "state = {'value': 0}\nassert query(state) == 1\nassert state == {'value': 1}\n", "service.py::query"),
    "receiver-attribute": ("class Service:\n    def query(self):\n        self.value = 1\n        return 1\n", "value = Service()\nassert value.query() == 1\nassert value.value == 1\n", "service.py::Service.query"),
}


def _inventory(tmp_path, source):
    path = tmp_path / "service.py"
    path.write_text(source)
    return resolve_python_imports(tmp_path, discover_python_source(tmp_path, files=[path]))


def _operation():
    return {"id": "state-mutation.query.v1", "allowed_mutation_ports": [],
            "allowed_authority_ports": [], "non_authoritative_output_effects": []}


@pytest.mark.parametrize("case", tuple(CASES))
def test_effect_consumer_cannot_accept_undeclared_state_mutation(tmp_path, case):
    source, _, entrypoint = CASES[case]
    inventory = _inventory(tmp_path, source)
    with pytest.raises(SemanticOperationEffectError, match="(undeclared write|unresolved effect)"):
        validate_operation_effects(_operation(), entrypoint, inventory)


@pytest.mark.parametrize("case", tuple(CASES))
def test_fresh_python_consumer_witnesses_non_call_mutation(tmp_path, case):
    source, witness, _ = CASES[case]
    fixture = tmp_path / "consumer.py"
    fixture.write_text(source + "\n" + witness + "print('state-mutation-witnessed')\n")
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("PYTHON", "BCF_", "GIT_", "GITHUB_", "AGENTBUS_"))
                   and key not in {"GH_TOKEN", "VIRTUAL_ENV"}}
    result = subprocess.run([sys.executable, "-I", "-B", str(fixture)], cwd=tmp_path,
                            env=environment, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "state-mutation-witnessed\n"
    assert not result.stderr


@pytest.mark.parametrize("body", ("value = 1\n    return value", "value = 1\n    value = 2\n    return value"))
def test_ordinary_scalar_local_binding_remains_local(tmp_path, body):
    inventory = _inventory(tmp_path, "def query():\n    " + body + "\n")
    assert validate_operation_effects(_operation(), "service.py::query", inventory) == (0, 0)

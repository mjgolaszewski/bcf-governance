"""Unresolved Python callback targets cannot gain authority from a port label."""
from pathlib import Path
import os
import subprocess
import sys

import pytest

from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, validate_operation_effects
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports

CASES = {
    "callback": ("def query(callback):\n    return callback()\n", "query(handler)"),
    "callback-alias": ("def query(callback):\n    selected = callback\n    return selected()\n", "query(handler)"),
    "callback-container": ("def query(callbacks):\n    return callbacks[0]()\n", "query([handler])"),
    "parameter-method": ("def query(value):\n    return value.read()\n", "query(Reader())"),
}
PREFIX = (
    "from pathlib import Path\n"
    "def handler():\n    Path('state').write_text('changed')\n    return 1\n"
    "class Reader:\n    def read(self):\n        return handler()\n"
)


def _inventory(tmp_path, source):
    path = tmp_path / "service.py"
    path.write_text(source)
    return resolve_python_imports(tmp_path, discover_python_source(tmp_path, files=[path], call_contracts_version="1.0"))


def _operation():
    return {"id": "callback-binding.query.v1", "allowed_mutation_ports": [],
            "allowed_authority_ports": [], "non_authoritative_output_effects": []}


@pytest.mark.parametrize("case", tuple(CASES))
@pytest.mark.parametrize("declared", (False, True), ids=("undeclared", "declared-port"))
def test_unknown_callback_target_cannot_be_accepted_or_declared_away(tmp_path, case, declared):
    source, _ = CASES[case]
    inventory = _inventory(tmp_path, PREFIX + source)
    operation = _operation()
    if declared:
        query = next(row for row in inventory["functions"] if row["symbol"] == "service.py::query")
        operation["allowed_mutation_ports"] = [row["called_symbol"] for row in query["calls"]]
    with pytest.raises(SemanticOperationEffectError, match="unresolved effect"):
        validate_operation_effects(operation, "service.py::query", inventory)


@pytest.mark.parametrize("case", tuple(CASES))
def test_fresh_python_consumer_witnesses_unknown_target_write(tmp_path, case):
    source, call = CASES[case]
    fixture = tmp_path / "consumer.py"
    fixture.write_text(PREFIX + source + "\nassert " + call + " == 1\nassert Path('state').read_text() == 'changed'\nprint('unknown-target-write-witnessed')\n")
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("PYTHON", "BCF_", "GIT_", "GITHUB_", "AGENTBUS_"))
                   and key not in {"GH_TOKEN", "VIRTUAL_ENV"}}
    result = subprocess.run([sys.executable, "-I", "-B", str(fixture)], cwd=tmp_path,
                            env=environment, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "unknown-target-write-witnessed\n"
    assert not result.stderr


@pytest.mark.parametrize("body", ("value = 1\n    return value", "return helper()"))
def test_known_source_and_local_binding_remain_valid(tmp_path, body):
    inventory = _inventory(tmp_path, "def helper():\n    return 1\ndef query():\n    " + body + "\n")
    assert validate_operation_effects(_operation(), "service.py::query", inventory) == (0, 0)

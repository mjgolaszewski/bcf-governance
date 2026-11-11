"""Lifetime hooks remain conservative source obligations in both consumers."""
from pathlib import Path
import os
import subprocess
import sys

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError, source_operation_call_population, validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports

HOOKS = {
    "__del__": (
        "class Owner:\n"
        "    def __init__(self):\n        pass\n"
        "    def __del__(self):\n        Path('state').write_text('changed')\n"
    ),
    "__delattr__": (
        "class Owner:\n"
        "    def __init__(self):\n        self.field = 1\n        del self.field\n"
        "    def __delattr__(self, name):\n"
        "        Path('state').write_text('changed')\n"
        "        object.__delattr__(self, name)\n"
    ),
}

def _sources(hook, context):
    declaration = "from pathlib import Path\n" + HOOKS[hook]
    if context in {"local", "inherited"}:
        owner = "Owner"
        if context == "inherited":
            declaration = declaration.replace("class Owner:", "class Base:") + "class Owner(Base):\n    pass\n"
            owner = "Base"
        return {"service.py": declaration + "def query():\n    return Owner()\n"}, "service.py::" + owner
    name = "factory" if context == "lower-import-alias" else "Owner"
    return {
        "owner.py": declaration,
        "service.py": f"from owner import Owner as {name}\ndef query():\n    return {name}()\n",
    }, "owner.py::Owner"

def _inventory(tmp_path, hook, context):
    sources, owner = _sources(hook, context)
    paths = []
    for relative, source in sources.items():
        path = tmp_path / relative
        path.write_text(source)
        paths.append(path)
    return resolve_python_imports(
        tmp_path, discover_python_source(tmp_path, files=paths, call_contracts_version="1.0"),
    ), owner

@pytest.mark.parametrize("hook", tuple(HOOKS))
@pytest.mark.parametrize("context", ("local", "imported", "lower-import-alias", "inherited"))
def test_source_effect_consumer_cannot_accept_lifetime_hook_write(tmp_path, hook, context):
    inventory, _ = _inventory(tmp_path, hook, context)
    operation = {
        "id": "source-lifetime.query.v1", "allowed_mutation_ports": [],
        "allowed_authority_ports": [], "non_authoritative_output_effects": [],
    }
    with pytest.raises(SemanticOperationEffectError, match="(construction.*provenance|undeclared write)"):
        validate_operation_effects(operation, "service.py::query", inventory)

@pytest.mark.parametrize("hook", tuple(HOOKS))
@pytest.mark.parametrize("context", ("local", "imported", "lower-import-alias", "inherited"))
def test_source_population_includes_lifetime_hook_without_execution_credit(tmp_path, hook, context):
    inventory, owner = _inventory(tmp_path, hook, context)
    result = source_operation_call_population("service.py::query", inventory)
    assert owner + "." + hook in result["functions"], "lifetime source body omitted"
    assert result["authority"] is result["execution_qualified"] is False
    query = next(row for row in inventory["functions"] if row["symbol"] == "service.py::query")
    observation = query["calls"][0]["construction_effect_observation"]
    assert observation["authority"] is False
    assert observation["unresolved"], "unknown hook timing/provenance erased"

@pytest.mark.parametrize("hook", tuple(HOOKS))
@pytest.mark.parametrize("context", ("local", "inherited"))
def test_fresh_python_consumer_witnesses_lifetime_hook_write(tmp_path: Path, hook, context):
    # An ordinary CPython process and explicit source-level deletion, no GC probes.
    sources, _ = _sources(hook, context)
    source = sources["service.py"] + (
        "value = query()\ndel value\n"
        "assert Path('state').read_text() == 'changed'\n"
        "print('lifetime-write-witnessed')\n"
    )
    fixture = tmp_path / "consumer.py"
    fixture.write_text(source)
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("PYTHON", "BCF_", "GIT_", "GITHUB_", "AGENTBUS_"))
                   and key not in {"GH_TOKEN", "VIRTUAL_ENV"}}
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(fixture)],
        cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "lifetime-write-witnessed\n"
    assert not result.stderr

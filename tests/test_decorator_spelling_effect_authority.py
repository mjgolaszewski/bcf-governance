"""Decorator spelling alone cannot authorize source-only effect conclusions."""
from pathlib import Path
import os
import subprocess
import sys

import pytest

from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, validate_operation_effects
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports

SPELLINGS = ("staticmethod", "classmethod", "hooks.staticmethod", "hooks.classmethod", "hooks.inner.staticmethod", "hooks.inner.classmethod")


def _source(spelling):
    prefix = (
        "from pathlib import Path\n"
        "from types import SimpleNamespace\n"
        "def misleading(function):\n"
        "    def wrapped(*args, **kwargs):\n"
        "        Path('state').write_text('changed')\n"
        "        return function(*args, **kwargs)\n"
        "    return wrapped\n"
        "staticmethod = misleading\n"
        "classmethod = misleading\n"
        "hooks = SimpleNamespace(staticmethod=misleading, classmethod=misleading,\n"
        "    inner=SimpleNamespace(staticmethod=misleading, classmethod=misleading))\n"
    )
    return prefix + (
        "class Service:\n"
        f"    @{spelling}\n"
        "    def query(self):\n"
        "        return 1\n"
    )


def _inventory(tmp_path, source):
    path = tmp_path / "service.py"
    path.write_text(source)
    return resolve_python_imports(tmp_path, discover_python_source(tmp_path, files=[path]))


def _operation():
    return {"id": "decorator-binding.query.v1", "allowed_mutation_ports": [],
            "allowed_authority_ports": [], "non_authoritative_output_effects": []}


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_decorator_named_like_builtin_retains_unresolved_binding(tmp_path, spelling):
    inventory = _inventory(tmp_path, _source(spelling))
    query = next(row for row in inventory["functions"] if row["symbol"] == "service.py::Service.query")
    assert any(row.get("dispatch_kind") == "decorated_method" for row in query.get("effect_unresolved", [])), "decorator spelling erased unresolved runtime binding"


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_effect_consumer_cannot_accept_shadowed_builtin_decorator(tmp_path, spelling):
    inventory = _inventory(tmp_path, _source(spelling))
    with pytest.raises(SemanticOperationEffectError, match="unresolved effect"):
        validate_operation_effects(_operation(), "service.py::Service.query", inventory)


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_fresh_python_consumer_witnesses_decorator_wrapper_write(tmp_path, spelling):
    fixture = tmp_path / "consumer.py"
    fixture.write_text(_source(spelling) + "\nassert Service().query() == 1\nassert Path('state').read_text() == 'changed'\nprint('decorator-write-witnessed')\n")
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("PYTHON", "BCF_", "GIT_", "GITHUB_", "AGENTBUS_"))
                   and key not in {"GH_TOKEN", "VIRTUAL_ENV"}}
    result = subprocess.run([sys.executable, "-I", "-B", str(fixture)], cwd=tmp_path,
                            env=environment, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "decorator-write-witnessed\n"
    assert not result.stderr


@pytest.mark.parametrize("body", ("return 1", "return self.read()"))
def test_undecorated_same_instance_query_remains_local(tmp_path, body):
    source = "class Service:\n    def query(self):\n        " + body + "\n    def read(self):\n        return 1\n"
    inventory = _inventory(tmp_path, source)
    assert validate_operation_effects(_operation(), "service.py::Service.query", inventory) == (0, 0)

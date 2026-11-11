"""Ordinary isolated consumers distinguish class creation from instance construction."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from bcf_governance.tooling.semantic_operation_effects import source_operation_call_population
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports

CASES = {
  "ordinary": [
    "class Owner:\n    def __init__(self):\n        events.append('init')\n",
    [],
    [
      "init"
    ]
  ],
  "dormant-property": [
    "class Owner:\n    @property\n    def field(self):\n        events.append('property-body')\n",
    [],
    []
  ],
  "dormant-staticmethod": [
    "class Owner:\n    @staticmethod\n    def unused():\n        events.append('static-body')\n",
    [],
    []
  ],
  "shadowed-decorator": [
    "def staticmethod(function):\n    events.append('decorate')\n    def replacement():\n        events.append('replacement')\n    return replacement\nclass Owner:\n    @staticmethod\n    def unused():\n        events.append('original')\n",
    [
      "decorate"
    ],
    []
  ],
  "descriptor": [
    "class Descriptor:\n    def __set_name__(self, owner, name):\n        events.append('set-name')\n    def __set__(self, instance, value):\n        events.append('set')\nclass Owner:\n    field = Descriptor()\n    def __init__(self):\n        self.field = 1\n",
    [
      "set-name"
    ],
    [
      "set"
    ]
  ],
  "metaclass": [
    "class Meta(type):\n    def __new__(meta, name, bases, namespace):\n        events.append('class-new')\n        return super().__new__(meta, name, bases, namespace)\n    def __call__(cls):\n        events.append('class-call')\n        return super().__call__()\nclass Owner(metaclass=Meta):\n    def __init__(self):\n        events.append('init')\n",
    [
      "class-new"
    ],
    [
      "class-call",
      "init"
    ]
  ],
  "inherited": [
    "class Base:\n    def __init_subclass__(cls):\n        events.append('init-subclass')\n    def __init__(self):\n        events.append('base-init')\nclass Owner(Base):\n    pass\n",
    [
      "init-subclass"
    ],
    [
      "base-init"
    ]
  ],
  "plain-post-init": [
    "class Owner:\n    def __post_init__(self):\n        events.append('post-init')\n",
    [],
    []
  ],
  "dataclass-post-init": [
    "from dataclasses import dataclass\n@dataclass\nclass Owner:\n    def __post_init__(self):\n        events.append('post-init')\n",
    [],
    [
      "post-init"
    ]
  ],
  "foreign-new": [
    "class Owner:\n    def __new__(cls):\n        events.append('new')\n        return object()\n    def __init__(self):\n        events.append('init')\n",
    [],
    [
      "new"
    ]
  ],
  "new-and-init": [
    "class Owner:\n    def __new__(cls):\n        events.append('new')\n        return super().__new__(cls)\n    def __init__(self):\n        events.append('init')\n",
    [],
    [
      "new",
      "init"
    ]
  ],
  "static-init": [
    "class Owner:\n    @staticmethod\n    def __init__():\n        events.append('static-init')\n",
    [],
    [
      "static-init"
    ]
  ]
}

def _source(case):
    declaration, creation, construction = CASES[case]
    return "events = []\n" + declaration + "def query():\n    return Owner()\n"

@pytest.mark.parametrize("case", tuple(CASES))
def test_isolated_python_consumer_separates_creation_and_construction(tmp_path: Path, case):
    source = _source(case)
    source += (
        "creation = list(events)\nevents.clear()\n"
        "result = query()\n"
        "import json\nprint(json.dumps({'creation': creation, 'construction': events}))\n"
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
    assert not result.stderr
    _, creation, construction = CASES[case]
    assert json.loads(result.stdout) == {"creation": creation, "construction": construction}

@pytest.mark.parametrize("case", tuple(CASES))
def test_source_population_keeps_initialization_and_runtime_uncertainty(tmp_path: Path, case):
    fixture = tmp_path / "service.py"
    fixture.write_text(_source(case))
    inventory = resolve_python_imports(
        tmp_path, discover_python_source(tmp_path, files=[fixture], call_contracts_version="1.0"),
    )
    observation = source_operation_call_population(
        "service.py::query", inventory, include_initialization=True,
    )
    assert observation["authority"] is False
    assert observation["execution_qualified"] is False
    assert observation["completeness_qualified"] is False
    assert observation["unresolved_calls"] >= 1
    modules = inventory["module_initializers"]
    assert len(modules) == 1
    module = modules[0]
    assert module["authority"] is module["execution_qualified"] is False
    assert module["completeness_qualified"] is False
    assert any(site["kind"] == "class_construction" for site in module["sites"])
    assert any(row["reason"] == "metaclass_and_implicit_class_hooks" for row in module["unresolved"])
    if case in {"dormant-property", "dormant-staticmethod", "shadowed-decorator", "dataclass-post-init", "static-init"}:
        assert any(site["kind"] == "decorator_application" for site in module["sites"])
        assert any(row["reason"] == "implicit_decorator_execution" for row in module["unresolved"])
    query = next(row for row in inventory["functions"] if row["symbol"] == "service.py::query")
    constructors = query["constructors"]
    assert len(constructors) == 1
    fact = constructors[0]["construction_effect_observation"]
    assert fact["authority"] is False
    assert fact["qualification"] == "SOURCE_OBLIGATIONS_ONLY_RUNTIME_PROVENANCE_REQUIRED"

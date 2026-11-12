"""Causal consumer contracts: observed effects cannot qualify as pure reads."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source,
    resolve_python_imports,
)

OPERATION = {"id": "consumer.read.v1", "authoritative_read": True, "allowed_mutation_ports": [], "allowed_authority_ports": [], "non_authoritative_output_effects": []}


def inventory(tmp_path: Path, source: str):
    path = tmp_path / "consumer.py"
    path.write_text(textwrap.dedent(source))
    return path, resolve_python_imports(tmp_path, discover_python_source(tmp_path, [path]), (".",))


def witness(path: Path, interpreter: str = sys.executable):
    script = "import runpy,json; n=runpy.run_path(" + repr(str(path)) + "); print(json.dumps([n['read'](),n['read']()]))"
    result = subprocess.run([interpreter, "-I", "-B", "-c", script], cwd=path.parent, env={"PATH": os.defpath, "LANG": "C.UTF-8"}, check=True, capture_output=True, text=True, timeout=10)
    return json.loads(result.stdout)


@pytest.mark.parametrize("source,expected", [
    ("COUNTER=0\ndef read():\n global COUNTER\n COUNTER += 1\n return COUNTER\n", [1, 2]),
    ("STATE=[1,2]\ndef read():\n STATE.clear()\n return len(STATE)\n", [0, 0]),
    ("from dataclasses import dataclass\nCOUNTER=[]\n@dataclass\nclass Record:\n value:int=7\n def __post_init__(self):\n  COUNTER.append(self.value)\ndef read():\n Record()\n return len(COUNTER)\n", [1, 2]),
    ("COUNTER=[]\nclass Record:\n @property\n def value(self):\n  COUNTER.append(7)\n  return len(COUNTER)\ndef read():\n return Record().value\n", [1, 2]),
    ("COUNTER=[]\nclass Error(Exception):\n def __str__(self):\n  COUNTER.append(7)\n  return str(len(COUNTER))\ndef read():\n return str(Error())\n", ["1", "2"]),
])
def test_observed_retained_or_implicit_writes_are_not_read_only(tmp_path, source, expected):
    path, facts = inventory(tmp_path, source)
    assert witness(path) == expected
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


@pytest.mark.parametrize("kind", ["list", "set", "dict"])
@pytest.mark.parametrize("hook", ["__bool__", "__len__"])
def test_comprehension_truth_callback_writes_are_not_read_only(tmp_path, kind, hook):
    expression = {"list": "[x for x in [1] if Guard()]", "set": "{x for x in [1] if Guard()}", "dict": "{x:x for x in [1] if Guard()}"}[kind]
    source = f"COUNTER=[]\nclass Guard:\n def {hook}(self):\n  COUNTER.append(7)\n  return {repr(True) if hook == '__bool__' else '1'}\ndef read():\n result={expression}\n return len(COUNTER)\n"
    path, facts = inventory(tmp_path, source)
    assert witness(path) == [1, 2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


def test_dataclass_factory_is_qualified_without_removing_callback(tmp_path):
    path, facts = inventory(tmp_path, """
        from dataclasses import dataclass, field
        def fixed_source():
            return 7
        @dataclass(slots=True)
        class Record:
            value: int = field(default_factory=fixed_source)
            @classmethod
            def new(cls):
                return cls()
        def read():
            return Record.new().value
    """)
    assert witness(path) == [7, 7]
    assert validate_operation_effects(OPERATION, "consumer.py::read", facts) == (0, 0)


def test_fresh_source_record_return_is_not_a_receiver_alias(tmp_path):
    path, facts = inventory(tmp_path, """
        from dataclasses import dataclass
        @dataclass
        class Record:
            value: int = 7
            def to_payload(self):
                return self.value
        class Handler:
            def load(self):
                return Record()
            def read(self):
                row = self.load()
                return row.to_payload()
        def read():
            return Handler().read()
    """)
    assert witness(path) == [7, 7]
    assert validate_operation_effects(OPERATION, "consumer.py::Handler.read", facts) == (0, 0)


def test_factory_callbacks_are_actually_invoked_for_each_omitted_field(tmp_path):
    path, _ = inventory(tmp_path, """
        from dataclasses import dataclass, field
        EVENTS = []
        def factory():
            EVENTS.append(7)
            return 7
        @dataclass
        class Record:
            first: int = field(default_factory=factory)
            second: int = field(default_factory=factory)
        def read():
            Record()
            return len(EVENTS)
    """)
    assert witness(path) == [2, 4]


def test_qualified_factory_body_is_still_checked_for_retained_writes(tmp_path):
    path, facts = inventory(tmp_path, """
        from dataclasses import dataclass, field
        EVENTS = []
        def factory():
            EVENTS.append(7)
            return 7
        @dataclass
        class Record:
            value: int = field(default_factory=factory)
            @classmethod
            def new(cls):
                return cls()
        def read():
            Record.new()
            return len(EVENTS)
    """)
    assert witness(path) == [1, 2]
    factory = next(row for row in facts["functions"] if row["symbol"] == "consumer.py::Record.new")
    assert any(call["called_symbol"] == "consumer.py::factory" and call.get("implicit_callback") for call in factory["calls"])
    with pytest.raises(SemanticOperationEffectError, match="write effects"):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


@pytest.mark.parametrize("producer", ["return self", "return self.record", "return Record() if self.flag else self.record"])
def test_real_or_mixed_receiver_aliases_remain_unqualified(tmp_path, producer):
    _, facts = inventory(tmp_path, f"""
        from dataclasses import dataclass
        @dataclass
        class Record:
            value: int = 7
            def to_payload(self):
                return self.value
        class Handler:
            def load(self):
                {producer}
            def read(self):
                row = self.load()
                return row.to_payload()
    """)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::Handler.read", facts)


@pytest.mark.parametrize("source", [
    "STATE=[1]\ndef read():\n alias=STATE\n alias.clear()\n return len(STATE)\n",
    "STATE=[1]\ndef read():\n alias=[]\n alias=STATE\n alias.clear()\n return len(STATE)\n",
    "STATE=[1]\ndef read():\n wrapper=[STATE]\n wrapper[0].clear()\n return len(STATE)\n",
])
def test_borrowed_mutation_cannot_be_laundered_through_a_local(tmp_path, source):
    path, facts = inventory(tmp_path, source)
    assert witness(path) == [0, 0]
    with pytest.raises(SemanticOperationEffectError, match="write effects"):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)


@pytest.mark.parametrize("hook", ["validator", "serializer"])
def test_pydantic_callbacks_cannot_hide_writes(tmp_path, hook):
    interpreter = os.environ.get("BCF_PYDANTIC_TEST_PYTHON")
    if interpreter is None:
        pytest.skip("explicit immutable Pydantic witness interpreter required")
    if hook == "validator":
        body = " @model_validator(mode='after')\n def validate_value(self):\n  COUNTER.append(self.value)\n  return self\n"
    else:
        body = " @model_serializer\n def serialize_value(self):\n  COUNTER.append(self.value)\n  return {'value':self.value}\n"
    source = "from pydantic import BaseModel,model_validator,model_serializer\nCOUNTER=[]\nclass Record(BaseModel):\n value:int\n" + body + "def read():\n row=Record(value=7)\n row.model_dump()\n return len(COUNTER)\n"
    path, facts = inventory(tmp_path, source)
    assert witness(path, interpreter) == [1, 2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts)

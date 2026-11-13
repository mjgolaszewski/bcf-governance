"""Dependency-bound model selection never authorizes model callback effects."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def observe(root: Path, source: str, *, fake: bool = False):
    interpreter = os.environ.get('BCF_PYDANTIC_TEST_PYTHON', sys.executable)
    (root / 'pyproject.toml').write_text('[project]\nname="binding-fixture"\nversion="1"\nrequires-python=">=3.11"\ndependencies=["pydantic==2.13.4"]\n')
    (root / 'models.py').write_text(textwrap.dedent(source))
    if fake:
        (root / 'pydantic.py').write_text('class BaseModel:\n pass\nraise RuntimeError("must not import project source")\n')
    code = '''import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source,resolve_python_imports
from bcf_governance.tooling.semantic_operation_effects import validate_operation_effects,SemanticOperationEffectError
root=Path(sys.argv[2]);facts=resolve_python_imports(root,discover_python_source(root,sorted(root.glob('*.py'))),('.',))
operation={'id':'read.v1','authoritative_read':True,'allowed_mutation_ports':[],'allowed_authority_ports':[],'non_authoritative_output_effects':[]}
try: validate_operation_effects(operation,'models.py::read',facts)
except SemanticOperationEffectError as error: verdict=str(error)
else: verdict='ACCEPTED'
print(json.dumps({'classes':facts['classes'],'constructors':facts['constructors'],'unresolved':facts['unresolved'],'effect_verdict':verdict}))
'''
    completed = subprocess.run([interpreter, '-I', '-B', '-c', code, str(ROOT), str(root)],
        env={'PATH': os.defpath, 'LANG': 'C.UTF-8'}, capture_output=True, text=True, timeout=20, check=True)
    return json.loads(completed.stdout)


def test_model_and_inherited_envelope_bind_without_claiming_effects(tmp_path):
    result = observe(tmp_path, '''
        from pydantic import BaseModel,ConfigDict,Field
        class Envelope(BaseModel):
            values: list[int] = Field(default_factory=list)
        class Record(Envelope):
            model_config = ConfigDict(extra='forbid',strict=True)
            value: int
            @classmethod
            def new(cls):
                return cls(value=7)
        def read():
            return Record.new()
    ''')
    record = next(row for row in result['classes'] if row['symbol']=='models.py::Record')
    assert record['library_model_binding']['execution_qualified'] is False
    assert record['library_model_binding']['effects_qualified'] is False
    assert any(row['caller']=='models.py::Record.new' and row['constructed_symbol']=='models.py::Record' for row in result['constructors'])
    assert not result['unresolved']
    assert result['effect_verdict'] != 'ACCEPTED'


@pytest.mark.parametrize('variant', ['schema_hook','custom_meta','rebound','fake_package'])
def test_opaque_model_selection_stays_unresolved(tmp_path, variant):
    extra = "\n    @classmethod\n    def __get_pydantic_core_schema__(cls,*args):\n        raise RuntimeError('not executed by discovery')\n" if variant=='schema_hook' else ''
    base = 'BaseModel,metaclass=type' if variant=='custom_meta' else 'BaseModel'
    source = 'from pydantic import BaseModel\nclass Record('+base+'):\n    value:int\n    @classmethod\n    def new(cls):\n        return cls(value=7)\n'+extra+'\ndef read():\n    return Record.new()\n'
    if variant=='rebound':
        source += '\nRecord.new = object()\n'
    result = observe(tmp_path, source, fake=variant=='fake_package')
    assert any(row['kind']=='unresolved_class_constructor' for row in result['unresolved'])
    assert result['effect_verdict'] != 'ACCEPTED'


def test_model_validator_retains_a_callback_obligation(tmp_path):
    result = observe(tmp_path, '''
        from pydantic import BaseModel,model_validator
        EVENTS=[]
        class Record(BaseModel):
            value:int
            @model_validator(mode='after')
            def observe_value(self):
                EVENTS.append(self.value)
                return self
            @classmethod
            def new(cls):
                return cls(value=7)
        def read():
            return Record.new()
    ''')
    assert not result['unresolved']
    assert result['effect_verdict'] != 'ACCEPTED'

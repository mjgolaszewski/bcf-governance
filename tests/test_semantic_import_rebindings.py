"""Known Python bindings cannot masquerade as native path constructors."""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap

import pytest

from bcf_governance.tooling.semantic_ownership_scan import evaluate_discovery
from tests.test_consumer_callback_contracts import inventory
from tests.test_semantic_generated_copies import BASE, registry

CASES = {'genuine_path': 'def read(record: Record):\n return Path(record.value).suffix.lower()==".json"\n', 'local_def': 'def read(record: Record):\n def Path(value):return Fake(value)\n return Path(record.value).suffix.lower()==".json"\n', 'local_class': 'def read(record: Record):\n class Path:\n  def __init__(self,value):self.suffix=value\n return Path(record.value).suffix.lower()==".json"\n', 'local_match': 'def read(record: Record):\n match Fake:\n  case Path:pass\n return Path(record.value).suffix.lower()==".json"\n', 'module_match': 'match Fake:\n case Path:pass\ndef read(record: Record):\n return Path(record.value).suffix.lower()==".json"\n', 'local_except': 'def read(record: Record):\n try:raise FactoryError()\n except FactoryError as Path:\n  return Path(record.value).suffix.lower()==".json"\n', 'module_except': 'def read(record: Record):\n return Path(record.value).suffix.lower()==".json"\ntry:raise FactoryError()\nexcept FactoryError as Path:\n OBSERVED=[read(owner(".JSON")),read(owner("a.JSON"))]\n', 'function_header': 'def unused(value=(Path:=Fake)):pass\ndef read(record: Record):\n return Path(record.value).suffix.lower()==".json"\n', 'class_header': 'class Unused((Path:=Fake)):pass\ndef read(record: Record):\n return Path(record.value).suffix.lower()==".json"\n', 'module_member': 'import pathlib\npathlib.Path=Fake\ndef read(record: Record):\n return pathlib.Path(record.value).suffix.lower()==".json"\n', 'local_star': 'def read(record: Record):\n match [Fake]:\n  case [*Path]:pass\n return Path(record.value).suffix.lower()==".json"\n', 'module_star': 'match [Fake]:\n case [*Path]:pass\ndef read(record: Record):\n return Path(record.value).suffix.lower()==".json"\n', 'local_mapping_rest': 'def read(record: Record):\n match {"kind":Fake}:\n  case {**Path}:pass\n return Path(record.value).suffix.lower()==".json"\n', 'module_mapping_rest': 'match {"kind":Fake}:\n case {**Path}:pass\ndef read(record: Record):\n return Path(record.value).suffix.lower()==".json"\n'}

@pytest.mark.parametrize('case', list(CASES))
def test_all_known_rebinding_forms_keep_ordinary_accounting(tmp_path, case):
    base=textwrap.dedent(BASE)+'\nfrom pathlib import Path\nclass Fake:\n def __init__(self,value):self.suffix=value\nclass FactoryError(Exception):\n def __call__(self,value):return Fake(value)\n'
    path,facts=inventory(tmp_path,base+CASES[case])
    code='import runpy,json; n=runpy.run_path('+repr(str(path))+'); print(json.dumps(n["OBSERVED"] if "OBSERVED" in n else [n["read"](n["owner"](".JSON")),n["read"](n["owner"]("a.JSON"))]))'
    result=subprocess.run([sys.executable,'-I','-B','-c',code],capture_output=True,text=True,timeout=10)
    noncallable=case.endswith(('star','mapping_rest'))
    if noncallable:
        assert result.returncode!=0 and 'TypeError' in result.stderr
    else:
        assert result.returncode==0,result.stderr
        assert json.loads(result.stdout)==([False,True] if case=='genuine_path' else [True,False])
    failures=[row for row in evaluate_discovery(facts,registry())['violations']
              if row['kind']=='downstream_normalization' and row['symbol']=='consumer.py::read']
    assert bool(failures) is (case!='genuine_path')

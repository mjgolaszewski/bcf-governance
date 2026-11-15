"""Adversarial witnesses for deferred callback proof state and protocol edges."""
import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from tests.test_consumer_callback_contracts import OPERATION, inventory, witness

CASES={
"optional-rebind-loop":"EVENTS=[]\ndef invoke(callback=None):\n def write(): EVENTS.append(7)\n for item in [1,2]:\n  if callback is None:\n   callback=write\n  else:\n   callback()\ndef read():\n invoke()\n return len(EVENTS)\n",
"transitive-index":"EVENTS=[]\nclass Probe:\n def __getitem__(self,key):\n  EVENTS.append(7)\n  return 7\nPROBE=Probe()\ndef project(value): return value['key']\ndef invoke(callback): return callback()\ndef read():\n def callback(): return project(PROBE)\n invoke(callback)\n return len(EVENTS)\n",
"fallback-await":"import asyncio\nEVENTS=[]\nFLAG=True\nclass Probe:\n def __await__(self):\n  EVENTS.append(7)\n  if False: yield\n  return 7\nPROBE=Probe()\nasync def invoke(callback):\n if FLAG: pass\n return await callback()\ndef read():\n def callback(): return PROBE\n asyncio.run(invoke(callback))\n return len(EVENTS)\n",
"native-evidence-loop":"EVENTS=[]\nclass Probe:\n def __len__(self):\n  EVENTS.append(7)\n  return 0\nPROBE=Probe()\ndef invoke(callback): return callback()\ndef read():\n def callback():\n  value=[]\n  for item in [1,2]:\n   len(value)\n   value=PROBE\n invoke(callback)\n return len(EVENTS)\n"
}
CASES["transitive-classmethod"] = "EVENTS=[]\nclass Probe:\n def __getitem__(self,key):\n  EVENTS.append(7)\n  return 7\nPROBE=Probe()\nclass Projector:\n @classmethod\n def project(cls,value): return value['key']\ndef invoke(callback): return callback()\ndef read():\n def callback(): return Projector.project(PROBE)\n invoke(callback)\n return len(EVENTS)\n"

@pytest.mark.parametrize("case",list(CASES))
def test_callback_cannot_hide_runtime_mutation(tmp_path,case):
    path,facts=inventory(tmp_path,CASES[case])
    assert witness(path)==[1,2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,"consumer.py::read",facts,experimental_protocols=False)


def test_bare_source_coroutine_callback_retains_positive_contract(tmp_path):
    source="import asyncio\nasync def invoke(callback):\n return await callback()\ndef read():\n async def callback(): return 7\n return asyncio.run(invoke(callback))\n"
    path,facts=inventory(tmp_path,source)
    assert witness(path)==[7,7]
    assert validate_operation_effects(OPERATION,"consumer.py::read",facts,experimental_protocols=False)==(0,0)

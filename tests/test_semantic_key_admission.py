"""Unchanged actual body, renamed roles, and causal guard/writer counterexamples."""
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from bcf_governance.tooling.semantic_python_value_origins import value_origins
from tests.test_consumer_callback_contracts import OPERATION, inventory

SOURCE = (Path(__file__).parent / "fixtures/semantic_private_key_ledger.txt").read_text()
ENTRY = "\ndef read(value):\n ledger=make_batch_export_identity_ledger(max_identities=7)\n ledger.observe_account(value)\n return len(ledger._accounts)\n"


def test_unchanged_actual_guarded_private_set_operation_qualifies(tmp_path):
    _, facts = inventory(tmp_path, SOURCE + ENTRY)
    assert validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False) == (0, 0)


def test_names_annotations_and_error_spelling_are_not_the_proof(tmp_path):
    source = SOURCE + ENTRY
    for old, new in [("BatchExportIdentityLedger", "RenamedLedger"), ("make_batch_export_identity_ledger", "allocate"), ("require_export_identity_capacity", "validate_budget"), ("_observe", "_accept"), ("identity_type", "kind"), ("identity", "candidate"), ("transaction", "second_kind"), ("_accounts", "_first"), ("_failed", "_stopped")]:
        source = source.replace(old, new)
    _, facts = inventory(tmp_path, source)
    assert validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False) == (0, 0)


@pytest.mark.parametrize("before,after", [("type(identity) is int", "isinstance(identity, int)"), ("type(identity) is str", "isinstance(identity, str)"), ("if not valid:", "if False:"), ("valid = False", "valid = True"), ("identity.encode(\"utf-8\")", "identity.encode(encoding)"), ("observed.add(identity)", "observed.add(external_key)"), ("if identity in observed:", "if external(identity):"), ("assert isinstance(identity, str | int)", "assert isinstance(identity, other_class)"), ("type(identity) is int", "type(identity) is bool"), ("observed.add(identity)", "observed.update([identity])")])
def test_missing_altered_or_bypassed_admission_never_qualifies(tmp_path, before, after):
    assert before in SOURCE
    _, facts = inventory(tmp_path, SOURCE.replace(before, after) + ENTRY)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False)


@pytest.mark.parametrize("extra", [" def inject(self, key): self._accounts.add(key)\n", " def expose(self): return self._accounts\n", " def overwrite(self): self._accounts=set()\n", " def captured(self):\n  alias=self\n  return external(alias)\n"])
def test_all_writer_and_alias_invariant_cannot_ignore_an_unproved_member(tmp_path, extra):
    source = SOURCE.replace("\ndef make_batch_export_identity_ledger", "\n" + textwrap.indent(textwrap.dedent(extra), "    ") + "\ndef make_batch_export_identity_ledger")
    _, facts = inventory(tmp_path, source + ENTRY)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False)


@pytest.mark.parametrize("change", ["early_return", "caught", "rebind", "shadow"])
def test_constructor_normal_return_refinement_requires_actual_guard(tmp_path, change):
    source = SOURCE
    if change == "early_return":
        source = source.replace('    if type(max_identities)', '    return\n    if type(max_identities)', 1)
    elif change == "caught":
        source = source.replace('        require_export_identity_capacity(max_identities)', '        try:\n            require_export_identity_capacity(max_identities)\n        except ValueError:\n            pass')
    elif change == "rebind":
        source = source.replace('        self._capacity = max_identities', '        max_identities=external()\n        self._capacity = max_identities')
    else:
        source += '\nrequire_export_identity_capacity=external\n'
    _, facts = inventory(tmp_path, source + ENTRY)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False)


def test_runtime_rejects_bool_subclasses_and_hostile_protocols_without_invoking_them(tmp_path):
    hostile = """
EVENTS=[]
class Probe:
 @property
 def __class__(self): EVENTS.append('class'); return int
 def __hash__(self): EVENTS.append('hash'); return 7
 def __eq__(self,other): EVENTS.append('eq'); return False
 def __str__(self): EVENTS.append('str'); return '7'
 def __index__(self): EVENTS.append('index'); return 7
class IntProbe(int):
 def __hash__(self): EVENTS.append('subclass_hash'); return 7
class StrProbe(str):
 def encode(self,*args): EVENTS.append('encode'); return b'x'
"""
    path, facts = inventory(tmp_path, SOURCE + ENTRY + hostile)
    script = "import runpy,json;n=runpy.run_path(" + repr(str(path)) + ");values=[True,n['Probe'](),n['IntProbe'](7),n['StrProbe']('x')];out=[]\nfor value in values:\n try: n['read'](value);out.append('accepted')\n except ValueError: out.append('rejected')\nprint(json.dumps([out,n['EVENTS']]))"
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script], check=True, capture_output=True, text=True, timeout=10)
    assert json.loads(result.stdout) == [["rejected"] * 4, []]
    assert validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False) == (0, 0)


def test_borrowed_or_lost_owner_frame_never_gets_key_proof(tmp_path):
    _, facts = inventory(tmp_path, SOURCE + ENTRY)
    functions = {row["symbol"]: row for row in facts["functions"]}
    result = value_origins("consumer.py::BatchExportIdentityLedger._observe", functions, (("self", "unknown"), ("identity", "scalar"), ("transaction", "scalar"), ("$source_callable_proof", "true")))
    assert result.get("source_control_unknown") or result.get("retained")


def test_missing_rejection_causes_real_subclass_hash_effects_and_static_failure(tmp_path):
    hostile = "\nEVENTS=[]\nclass Probe(int):\n def __hash__(self): EVENTS.append(7); return 7\n"
    source = SOURCE.replace("if not valid:", "if False:") + ENTRY + hostile
    path, facts = inventory(tmp_path, source)
    script = "import runpy,json;n=runpy.run_path(" + repr(str(path)) + ");v=n['Probe'](7);n['read'](v);a=len(n['EVENTS']);n['read'](v);print(json.dumps([a,len(n['EVENTS'])]))"
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script], check=True, capture_output=True, text=True, timeout=10)
    assert json.loads(result.stdout) == [2, 4]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False)

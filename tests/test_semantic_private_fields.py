"""Private scalar writes require old/replacement proof; set identity is not key purity."""
import json

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from bcf_governance.tooling.semantic_python_value_origins import value_origins
from tests.test_consumer_callback_contracts import OPERATION, inventory
from tests.test_semantic_instance_frames import SOURCE


def source_for(body):
    return SOURCE.replace("return ledger.require_nonempty()", "return ledger.observe_account(7)").replace("self._failed=True", body)


def test_actual_failed_bool_write_is_private_only_under_qualified_owner(tmp_path):
    _, facts = inventory(tmp_path, source_for("self._failed=True"))
    assert validate_operation_effects(OPERATION, "consumer.py::BuildSavedBatchExport.execute", facts, experimental_protocols=False) == (0, 0)


@pytest.mark.parametrize("old,new", [("max_identities", "True"), ("False", "external()"), ("False", "identity"), ("False", "type(identity)")])
def test_unknown_old_or_replacement_never_gets_scalar_write_proof(tmp_path, old, new):
    source = source_for("self._failed=" + new).replace("self._failed=False", "self._failed=" + old)
    if new == "identity":
        source = source.replace("ledger.observe_account(7)", "ledger.observe_account(external_value)")
    _, facts = inventory(tmp_path, source)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::BuildSavedBatchExport.execute", facts, experimental_protocols=False)


@pytest.mark.parametrize("body", ["self._accounts.add(identity)", "return identity in self._accounts", "self._accounts.clear()", "self._accounts.pop()", "self._accounts=set()", "del self._accounts"])
def test_set_key_mutation_replacement_and_deletion_stay_unqualified(tmp_path, body):
    _, facts = inventory(tmp_path, source_for(body))
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::BuildSavedBatchExport.execute", facts, experimental_protocols=False)


@pytest.mark.parametrize("body", ["external(self)", "alias=self\n  external(alias)", "return self", "return self._accounts", "external(self._accounts)", "holder.value=self._accounts", "box=[self._accounts]", "def captured(): return self._accounts\n  external(captured)"])
def test_borrowed_or_escaped_owner_and_field_aliases_lose_ownership(tmp_path, body):
    source = source_for(body + "\n  self._failed=True")
    _, facts = inventory(tmp_path, source)
    functions = {row["symbol"]: row for row in facts["functions"]}
    factory = value_origins("consumer.py::make_batch_export_identity_ledger", functions, (("max_identities", "scalar"),))
    origin = factory["return"]
    result = value_origins("consumer.py::BatchExportIdentityLedger.observe_account", functions, (("self", origin), ("identity", "unknown"), ("$source_callable_proof", "true")))
    assert result.get("degraded") or result.get("retained") or not result.get("writes")


def test_mutated_set_is_not_reset_to_initializer_state_across_calls(tmp_path):
    source = source_for("self._accounts.add(identity)")
    _, facts = inventory(tmp_path, source)
    functions = {row["symbol"]: row for row in facts["functions"]}
    origin = value_origins("consumer.py::make_batch_export_identity_ledger", functions, (("max_identities", "scalar"),))["return"]
    assert json.loads(origin.removeprefix("source-instance:"))["private_fields"]["_accounts"] == "native-set"
    import ast

    from bcf_governance.tooling.semantic_python_instance_control import instance_control_contexts
    row = functions["consumer.py::BatchExportIdentityLedger.observe_account"]
    tree = ast.parse(row["python_value_source"]).body[0]
    positions = {id(node): point for node, point in zip(ast.walk(tree), row["python_value_sites"], strict=False)}
    result = instance_control_contexts(row, tree, functions, (("self", origin), ("identity", "unknown")), positions)
    assert next(iter(result["instance_owner_states"].values()))["_accounts"] == "unknown"


def test_returned_instance_alias_cannot_restore_private_frame(tmp_path):
    source = SOURCE.replace(" def require_nonempty(self): return 7", " def return_self(self): return self\n def require_nonempty(self): return 7").replace("  return self._process_source(None,None,None,None,ledger)", "  alias=ledger.return_self()\n  return alias.observe_account(7)")
    _, facts = inventory(tmp_path, source)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::BuildSavedBatchExport.execute", facts, experimental_protocols=False)


def test_unknown_old_field_finalizer_is_real_and_not_authorized(tmp_path):
    import subprocess
    import sys
    source = "EVENTS=[]\nclass Probe:\n def __del__(self): EVENTS.append(7)\nclass Ledger:\n def __init__(self, old): self.flag=old\n def flip(self): self.flag=True\ndef read():\n ledger=Ledger(Probe())\n ledger.flip()\n return len(EVENTS)\n"
    path, facts = inventory(tmp_path, source)
    result = subprocess.run([sys.executable, "-I", "-B", "-c", "import runpy,json;n=runpy.run_path(" + repr(str(path)) + ");print(json.dumps([n['read'](),n['read']()]))"], check=True, capture_output=True, text=True, timeout=10)
    assert json.loads(result.stdout) == [1, 2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False)


@pytest.mark.parametrize("body", ["if identity:\n   self._failed=external()\n  self._failed=True", "for item in identity:\n   self._failed=True\n   self._failed=external()"])
def test_branch_and_later_iteration_cannot_restore_scalar_ownership(tmp_path, body):
    _, facts = inventory(tmp_path, source_for(body))
    functions = {row["symbol"]: row for row in facts["functions"]}
    origin = value_origins("consumer.py::make_batch_export_identity_ledger", functions, (("max_identities", "scalar"),))["return"]
    result = value_origins("consumer.py::BatchExportIdentityLedger.observe_account", functions, (("self", origin), ("identity", "unknown"), ("$source_callable_proof", "true")))
    assert not result["writes"]


def test_conditional_initialization_is_not_a_scalar_field_frame(tmp_path):
    source = source_for("self._failed=True").replace("  self._failed=False", "  if max_identities:\n   self._failed=False")
    _, facts = inventory(tmp_path, source)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::BuildSavedBatchExport.execute", facts, experimental_protocols=False)


def test_chained_set_initialization_does_not_invent_distinct_private_sets(tmp_path):
    source = SOURCE.replace("  self._accounts=set()\n  self._transactions=set()", "  self._accounts=self._transactions=set()")
    _, facts = inventory(tmp_path, source)
    functions = {row["symbol"]: row for row in facts["functions"]}
    origin = value_origins("consumer.py::make_batch_export_identity_ledger", functions, (("max_identities", "scalar"),))["return"]
    fields = json.loads(origin.removeprefix("source-instance:"))["private_fields"]
    assert fields.get("_accounts", "unknown") == fields.get("_transactions", "unknown") == "unknown"


def test_borrowed_receiver_write_is_required_without_private_frame(tmp_path):
    _, facts = inventory(tmp_path, source_for("self._failed=True"))
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::BatchExportIdentityLedger.observe_account", facts, experimental_protocols=False)

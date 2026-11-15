"""Source factory identity and method argument binding never grant heap ownership."""
import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from tests.test_consumer_callback_contracts import OPERATION, inventory

SOURCE = """
def require_export_identity_capacity(max_identities):
 if type(max_identities) is not int or not 1 <= max_identities <= 1000000:
  raise ValueError('capacity')
class BatchExportIdentityLedger:
 def __init__(self, max_identities):
  require_export_identity_capacity(max_identities)
  self._capacity=max_identities
  self._accounts=set()
  self._transactions=set()
  self._account_type=None
  self._transaction_type=None
  self._failed=False
 def require_nonempty(self): return 7
 def observe_account(self, identity):
  self._failed=True
 def observe_transaction(self, identity):
  self._transactions.add(identity)
def make_batch_export_identity_ledger(*, max_identities):
 return BatchExportIdentityLedger(max_identities)
class BuildSavedBatchExport:
 def _process_source(self, source, output, entry, selection, ledger):
  return ledger.require_nonempty()
 def execute(self):
  ledger=make_batch_export_identity_ledger(max_identities=7)
  return self._process_source(None,None,None,None,ledger)
"""


def test_real_factory_and_process_source_argument_positions(tmp_path):
    _, facts = inventory(tmp_path, SOURCE)
    assert validate_operation_effects(OPERATION, "consumer.py::BuildSavedBatchExport.execute", facts, experimental_protocols=False) == (0, 0)


@pytest.mark.parametrize("method", ["observe_account", "observe_transaction"])
def test_factory_identity_never_proves_private_mutation_ownership(tmp_path, method):
    source = SOURCE.replace("return ledger.require_nonempty()", "return ledger." + method + "(7)")
    if method == "observe_account":
        source = source.replace("self._failed=False", "self._failed=external_value")
    _, facts = inventory(tmp_path, source)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::BuildSavedBatchExport.execute", facts, experimental_protocols=False)


@pytest.mark.parametrize("change", ["borrowed", "retained", "rebound", "new", "metaclass", "hierarchy", "getattr"])
def test_unproven_or_escaped_factory_receiver_stays_unknown(tmp_path, change):
    source = SOURCE
    if change == "borrowed":
        source = source.replace("def execute(self):", "def execute(self, ledger):").replace("  ledger=make_batch_export_identity_ledger(max_identities=7)\n", "")
    elif change == "retained":
        source = "KEPT=[]\ndef retain(value): KEPT.append(value)\n" + source.replace("  return self._process_source", "  retain(ledger)\n  return self._process_source")
    elif change == "rebound":
        source = source.replace("  return self._process_source", "  ledger.require_nonempty=external\n  return self._process_source")
    elif change == "new":
        source = source.replace("class BatchExportIdentityLedger:", "class BatchExportIdentityLedger:\n def __new__(cls, *args): return external()")
    elif change == "metaclass":
        source = "class Meta(type): pass\n" + source.replace("class BatchExportIdentityLedger:", "class BatchExportIdentityLedger(metaclass=Meta):")
    elif change == "hierarchy":
        source += "\nclass Hostile(BatchExportIdentityLedger):\n def require_nonempty(self): return external()\n"
    else:
        source = source.replace("class BatchExportIdentityLedger:", "class BatchExportIdentityLedger:\n def __getattr__(self, name): return external()")
    _, facts = inventory(tmp_path, source)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::BuildSavedBatchExport.execute", facts, experimental_protocols=False)


@pytest.mark.parametrize("change", ["helper_escape", "return_escape", "missing_proof", "unknown_factory", "argument_offset"])
def test_identity_requires_constructor_and_nonescaping_argument_proof(tmp_path, change):
    source = SOURCE
    if change == "helper_escape":
        source = "KEPT=[]\ndef helper(value): KEPT.append(value)\n" + source.replace("  return self._process_source", "  helper(ledger)\n  return self._process_source")
    elif change == "return_escape":
        source = "KEPT=[]\ndef expose(value):\n KEPT.append(value)\n return value\n" + source.replace("  return self._process_source", "  ledger=expose(ledger)\n  return self._process_source")
    elif change == "unknown_factory":
        source = source.replace(" return BatchExportIdentityLedger(max_identities)", " return external(max_identities)")
    elif change == "argument_offset":
        source = source.replace("self._process_source(None,None,None,None,ledger)", "self._process_source(ledger,None,None,None,None)")
    _, facts = inventory(tmp_path, source)
    if change == "missing_proof":
        for row in facts["functions"]:
            for call in row.get("calls", []):
                call.pop("source_constructor_frame", None)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::BuildSavedBatchExport.execute", facts, experimental_protocols=False)


def test_source_instance_body_keeps_omitted_port_rejection(tmp_path):
    source = SOURCE.replace("return ledger.require_nonempty()", "return ledger.record()").replace(" def require_nonempty(self): return 7", " def record(self): return sink.commit(7)\n def require_nonempty(self): return 7")
    _, facts = inventory(tmp_path, source)
    declared = {**OPERATION, "authoritative_read": False, "allowed_mutation_ports": ["consumer.py::sink.commit"]}
    assert validate_operation_effects(declared, "consumer.py::BuildSavedBatchExport.execute", facts, experimental_protocols=False) == (1, 0)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::BuildSavedBatchExport.execute", facts, experimental_protocols=False)


def test_local_alias_cannot_hide_instance_method_rebind(tmp_path):
    source = SOURCE.replace("  return self._process_source", "  alias=ledger\n  alias.require_nonempty=external\n  return self._process_source")
    _, facts = inventory(tmp_path, source)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::BuildSavedBatchExport.execute", facts, experimental_protocols=False)

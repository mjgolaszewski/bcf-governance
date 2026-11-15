"""Context/loop identity facts remain conditional on required execution proof."""
import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from bcf_governance.tooling.semantic_python_value_origins import value_origins
from tests.test_consumer_callback_contracts import OPERATION, inventory
from tests.test_semantic_instance_frames import SOURCE

CONTROL = SOURCE[:SOURCE.index("class BuildSavedBatchExport:")] + """
class BuildSavedBatchExport:
 async def _process_source(self, source, output, entry, selection, ledger):
  for raw in entry:
   ledger.observe_account(raw)
   ledger.observe_transaction(raw)
 async def execute(self, source, publication, records):
  ledger=make_batch_export_identity_ledger(max_identities=7)
  async with source.source_generation() as lease:
   async with publication.stage() as output:
    for entry in records:
     await self._process_source(lease,output,entry,None,ledger)
    ledger.require_nonempty()
"""


def origin_context(facts, symbol, arguments=()):
    functions = {row["symbol"]: row for row in facts["functions"]}
    return value_origins(symbol, functions, arguments)


def test_nested_actual_context_and_process_loop_shapes_retain_three_edges(tmp_path):
    _, facts = inventory(tmp_path, CONTROL)
    root = origin_context(facts, "consumer.py::BuildSavedBatchExport.execute")
    assert root["instance_control_obligations"]
    process = next(context for context in root["calls"].values() if any(name == "ledger" and value.startswith("source-instance:") for name, value in context))
    child = origin_context(facts, "consumer.py::BuildSavedBatchExport._process_source", process)
    assert "consumer.py::BatchExportIdentityLedger.require_nonempty" in root["contextual_calls"].values()
    assert {"consumer.py::BatchExportIdentityLedger.observe_account", "consumer.py::BatchExportIdentityLedger.observe_transaction"} <= set(child["contextual_calls"].values())
    with pytest.raises(SemanticOperationEffectError, match="unqualified source instance control"):
        validate_operation_effects(OPERATION, "consumer.py::BuildSavedBatchExport.execute", facts, experimental_protocols=False)


@pytest.mark.parametrize("escape", ["leak(ledger)", "alias=ledger\n    leak(alias)", "box=[ledger]", "box={'value':ledger}", "holder.value=ledger", "ledger.require_nonempty=other", "ledger.__class__=other", "ledger.__dict__.update(other)", "getattr(ledger,'require_nonempty')", "def captured(): return ledger\n    leak(captured)", "ledger=other"])
def test_context_escapes_or_rebinds_never_keep_later_identity(tmp_path, escape):
    source = CONTROL.replace("    for entry in records:", "    " + escape + "\n    for entry in records:")
    _, facts = inventory(tmp_path, source)
    root = origin_context(facts, "consumer.py::BuildSavedBatchExport.execute")
    assert "consumer.py::BatchExportIdentityLedger.require_nonempty" not in root["contextual_calls"].values()
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::BuildSavedBatchExport.execute", facts, experimental_protocols=False)


@pytest.mark.parametrize("change", ["ledger=other", "leak(ledger)", "alias=ledger\n     leak(alias)"])
def test_later_iteration_or_suppressed_exception_cannot_reuse_old_identity(tmp_path, change):
    source = CONTROL.replace("     await self._process_source(lease,output,entry,None,ledger)", "     ledger.require_nonempty()\n     " + change + "\n     raise RuntimeError('suppressed')")
    _, facts = inventory(tmp_path, source)
    root = origin_context(facts, "consumer.py::BuildSavedBatchExport.execute")
    assert "consumer.py::BatchExportIdentityLedger.require_nonempty" not in root["contextual_calls"].values()


def test_zero_iteration_binding_is_not_a_post_loop_identity(tmp_path):
    source = CONTROL.replace("  ledger=make_batch_export_identity_ledger(max_identities=7)\n", "").replace("     await self._process_source(lease,output,entry,None,ledger)", "     ledger=make_batch_export_identity_ledger(max_identities=7)")
    _, facts = inventory(tmp_path, source)
    root = origin_context(facts, "consumer.py::BuildSavedBatchExport.execute")
    assert "consumer.py::BatchExportIdentityLedger.require_nonempty" not in root["contextual_calls"].values()


def test_context_class_mutation_blocks_constructor_method_map(tmp_path):
    source = "class Context:\n def __enter__(self):\n  BatchExportIdentityLedger.require_nonempty=external\n def __exit__(self,*args): return True\n" + CONTROL
    _, facts = inventory(tmp_path, source)
    root = origin_context(facts, "consumer.py::BuildSavedBatchExport.execute")
    assert not root["contextual_calls"]


def test_initializer_cycle_does_not_create_sealed_identity(tmp_path):
    source = CONTROL.replace("  self._capacity=max_identities", "  self._capacity=max_identities\n  self._cycle=[self]")
    _, facts = inventory(tmp_path, source)
    root = origin_context(facts, "consumer.py::BuildSavedBatchExport.execute")
    assert not root["contextual_calls"]


@pytest.mark.parametrize("change", ["global SAVED\n    SAVED=ledger", "raise external(ledger)", "return external(ledger)", "globals()", "helper(*[ledger])"])
def test_global_raise_return_and_reflective_paths_do_not_hide_escape(tmp_path, change):
    source = CONTROL.replace("    for entry in records:", "    " + change + "\n    for entry in records:")
    _, facts = inventory(tmp_path, source)
    root = origin_context(facts, "consumer.py::BuildSavedBatchExport.execute")
    assert "consumer.py::BatchExportIdentityLedger.require_nonempty" not in root["contextual_calls"].values()


def test_suppressed_exception_prefix_join_loses_rebound_identity(tmp_path):
    source = CONTROL.replace("    for entry in records:\n     await self._process_source(lease,output,entry,None,ledger)", "    try:\n     ledger=other\n     raise RuntimeError('suppressed')\n    except RuntimeError:\n     pass")
    _, facts = inventory(tmp_path, source)
    root = origin_context(facts, "consumer.py::BuildSavedBatchExport.execute")
    assert "consumer.py::BatchExportIdentityLedger.require_nonempty" not in root["contextual_calls"].values()


@pytest.mark.parametrize("change", ["def helper(value): return helper(value)\n", "def helper(value): pass\nhelper=external\n", "@decorate\ndef helper(value): pass\n"])
def test_uncertain_source_helper_cannot_preserve_identity(tmp_path, change):
    source = change + CONTROL.replace("    for entry in records:", "    helper(ledger)\n    for entry in records:")
    _, facts = inventory(tmp_path, source)
    root = origin_context(facts, "consumer.py::BuildSavedBatchExport.execute")
    assert "consumer.py::BatchExportIdentityLedger.require_nonempty" not in root["contextual_calls"].values()

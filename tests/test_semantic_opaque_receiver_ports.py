"""Opaque receivers must reach declared boundaries; annotations do not prove effects."""
import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from tests.test_consumer_callback_contracts import OPERATION, inventory, witness


@pytest.mark.parametrize("body,port", [
    ("store.commit()", "store.commit"),
    ("alias=store\n alias.commit()", "alias.commit"),
])
def test_borrowed_protocol_call_cannot_pass_without_actual_boundary(tmp_path, body, port):
    source="from typing import Protocol\nclass Store(Protocol):\n def commit(self): ...\ndef read(store: Store):\n " + body + "\n return 7\n"
    _,facts=inventory(tmp_path,source)
    declared={**OPERATION,"allowed_mutation_ports":["consumer.py::"+port]}
    assert validate_operation_effects(declared,"consumer.py::read",facts,experimental_protocols=False)==(1,0)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,"consumer.py::read",facts,experimental_protocols=False)


def test_context_result_receiver_requires_declared_boundary(tmp_path):
    source="def read(manager):\n with manager as output:\n  output.commit()\n return 7\n"
    _,facts=inventory(tmp_path,source)
    declared={**OPERATION,"allowed_mutation_ports":["consumer.py::output.commit"]}
    assert validate_operation_effects(declared,"consumer.py::read",facts,experimental_protocols=False)==(1,0)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,"consumer.py::read",facts,experimental_protocols=False)


def test_captured_borrowed_method_is_not_a_closed_source_callback(tmp_path):
    _,facts=inventory(tmp_path,"def read(store):\n method=store.commit\n method()\n return 7\n")
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,"consumer.py::read",facts,experimental_protocols=False)



def test_real_borrowed_receiver_mutation_has_causal_runtime_witness(tmp_path):
    source="EVENTS=[]\nclass Concrete:\n def commit(self): EVENTS.append(7)\nSTATE=Concrete()\ndef dispatch(store):\n store.commit()\ndef read():\n dispatch(STATE)\n return len(EVENTS)\n"
    path,facts=inventory(tmp_path,source)
    assert witness(path)==[1,2]
    declared={**OPERATION,"allowed_mutation_ports":["consumer.py::store.commit"]}
    assert validate_operation_effects(declared,"consumer.py::read",facts,experimental_protocols=False)==(1,0)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION,"consumer.py::read",facts,experimental_protocols=False)



def test_report_policy_retains_unqualified_receiver_observation(tmp_path):
    _,facts=inventory(tmp_path,"def read(store):\n store.commit()\n return 7\n")
    assert validate_operation_effects(OPERATION,"consumer.py::read",facts,unresolved_dynamic_policy="report",experimental_protocols=False)==(0,0)
    assert any(row["kind"]=="unqualified_opaque_receiver_call" and row["qualified"] is False for row in facts["effect_proof_observations"])

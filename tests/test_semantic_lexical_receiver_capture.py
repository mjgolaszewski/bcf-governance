"""Lexical capture feeds closed source dispatch; it never proves opaque purity."""
import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from tests.test_consumer_callback_contracts import OPERATION, inventory


def fixture(tmp_path, prefix="", callback="return self._enqueue()", before="", after="", suffix="", parent_decorator=""):
    source = prefix + "\ndef invoke(callback): return callback()\nclass Command:\n def _enqueue(self): return 7\n " + (parent_decorator + "\n " if parent_decorator else "") + "def execute(self, other=None):\n " + (" " + before + "\n " if before else "") + " def enqueue():\n   " + callback + "\n " + (" " + after + "\n " if after else "") + " return invoke(enqueue)\n" + suffix
    return inventory(tmp_path, source)[1]


def test_direct_lexical_receiver_reuses_existing_source_edge(tmp_path):
    facts = fixture(tmp_path)
    frame = next(row for row in facts["source_callable_frames"] if row["symbol"].endswith("execute.enqueue"))
    call = next(row for row in frame["calls"] if row["call_name"] == "_enqueue")
    assert call["called_symbol"] == "consumer.py::Command._enqueue"
    assert call["dispatch_resolution"] == "exact_same_instance"
    assert validate_operation_effects(OPERATION, "consumer.py::Command.execute", facts, experimental_protocols=False) == (0, 0)


@pytest.mark.parametrize("before,after", [("self=other", ""), ("", "self=other"), ("alias=self", ""), ("retain(self)", ""), ("", "retain(enqueue)")])
def test_rebind_alias_or_escape_keeps_capture_unqualified(tmp_path, before, after):
    facts = fixture(tmp_path, prefix="KEPT=[]\ndef retain(value): KEPT.append(value)\n", before=before, after=after)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::Command.execute", facts, experimental_protocols=False)


@pytest.mark.parametrize("decorator", ["@staticmethod", "@classmethod", "@decorate"])
def test_decorated_parent_is_not_an_instance_capture_proof(tmp_path, decorator):
    facts = fixture(tmp_path, parent_decorator=decorator)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::Command.execute", facts, experimental_protocols=False)


@pytest.mark.parametrize("suffix", ["\nclass Hostile(Command):\n def _enqueue(self): return external()\n", "\nCommand._enqueue=external\n"])
def test_hostile_hierarchy_or_class_mutation_stays_unresolved(tmp_path, suffix):
    facts = fixture(tmp_path, suffix=suffix)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::Command.execute", facts, experimental_protocols=False)


def test_captured_source_method_body_is_still_traversed(tmp_path):
    facts = fixture(tmp_path, prefix="EVENTS=[]\n")
    target = next(row for row in facts["functions"] if row["symbol"].endswith("Command._enqueue"))
    # Use a real changed source body, never an opaque method port.
    path = tmp_path / "consumer.py"
    path.write_text(path.read_text().replace("def _enqueue(self): return 7", "def _enqueue(self): EVENTS.append(7)"))
    facts = inventory(tmp_path, path.read_text())[1]
    assert target["symbol"] == "consumer.py::Command._enqueue"
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::Command.execute", facts, experimental_protocols=False)


def test_deeper_capture_stays_unknown(tmp_path):
    facts = fixture(tmp_path, callback="def deeper(): return self._enqueue()\n   return invoke(deeper)")
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::Command.execute", facts, experimental_protocols=False)


@pytest.mark.parametrize("change", ["property", "metaclass"])
def test_property_or_metaclass_dispatch_is_not_closed(tmp_path, change):
    fixture(tmp_path)
    path = tmp_path / "consumer.py"
    source = path.read_text()
    if change == "property":
        source = source.replace(" def _enqueue(self): return 7", " @property\n def _enqueue(self): return external")
    else:
        source = "class Meta(type): pass\n" + source.replace("class Command:", "class Command(metaclass=Meta):")
    facts = inventory(tmp_path, source)[1]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::Command.execute", facts, experimental_protocols=False)


def test_missing_parent_capture_fact_does_not_reuse_previous_dispatch(tmp_path):
    from bcf_governance.tooling.semantic_ownership_inventory import resolve_python_imports
    facts = fixture(tmp_path)
    frame = next(row for row in facts["source_callable_frames"] if row["symbol"].endswith("execute.enqueue"))
    frame.pop("lexical_parent_instance_capture")
    requalified = resolve_python_imports(tmp_path, facts)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::Command.execute", requalified, experimental_protocols=False)

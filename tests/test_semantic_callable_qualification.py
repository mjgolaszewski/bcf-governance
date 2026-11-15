"""Real discovery qualifies deferred facts without inventing ownership sites."""
import json
import subprocess
import sys
from copy import deepcopy

import pytest

from bcf_governance.tooling.semantic_ownership_inventory import (
    SemanticInventoryError,
    discover_python_source,
    resolve_python_imports,
)
from bcf_governance.tooling.semantic_ownership_typescript import TypeScriptDiscoveryError
from bcf_governance.tooling.semantic_source_discovery import merge_inventories


def test_real_deferred_import_constructor_uses_existing_qualification(tmp_path):
    model = tmp_path / "model.py"
    model.write_text("class Record:\n def __init__(self):\n  self.value=7\n")
    consumer = tmp_path / "consumer.py"
    consumer.write_text("from model import Record\ndef read():\n def callback():\n  return Record()\n return callback()\n")
    raw = discover_python_source(tmp_path, [model, consumer])
    ordinary = deepcopy(raw)
    ordinary.pop("source_callable_frames")
    baseline = resolve_python_imports(tmp_path, ordinary)
    actual = resolve_python_imports(tmp_path, raw)
    for key in baseline:
        assert actual[key] == baseline[key], key
    frame = next(row for row in actual["source_callable_frames"] if row["symbol"].endswith("read.callback"))
    assert any(row["called_symbol"] == "model.py::Record" for row in frame["calls"])
    assert any(row["constructed_symbol"] == "model.py::Record" for row in frame["constructors"])
    assert frame["parameter_annotation_symbols"] == {}
    assert actual["constructors"] == baseline["constructors"]


def test_duplicate_deferred_symbol_is_rejected(tmp_path):
    path = tmp_path / "consumer.py"
    path.write_text("def read():\n def callback(): return 7\n return callback()\n")
    raw = discover_python_source(tmp_path, [path])
    raw["source_callable_frames"].append(deepcopy(raw["source_callable_frames"][0]))
    with pytest.raises(SemanticInventoryError, match="conflicting source callable"):
        resolve_python_imports(tmp_path, raw)


def test_mixed_language_merger_retains_exact_deferred_bodies():
    frame = {"symbol": "consumer.py::read.callback", "calls": [{"called_symbol": "store.commit"}]}
    merged = merge_inventories([{"source_callable_frames": [frame]}, {"functions": [{"symbol": "api.ts::read"}]}])
    assert merged["source_callable_frames"] == [frame]
    assert merge_inventories([merged, {"source_callable_frames": [deepcopy(frame)]}])["source_callable_frames"] == [frame]
    changed = {**frame, "calls": []}
    with pytest.raises(TypeScriptDiscoveryError, match="source_callable_frames"):
        merge_inventories([merged, {"source_callable_frames": [changed]}])


@pytest.mark.parametrize("mutates", [False, True])
def test_imported_deferred_constructor_keeps_real_effect_obligations(tmp_path, mutates):
    from bcf_governance.tooling.semantic_operation_effects import (
        SemanticOperationEffectError,
        validate_operation_effects,
    )
    from tests.test_consumer_callback_contracts import OPERATION
    model = tmp_path / "model.py"
    model.write_text("EVENTS=[]\nclass Record:\n def __init__(self):\n  " + ("EVENTS.append(7)" if mutates else "self.value=7") + "\n")
    consumer = tmp_path / "consumer.py"
    consumer.write_text("from model import Record\ndef invoke(callback):\n return callback()\ndef read():\n def callback():\n  return Record()\n return invoke(callback)\n")
    script = ("import sys,runpy,json;sys.path.insert(0," + repr(str(tmp_path))
        + ");n=runpy.run_path(" + repr(str(consumer))
        + ");import model;n['read']();a=len(model.EVENTS);n['read']();print(json.dumps([a,len(model.EVENTS)]))")
    observed = subprocess.run([sys.executable, "-I", "-B", "-c", script],
        check=True, capture_output=True, text=True, timeout=10)
    assert json.loads(observed.stdout) == ([1, 2] if mutates else [0, 0])
    facts = resolve_python_imports(tmp_path, discover_python_source(tmp_path, [model, consumer]))
    if mutates:
        with pytest.raises(SemanticOperationEffectError):
            validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False)
    else:
        assert validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False) == (0, 0)


def test_missing_constructor_callback_edge_cannot_qualify_deferred_call(tmp_path):
    from bcf_governance.tooling.semantic_operation_effects import (
        SemanticOperationEffectError,
        validate_operation_effects,
    )
    from tests.test_consumer_callback_contracts import OPERATION
    path = tmp_path / "consumer.py"
    path.write_text("class Record:\n def __init__(self): self.value=7\ndef invoke(callback): return callback()\ndef read():\n def callback(): return Record()\n return invoke(callback)\n")
    facts = resolve_python_imports(tmp_path, discover_python_source(tmp_path, [path]))
    frame = next(row for row in facts["source_callable_frames"] if row["symbol"].endswith("read.callback"))
    frame["calls"] = [row for row in frame["calls"] if not row.get("constructor_frame_origin")]
    with pytest.raises(SemanticOperationEffectError, match="unqualified source callable target"):
        validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False)


def test_public_discovery_path_preserves_qualified_frames(tmp_path):
    from bcf_governance.tooling.semantic_ownership_registry import Registry
    from bcf_governance.tooling.semantic_source_discovery import discover_source
    path = tmp_path / "consumer.py"
    path.write_text("class Record:\n def __init__(self): self.value=7\ndef read():\n def callback(): return Record()\n return callback()\n")
    raw = discover_python_source(tmp_path, [path])
    registry = Registry("test", "enforce", "fail_closed", (), (), (), {})
    combined, python, typescript, _ = discover_source(tmp_path, python_inventory=raw, typescript_files=[], registry=registry)
    assert typescript["projects"] == []
    assert combined == python
    frame = next(row for row in combined["source_callable_frames"] if row["symbol"].endswith("read.callback"))
    call = next(row for row in frame["calls"] if row.get("source_constructor_frame"))
    assert call["source_constructor_frame"]["initializer"] == "consumer.py::Record.__init__"


def test_branch_local_same_name_definitions_preserve_distinct_sites(tmp_path):
    from bcf_governance.tooling.semantic_operation_effects import (
        SemanticOperationEffectError,
        validate_operation_effects,
    )
    from tests.test_consumer_callback_contracts import OPERATION
    path = tmp_path / "consumer.py"
    path.write_text("def choose(selector):\n if selector == 0:\n  def perform(): return 1\n elif selector == 1:\n  def perform(): return 2\n elif selector == 2:\n  def perform(): return 3\n else:\n  def perform(): return 4\n return perform()\ndef invoke(callback): return callback()\ndef read():\n def callback(): return 7\n return invoke(callback)\n")
    raw = discover_python_source(tmp_path, [path])
    ordinary = deepcopy(raw)
    ordinary.pop("source_callable_frames")
    baseline = resolve_python_imports(tmp_path, ordinary)
    actual = resolve_python_imports(tmp_path, raw)
    for key in baseline:
        assert actual[key] == baseline[key], key
    frames = [row for row in actual["source_callable_frames"] if ".choose.perform" in row["symbol"] or "::choose.perform" in row["symbol"]]
    assert len(frames) == len({row["symbol"] for row in frames}) == 4
    assert len({row["python_value_source"] for row in frames}) == 4
    parent = next(row for row in actual["functions"] if row["symbol"] == "consumer.py::choose")
    declarations = [row for row in parent["source_callable_definitions"] if row["name"] == "perform"]
    assert len(declarations) == 4
    assert all(row["stable"] is False for row in declarations)
    assert {row["symbol"] for row in declarations} == {row["symbol"] for row in frames}
    assert validate_operation_effects(OPERATION, "consumer.py::read", actual, experimental_protocols=False) == (0, 0)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::choose", actual, experimental_protocols=False)
    assert merge_inventories([actual, {"functions": [{"symbol": "api.ts::read"}]}])["source_callable_frames"]

"""Independent source must catch an erased object store and its effect together."""
import copy

import pytest

from bcf_governance.tooling.semantic_authority_contracts import SemanticAuthorityError
from tests.test_independent_call_coverage import capture, consume, work


@pytest.mark.parametrize("statement", ["value['v']=1", "value['v']+=1", "del value['v']",
    "value.item=1", "value.item+=1", "del value.item"])
@pytest.mark.parametrize("version", [None, "1.0"])
def test_erased_store_and_paired_effect_still_fail(tmp_path, statement, version):
    source = "def work(value):\n    " + statement + "\n    return 1\nCOMMANDS={'work':work}\n"
    facts = capture(tmp_path, source, version)
    function = work(facts)
    assert function["source_store_observations"]
    function["source_store_observations"] = []
    function["effects"] = [row for row in function.get("effects", []) if "source_store_key" not in row]
    with pytest.raises(SemanticAuthorityError, match="Python source store coverage"):
        consume(tmp_path, facts)


@pytest.mark.parametrize("defect", ["erase", "duplicate", "line", "end_column", "caller", "kind", "expression_sha256", "occurrence"])
def test_closed_local_store_membership_is_independently_checked(tmp_path, defect):
    facts = capture(tmp_path, "def work():\n    value={}\n    value['v']=1\n    return 1\nCOMMANDS={'work':work}\n")
    assert consume(tmp_path, facts)
    rows = work(facts)["source_store_observations"]
    if defect == "erase":
        rows.clear()
    elif defect == "duplicate":
        rows.append(copy.deepcopy(rows[0]))
    elif defect in {"line", "end_column", "occurrence"}:
        rows[0][defect] += 1
    elif defect == "caller":
        rows[0][defect] = "runtime.py::other"
    elif defect == "kind":
        rows[0][defect] = "subscript_delete"
    else:
        rows[0][defect] = "0" * 64
    with pytest.raises(SemanticAuthorityError, match="Python source store coverage"):
        consume(tmp_path, facts)


def test_removed_inventory_does_not_erase_actual_mutation(tmp_path):
    source = "STATE={'v':0}\ndef work():\n    STATE['v']=1\n    return 1\nCOMMANDS={'work':work}\n"
    namespace = {}
    exec(compile(source, "runtime.py", "exec"), namespace)
    namespace["work"]()
    assert namespace["STATE"] == {'v': 1}
    facts = capture(tmp_path, source)
    work(facts)["source_store_observations"] = []
    work(facts)["effects"] = []
    with pytest.raises(SemanticAuthorityError, match="Python source store coverage"):
        consume(tmp_path, facts)


@pytest.mark.parametrize("body", [
    "value={}\nvalue['v']=1\nreturn value['v']",
    "value=[0]\nvalue[0]=1\nreturn value[0]",
    "value={'v':0}\ndel value['v']\nreturn 1",
    "value={}\nvalue['v']=1\nvalue['v']=1\nreturn 1",
    "value={'v':0}\nvalue['v']+=1\nreturn 1",
])
def test_real_closed_local_store_remains_compatible(tmp_path, body):
    facts = capture(tmp_path, "def work():\n    " + body.replace("\n", "\n    ") + "\nCOMMANDS={'work':work}\n")
    assert consume(tmp_path, facts)


@pytest.mark.parametrize("source", [
    "def other(value):\n    value.x=1\n    del value.x\ndef work():\n    return 1\nCOMMANDS={'work':work}\n",
    "def outer(value):\n    class Local:\n        value.x=1\n        def method(self):\n            value.x=2\n    def child():\n        value.x=3\n    return lambda: value\ndef work():\n    return 1\nCOMMANDS={'work':work}\n",
    "def other(value, items):\n    for value.x in items:\n        value['x']=1\n    del value['x']\ndef work():\n    return 1\nCOMMANDS={'work':work}\n",
    "from __future__ import annotations\ndef other(value: annotation()):\n    value.x=1\n    return lambda: value.x\ndef work():\n    return 1\nCOMMANDS={'work':work}\n",
])
def test_unchanged_eager_deferred_and_nested_store_scopes(tmp_path, source):
    from bcf_governance.tooling import semantic_authority_operations as owner
    from bcf_governance.tooling.semantic_operation_effects import _source_function_population
    facts = capture(tmp_path, source)
    owner._validate_python_call_source_coverage(tmp_path, facts, _source_function_population(facts), None)

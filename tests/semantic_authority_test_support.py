"""Native source fixtures and unchanged loader for semantic-authority controls."""
import importlib.util
import os
from pathlib import Path
import sys

import pytest

from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports
from tests.test_independent_call_coverage import payload

def load_contracts():
    module_path = os.environ.get("BCF_SEMANTIC_AUTHORITY_MODULE_PATH")
    if module_path is None:
        from bcf_governance.tooling import semantic_authority_contracts

        return semantic_authority_contracts
    spec = importlib.util.spec_from_file_location(
        "semantic_authority_contracts", Path(module_path)
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load semantic authority module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_case(root, source, extras=(), kind="query"):
    paths=[]
    for relative,text in [("runtime.py",source),*extras]:
        path=root/relative
        path.write_text(text)
        paths.append(path)
    (root/"schemas").mkdir()
    schema=Path(__file__).parents[1]/"schemas/application-operations.schema.json"
    (root/"schemas/application-operations.schema.json").write_bytes(schema.read_bytes())
    facts=resolve_python_imports(root,discover_python_source(root,files=paths,call_contracts_version="1.0"))
    policy=payload()
    operation=policy["operations"][0]
    operation["semantic_kind"]=kind
    operation["produces_projection"]=kind=="projection"
    return policy,facts


def rejected_obligations(root, policy, facts, contracts):
    with pytest.raises(contracts.SemanticAuthorityError) as caught:
        contracts._validate_operations(root,policy,facts,collect_effect_obligations=True)
    return {row[2] for row in caught.value.operation_effect_obligations}


def unreachable_port(root, contracts):
    source="STATE=0\ndef mutate():\n    global STATE\n    STATE=1\ndef work():\n    return 1\nCOMMANDS={'work':work}\n"
    policy,facts=source_case(root,source,kind="command")
    policy["operations"][0].update(authoritative_mutation=True,allowed_mutation_ports=["runtime.py::mutate"])
    assert "unreachable_port" in rejected_obligations(root,policy,facts,contracts)


def query_write(root, contracts):
    source="STATE=0\ndef work():\n    global STATE\n    STATE=1\nCOMMANDS={'work':work}\n"
    policy,facts=source_case(root,source)
    namespace={}
    exec(compile(source,"runtime.py","exec"),namespace)
    assert namespace["STATE"]==0
    namespace["work"]()
    assert namespace["STATE"]==1
    assert "write" in rejected_obligations(root,policy,facts,contracts)


def imported_write(root, contracts, monkeypatch):
    helper="STATE=0\ndef mutate():\n    global STATE\n    STATE=1\n"
    source="from helper import mutate\ndef work():\n    mutate()\nCOMMANDS={'work':work}\n"
    policy,facts=source_case(root,source,extras=[("helper.py",helper)])
    spec=importlib.util.spec_from_file_location("helper",root/"helper.py")
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setitem(sys.modules,"helper",module)
    namespace={}
    exec(compile(source,"runtime.py","exec"),namespace)
    assert module.STATE==0
    namespace["work"]()
    assert module.STATE==1
    assert "write" in rejected_obligations(root,policy,facts,contracts)


def projection_authority(root, contracts):
    source="APPROVED=False\ndef approve():\n    global APPROVED\n    APPROVED=True\ndef work():\n    approve()\n    return APPROVED\nCOMMANDS={'work':work}\n"
    policy,facts=source_case(root,source,kind="projection")
    namespace={}
    exec(compile(source,"runtime.py","exec"),namespace)
    assert namespace["APPROVED"] is False
    assert namespace["work"]() is True
    assert {"authority","write"} <= rejected_obligations(root,policy,facts,contracts)


def dynamic_path(root, contracts):
    policy,facts=source_case(root,"def work():\n    exec('pass')\nCOMMANDS={'work':work}\n")
    assert "dynamic_call" in rejected_obligations(root,policy,facts,contracts)

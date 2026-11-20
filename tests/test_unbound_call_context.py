"""Reached unbound Python invocation is not effect authority, even with a port label."""
import os
import subprocess
import sys

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError, validated_operation_effect_inventory, validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source, resolve_python_imports

CASES = {
    "bool": ("__bool__", "return True", "bool(value)"),
    "int": ("__int__", "return 1", "int(value)"),
    "float": ("__float__", "return 1.0", "float(value)"),
    "str": ("__str__", "return 'value'", "str(value)"),
    "bytes": ("__bytes__", "return b'value'", "bytes(value)"),
    "len": ("__len__", "return 1", "len(value)"),
    "hash": ("__hash__", "return 1", "hash(value)"),
    "repr": ("__repr__", "return 'value'", "repr(value)"),
    "iter": ("__iter__", "return iter((1,))", "iter(value)"),
    "list": ("__iter__", "return iter((1,))", "list(value)"),
}


def operation(**changes):
    return {"id":"unbound.query.v1", "allowed_mutation_ports":[],
        "allowed_authority_ports":[], "non_authoritative_output_effects":[]} | changes


def inventory(tmp_path, body="return bool(value)", extra="", other=None):
    path = tmp_path / "service.py"
    path.write_text(extra + "\ndef query(value):\n    " + body.replace("\n", "\n    ") + "\n")
    paths = [path]
    if other:
        target = tmp_path / "foreign/service.py"
        target.parent.mkdir()
        target.write_text(other)
        paths.append(target)
    return discover_python_source(tmp_path,files=paths,call_contracts_version="1.0")


@pytest.mark.parametrize("case", CASES)
def test_strict_native_input_callback_requires_invocation_context(tmp_path, case):
    with pytest.raises(SemanticOperationEffectError, match="runtime call context"):
        validate_operation_effects(operation(),"service.py::query",inventory(tmp_path,"return " + CASES[case][2]))


@pytest.mark.parametrize("case", CASES)
def test_ordinary_native_consumer_witnesses_input_callback(tmp_path, case):
    method, result, expression = CASES[case]
    source = "EVENTS=[]\nclass Value:\n    def " + method + "(self):\n        EVENTS.append('callback')\n        " + result + "\n"
    source += "def query(value):\n    return " + expression + "\nvalue=Value()\nquery(value)\nassert EVENTS==['callback']\nprint('native-unbound-callback')\n"
    path = tmp_path / "native.py"
    path.write_text(source)
    env = {key:value for key,value in os.environ.items() if not key.startswith(("PYTHON","BCF_","GIT_","GITHUB_","AGENTBUS_"))
           and key not in {"GH_TOKEN","VIRTUAL_ENV"}}
    result = subprocess.run([sys.executable,"-I","-B",str(path)],cwd=tmp_path,env=env,capture_output=True,text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "native-unbound-callback"


@pytest.mark.parametrize("body,extra", [("STORE.append(value)","STORE=[]\n"), ("return emit()", "")])
def test_global_object_and_global_callback_are_not_silently_pure(tmp_path, body, extra):
    with pytest.raises(SemanticOperationEffectError, match="runtime call context"):
        validate_operation_effects(operation(),"service.py::query",inventory(tmp_path,body,extra))


def test_transitive_source_helper_cannot_hide_native_callback(tmp_path):
    facts = inventory(tmp_path,"return helper(value)","def helper(value):\n    return bool(value)\n")
    with pytest.raises(SemanticOperationEffectError, match="runtime call context"):
        validate_operation_effects(operation(),"service.py::query",facts)


@pytest.mark.parametrize("field", ["allowed_mutation_ports","allowed_authority_ports","non_authoritative_output_effects"])
def test_native_port_label_does_not_authenticate_its_invocation(tmp_path, field):
    facts = inventory(tmp_path)
    with pytest.raises(SemanticOperationEffectError, match="runtime call context"):
        validate_operation_effects(operation(**{field:["service.py::bool"]}),"service.py::query",facts)


@pytest.mark.parametrize("forgery", ["call-language","function-language","both-languages","purity","context","effect"])
def test_candidate_metadata_cannot_qualify_python_native_call(tmp_path, forgery):
    facts = inventory(tmp_path)
    row = next(function for function in facts["functions"] if function["symbol"] == "service.py::query")
    call = row["calls"][0]
    if forgery in {"call-language","both-languages"}:
        call["language"] = "typescript"
    if forgery in {"function-language","both-languages"}:
        row["language"] = "typescript"
    if forgery == "purity":
        call["native_pure"] = True
    elif forgery == "context":
        call["runtime_context_qualified"] = True
    elif forgery == "effect":
        call["effect"] = "read"
    with pytest.raises(SemanticOperationEffectError, match="runtime call context"):
        validate_operation_effects(operation(),"service.py::query",facts)


def test_unrelated_basename_match_cannot_replace_actual_builtin_binding(tmp_path):
    facts = inventory(tmp_path,other="def bool(value):\n    return True\n")
    with pytest.raises(SemanticOperationEffectError, match="runtime call context"):
        validate_operation_effects(operation(),"service.py::query",facts)


def test_exact_source_bound_pure_helper_preserves_behavior(tmp_path):
    facts = inventory(tmp_path,"return helper(value)","def helper(value):\n    return value is None\n")
    assert validate_operation_effects(operation(),"service.py::query",facts) == (0,0)


def test_resolved_import_retains_exact_source_call_binding(tmp_path):
    helper = tmp_path / "helper.py"
    helper.write_text("def pure(value):\n    return value is None\n")
    path = tmp_path / "service.py"
    path.write_text("from helper import pure\ndef query(value):\n    return pure(value)\n")
    facts = resolve_python_imports(tmp_path,discover_python_source(tmp_path,files=[path,helper],call_contracts_version="1.0"))
    assert validate_operation_effects(operation(),"service.py::query",facts) == (0,0)


def test_source_only_projection_retains_unresolved_native_call_not_authority(tmp_path):
    facts = inventory(tmp_path)
    rows = validated_operation_effect_inventory(operation(),"service.py::query",facts,require_runtime_context=False)
    assert len(rows) == 1 and rows[0][:2] == ("unresolved","runtime_call")
    assert validate_operation_effects(operation(),"service.py::query",facts,require_runtime_context=False) == (0,0)


def test_explicit_native_port_remains_only_unqualified_source_projection(tmp_path):
    facts = inventory(tmp_path)
    selected = operation(allowed_mutation_ports=["service.py::bool"])
    rows = validated_operation_effect_inventory(selected,"service.py::query",facts,require_runtime_context=False)
    assert ("mutation","call","service.py::bool") in rows
    assert any(row[:2] == ("unresolved","runtime_call") for row in rows)
    assert validate_operation_effects(selected,"service.py::query",facts,require_runtime_context=False) == (1,0)


def test_unknown_invocations_retain_distinct_call_occurrences(tmp_path):
    facts = inventory(tmp_path,"emit()\nemit()\nreturn None")
    with pytest.raises(SemanticOperationEffectError) as captured:
        validate_operation_effects(operation(),"service.py::query",facts)
    rows = [row for row in captured.value.effect_obligations if row[1] == "runtime_call"]
    assert len(rows) == 2 and len({row[2] for row in rows}) == 2


@pytest.mark.parametrize("kind", ["global_object", "global_callback"])
def test_ordinary_global_invocation_witnesses_effect_without_input_callback(kind):
    events = []
    if kind == "global_object":
        source = "STORE=[]\ndef query(value):\n    STORE.append(value)\n"
        scope = {}
        exec(compile(source,"global-object.py","exec"),scope)
        scope["query"](None)
        assert scope["STORE"] == [None]
    else:
        source = "def query(value):\n    return emit()\n"
        scope = {"emit":lambda: events.append("global")}
        exec(compile(source,"global-callback.py","exec"),scope)
        scope["query"](None)
        assert events == ["global"]


def test_existing_typescript_projection_stays_outside_python_call_guard():
    facts = {"functions":[{"symbol":"app.ts::query", "language":"typescript",
        "calls":[{"caller":"app.ts::query","called_symbol":"external::read",
                  "call_name":"read","language":"typescript"}]}]}
    assert validate_operation_effects(operation(),"app.ts::query",facts) == (0,0)

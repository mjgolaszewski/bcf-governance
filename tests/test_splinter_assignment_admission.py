"""An exact union cannot hide incorrect per-splinter execution or malformed plans."""
import copy
import hashlib
import json

import pytest

from bcf_governance.tooling.evidence_scheduling import (
    compile_test_splinter_plan, validate_test_splinter_plan, validate_test_splinter_results,
)
from bcf_governance.tooling.test_splinter_proofs import applicability_identity

IDENTITY = {"subject_commit": "a" * 40, "subject_tree": "b" * 40,
            "session": "s", "policy_sha256": "c" * 64, "producer": "test"}
NODES = {"tests.one::test_a": "tests/one.py::test_a", "tests.two::test_b": "tests/two.py::test_b"}


def plan():
    return compile_test_splinter_plan(NODES, {}, max_splinters=2, identity=IDENTITY)


def rehash(value):
    value["partition_sha256"] = hashlib.sha256(json.dumps(
        {k:v for k,v in value.items() if k != "partition_sha256"},
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@pytest.mark.parametrize("defect", ["empty_inventory", "nonstring_node", "empty_selector",
    "nonstring_selector", "duplicate_selector", "empty_assignment", "identity_missing",
    "identity_extra", "identity_nonstring", "duration_digest", "unknown_fallback",
    "fallback_multiple_assignments", "inventory_order"])
@pytest.mark.parametrize("consumer", ["plan", "proof"])
def test_self_consistent_malformed_plan_is_rejected_before_use(defect, consumer):
    value = plan()
    if defect == "empty_inventory":
        value["node_inventory"] = []
        value["splinters"] = [{"id":"splinter-0", "nodes":[], "selectors":[], "estimated_duration_ms":1}]
    elif defect == "nonstring_node":
        value["node_inventory"][0] = 1
        value["splinters"][0]["nodes"][0] = 1
    elif defect == "empty_selector":
        value["splinters"][0]["selectors"][0] = ""
    elif defect == "nonstring_selector":
        value["splinters"][0]["selectors"][0] = 1
    elif defect == "duplicate_selector":
        value["splinters"][1]["selectors"] = value["splinters"][0]["selectors"][:]
    elif defect == "empty_assignment":
        value["splinters"].append({"id":"splinter-2", "nodes":[], "selectors":[], "estimated_duration_ms":1})
    elif defect == "identity_missing":
        del value["identity"]["subject_commit"]
    elif defect == "identity_extra":
        value["identity"]["unbound"] = "unbound"
    elif defect == "identity_nonstring":
        value["identity"]["session"] = True
    elif defect == "duration_digest":
        value["duration_input_sha256"] = "not-a-digest"
    elif defect == "unknown_fallback":
        value["fallback_reason"] = "candidate_decided"
    elif defect == "fallback_multiple_assignments":
        value["fallback_reason"] = "resources_incompatible"
    else:
        value["node_inventory"].reverse()
    rehash(value)
    with pytest.raises(ValueError, match="test splinter"):
        if consumer == "plan":
            validate_test_splinter_plan(value)
        else:
            applicability_identity(value, value["splinters"][0], toolchain_sha256="d" * 64)


def test_swapped_results_cannot_hide_behind_exact_union():
    value = plan()
    observed = {value["splinters"][0]["id"]: value["splinters"][1]["nodes"],
                value["splinters"][1]["id"]: value["splinters"][0]["nodes"]}
    with pytest.raises(ValueError, match="assignment"):
        validate_test_splinter_results(value, observed)


def test_result_validation_authenticates_plan_digest():
    value = plan()
    value["partition_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="digest"):
        validate_test_splinter_results(value, {row["id"]: row["nodes"] for row in value["splinters"]})


@pytest.mark.parametrize("nodes,identity,maximum", [
    ({1:"tests/one.py::test_a"}, IDENTITY, 1),
    ({"tests.one::test_a":1}, IDENTITY, 1),
    (NODES, dict(IDENTITY, session=True), 1),
    (NODES, IDENTITY, True),
])
def test_compiler_rejects_invalid_population_types(nodes, identity, maximum):
    with pytest.raises(ValueError, match="test splinter"):
        compile_test_splinter_plan(nodes, {}, max_splinters=maximum, identity=identity)


def test_genuine_results_preserve_order_independence_iterables_and_inputs():
    value = compile_test_splinter_plan(NODES, {}, max_splinters=1, identity=IDENTITY)
    before = copy.deepcopy(value)
    validate_test_splinter_results(value, {"splinter-0": iter(reversed(value["node_inventory"]))})
    assert value == before

from __future__ import annotations

import copy

import pytest

from tests.test_semantic_authority import (
    REPO_ROOT, SemanticAuthorityError, _yaml, contracts,
    source_inventory as source_inventory,
)


@pytest.mark.parametrize("invalid", [
    "missing", "duplicate", "stale", "entrypoint", "semantics", "function",
])
def test_complete_operation_admission_precedes_every_effect_query(
    invalid: str, source_inventory: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _yaml("governance/application-operations.yml")
    inventory = source_inventory
    operation = payload["operations"][-1]
    if invalid == "missing":
        payload["operations"].pop()
        cause = "unclassified public application operations"
    elif invalid == "duplicate":
        duplicate = copy.deepcopy(operation)
        duplicate["id"] += ".duplicate"
        payload["operations"].append(duplicate)
        cause = "multiply classified"
    elif invalid == "stale":
        operation["population_key"] = "removed-command"
        cause = "is stale"
    elif invalid == "entrypoint":
        operation["entrypoints"] = ["bcf_governance/cli.py::missing"]
        cause = "entrypoints must exactly match"
    elif invalid == "semantics":
        operation = next(row for row in payload["operations"]
                         if row["id"] == "governance.cli.doctor.v1")
        operation["authority_conferral"] = True
        cause = "cannot mutate or confer authority"
    else:
        functions = {row["symbol"]: row for row in source_inventory["functions"]}
        target = contracts._function_for_entrypoint(
            REPO_ROOT, operation["entrypoints"][0], functions,
        )
        assert target is not None
        inventory = dict(source_inventory, functions=[
            row for row in source_inventory["functions"] if row["symbol"] != target["symbol"]
        ])
        cause = "entrypoint is absent from the shared source inventory"

    def forbidden_effect_query(*args, **kwargs):
        pytest.fail("effect traversal allocated before complete operation admission")

    monkeypatch.setattr(contracts, "validated_operation_effect_inventory", forbidden_effect_query)
    with pytest.raises(SemanticAuthorityError, match=cause):
        contracts._validate_operations(REPO_ROOT, payload, inventory)


def test_admitted_operation_population_keeps_effect_order_and_observations(
    source_inventory: dict, monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _yaml("governance/application-operations.yml")
    baseline = contracts._validate_operations(REPO_ROOT, payload, source_inventory)
    original = contracts.validated_operation_effect_inventory
    observed = []

    def record(operation, *args, **kwargs):
        observed.append(operation["id"])
        return original(operation, *args, **kwargs)

    monkeypatch.setattr(contracts, "validated_operation_effect_inventory", record)
    assert contracts._validate_operations(REPO_ROOT, payload, source_inventory) == baseline
    assert observed == [row["operation"] for row in baseline]

from __future__ import annotations

import pytest
import yaml

from bcf_governance.tooling.governance_profiles import _v2_builtin_contracts
from bcf_governance.tooling.yaml_mutations import (
    YAMLMutationPathError,
    assign_yaml_value,
    mutation_mode,
    replace_yaml_value_bytes,
    resolve_yaml_target,
    typed_mutation_value,
)


def _payload() -> dict[str, object]:
    return {
        "representations": [
            {"semantic_id": "governance.alpha.v1", "owners": ["alpha"]},
            {"semantic_id": "governance.beta.v1", "owners": ["beta"]},
        ]
    }


def test_keyed_yaml_path_targets_identity_instead_of_list_position() -> None:
    payload = _payload()
    path = "representations[semantic_id=governance.beta.v1].owners"
    assert resolve_yaml_target(payload, path).value == ["beta"]
    previous = assign_yaml_value(payload, path, ["mutant"])
    assert previous == ["beta"]
    assert payload["representations"][0]["owners"] == ["alpha"]
    assert payload["representations"][1]["owners"] == ["mutant"]


@pytest.mark.parametrize(
    "path",
    [
        "representations[semantic_id=missing].owners",
        "representations[semantic_id=governance.beta.v1]",
        "representations..owners",
        "representations[semantic_id=governance.beta.v1].missing",
    ],
)
def test_keyed_yaml_path_fails_closed(path: str) -> None:
    with pytest.raises(YAMLMutationPathError):
        resolve_yaml_target(_payload(), path)


def test_keyed_yaml_path_rejects_ambiguous_identity() -> None:
    payload = _payload()
    payload["representations"].append(
        {"semantic_id": "governance.beta.v1", "owners": ["duplicate"]}
    )
    with pytest.raises(YAMLMutationPathError, match="resolved 2"):
        resolve_yaml_target(
            payload, "representations[semantic_id=governance.beta.v1].owners"
        )


def test_yaml_text_replacement_requires_an_explicit_byte_level_reason() -> None:
    mutation = {"search": "owner: old", "replace": "owner: new"}
    with pytest.raises(YAMLMutationPathError, match="byte_level_reason"):
        mutation_mode(mutation, suffix=".yml")
    mutation["byte_level_reason"] = "proves exact generated workflow byte custody"
    assert mutation_mode(mutation, suffix=".yml") == "text"


def test_typed_yaml_value_can_be_encoded_without_exposing_fixture_content() -> None:
    mutation = {
        "yaml_path": "owner",
        "value_base64": "L1VzZXJzL2V4YW1wbGUvcHJpdmF0ZS9BR0VOVFMueW1s",
    }
    assert mutation_mode(mutation, suffix=".yml") == "yaml"
    assert typed_mutation_value(mutation) == "/Users/example/private/AGENTS.yml"


def test_typed_yaml_assignment_preserves_all_unrelated_bytes() -> None:
    source = "document: {kind: phase_log, status: active}\nnotes:\n  - 'artifact: local-only'  # retained byte-for-byte\n"

    mutated, previous = replace_yaml_value_bytes(source, "document.status", "verified")

    assert previous == "active"
    assert mutated == source.replace("status: active", "status: verified")


def test_typed_yaml_assignment_preserves_keyed_selector_bytes() -> None:
    source = "rows:\n- {id: first, values: [a]}\n- {id: second, values: [b]} # retained\n"

    mutated, previous = replace_yaml_value_bytes(
        source, "rows[id=second].values", ["mutant"]
    )

    assert previous == ["b"]
    assert mutated == source.replace("values: [b]", "values: [mutant]")


def test_typed_yaml_assignment_preserves_block_collection_separator() -> None:
    source = "rows:\n- id: first\n  owners:\n  - old\n  authorized_pure_delegates: []\n"

    mutated, previous = replace_yaml_value_bytes(
        source, "rows[id=first].owners", ["new"]
    )

    assert previous == ["old"]
    assert mutated == source.replace("owners:\n  - old", "owners:\n  - new")
    assert yaml.safe_load(mutated)["rows"][0]["authorized_pure_delegates"] == []


@pytest.mark.parametrize("style", ["'", '"'])
def test_typed_yaml_assignment_preserves_quoted_flow_scalar(style: str) -> None:
    current = "${{ github.event.workflow_run.run_attempt }}"
    replacement = "${{ github.run_attempt }}"
    source = f"component: {{name: {style}{current}{style}, retained: exact}}\n"

    mutated, previous = replace_yaml_value_bytes(
        source, "component.name", replacement
    )

    assert previous == current
    assert yaml.safe_load(mutated) == {
        "component": {"name": replacement, "retained": "exact"}
    }
    assert "retained: exact" in mutated


@pytest.mark.parametrize(
    "mutation",
    [
        {"search": "old", "replace": "new", "yaml_path": "owner", "value": "new"},
        {"search": "old", "replace": "new", "replace_base64": "bmV3"},
        {"yaml_path": "owner"},
    ],
)
def test_mutation_mode_fails_closed_on_ambiguous_or_incomplete_shapes(
    mutation: dict[str, object],
) -> None:
    with pytest.raises(YAMLMutationPathError, match="exactly one"):
        mutation_mode(mutation, suffix=".py")


def test_builtin_yaml_controls_use_semantic_paths_not_literal_text() -> None:
    for gate in _v2_builtin_contracts().values():
        for control in gate["negative_controls"]:
            mutation = control["mutation"]
            assert mutation_mode(
                mutation, suffix=".yml"
            ) == "yaml", control["id"]

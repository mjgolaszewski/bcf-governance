"""The existing architecture schema and semantic parser are separate admissions."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
import pytest

from bcf_governance.tooling.architecture_source_components import (
    SourceComponentError,
    parse_source_components,
)
from test_architecture_source_components import architecture


def schema():
    owner = Path(__file__).resolve().parents[1] / "schemas/architecture-boundaries.schema.json"
    return json.loads(owner.read_text())["properties"]["architecture"]["properties"]["source_component_ownership"]


def test_shape_valid_declaration_remains_only_an_unresolved_request():
    value = architecture()
    Draft202012Validator(schema()).validate(value["source_component_ownership"])
    result = parse_source_components(value, reader_supported=True)
    assert len(result) == 1 and result[0].managed_pack is None
    assert not hasattr(result[0], "ownership_accepted")


@pytest.mark.parametrize("mutation", ["path_pattern", "unknown_layer"])
def test_shape_acceptance_cannot_replace_stricter_semantic_admission(mutation):
    value = architecture()
    component = value["source_component_ownership"]["components"][0]
    if mutation == "path_pattern":
        component["members"] = {"scripts/*.py": "a" * 64}
    else:
        component["layer"] = "foreign"
    Draft202012Validator(schema()).validate(value["source_component_ownership"])
    with pytest.raises(SourceComponentError):
        parse_source_components(value, reader_supported=True)


def test_trailing_newline_digest_refuses_at_both_shape_and_semantic_boundaries():
    value = architecture()
    value["source_component_ownership"]["components"][0]["members"]["scripts/catalog.py"] += "\n"
    with pytest.raises(ValidationError):
        Draft202012Validator(schema()).validate(value["source_component_ownership"])
    with pytest.raises(SourceComponentError, match="lowercase SHA256"):
        parse_source_components(value, reader_supported=True)

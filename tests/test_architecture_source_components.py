"""Closed admission controls; these declarations never confer native authority."""

from copy import deepcopy

import pytest

from bcf_governance.tooling.architecture_source_components import (
    SourceComponentError,
    parse_source_components,
)


def architecture():
    return {"layers": {"tooling": {}}, "source_component_ownership": {
        "version": "1.0", "components": [{
            "id": "tools", "layer": "tooling", "context": "catalog",
            "rationale": "Catalog validation owned by catalog tooling",
            "members": {"scripts/catalog.py": "a" * 64}, "managed_pack": None,
            "context_authority": {"kind": "independently_inferred_inventory", "version": "1.0", "selector": "catalog"},
        }],
    }}


@pytest.mark.parametrize("supported", [True, False])
def test_absent_declaration_preserves_legacy(supported):
    assert parse_source_components({}, reader_supported=supported) == ()


@pytest.mark.parametrize("value", [None, {}, [], {"version": "1.0", "components": []}])
def test_present_declaration_on_unsupported_consumer_refuses_even_if_empty(value):
    with pytest.raises(SourceComponentError, match="unsupported native consumer"):
        parse_source_components({"source_component_ownership": value}, reader_supported=False)


def test_closed_declaration_parses_to_unresolved_immutable_request_without_mutating_input():
    source = architecture()
    before = deepcopy(source)
    result = parse_source_components(source, reader_supported=True)
    assert source == before
    assert len(result) == 1 and result[0].members == (("scripts/catalog.py", "a" * 64),)
    assert result[0].context_authority.selector == "catalog" and result[0].context_authority.version == "1.0"
    assert result[0].managed_pack is None
    assert not hasattr(result[0], "authenticated") and not hasattr(result[0], "coverage_accepted")


@pytest.mark.parametrize("path", [
    "/scripts/catalog.py", "../catalog.py", "scripts/../catalog.py", "./scripts/catalog.py",
    "scripts//catalog.py", "scripts/catalog.py/", "scripts\\catalog.py", "C:/catalog.py",
    "scripts/*.py", "scripts/catalog?.py", "scripts/[a].py", "scripts/catalog.txt",
])
def test_member_path_aliases_patterns_and_nonpython_members_refuse(path):
    value = architecture()
    value["source_component_ownership"]["components"][0]["members"] = {path: "a" * 64}
    with pytest.raises(SourceComponentError):
        parse_source_components(value, reader_supported=True)


@pytest.mark.parametrize("field, replacement", [
    ("id", ""), ("id", " padded"), ("layer", "unknown"), ("context", ""),
    ("rationale", ""), ("members", {}), ("members", {"scripts/catalog.py": "A" * 64}),
    ("managed_pack", True), ("context_authority", {"kind": "rationale"}),
])
def test_invalid_component_fields_refuse(field, replacement):
    value = architecture()
    value["source_component_ownership"]["components"][0][field] = replacement
    with pytest.raises(SourceComponentError):
        parse_source_components(value, reader_supported=True)


@pytest.mark.parametrize("mutation", ["version", "unknown_field", "duplicate_id", "overlap", "foreign_lock"])
def test_closed_version_population_and_existing_runtime_owner_required(mutation):
    value = architecture()
    declaration = value["source_component_ownership"]
    component = declaration["components"][0]
    if mutation == "version":
        declaration["version"] = "2.0"
    elif mutation == "unknown_field":
        component["skip_checks"] = True
    elif mutation in {"duplicate_id", "overlap"}:
        other = deepcopy(component)
        if mutation == "overlap":
            other["id"] = "other"
        declaration["components"].append(other)
    else:
        component["managed_pack"] = {
            "runtime_lock_path": "governance/replacement-lock.json", "runtime_lock_sha256": "a" * 64,
        }
    with pytest.raises(SourceComponentError):
        parse_source_components(value, reader_supported=True)


@pytest.mark.parametrize("field", ["subject_sha256", "config_sha256", "member_sha256", "source_binding"])
def test_authored_context_request_cannot_supply_native_binding_digests(field):
    value = architecture()
    value["source_component_ownership"]["components"][0]["context_authority"][field] = "a" * 64
    with pytest.raises(SourceComponentError, match="exact fields"):
        parse_source_components(value, reader_supported=True)


@pytest.mark.parametrize("authority", [
    {"kind": "independently_inferred_inventory", "version": "2.0", "selector": "catalog"},
    {"kind": "independently_inferred_inventory", "version": "1.0", "selector": ""},
    {"kind": "qualified_package_metadata_context", "version": "1.0", "selector": "../__init__.py"},
    {"kind": "qualified_package_metadata_context", "version": "1.0", "selector": "src/business.py"},
])
def test_context_request_requires_supported_owner_version_and_exact_selector(authority):
    value = architecture()
    value["source_component_ownership"]["components"][0]["context_authority"] = authority
    with pytest.raises(SourceComponentError):
        parse_source_components(value, reader_supported=True)

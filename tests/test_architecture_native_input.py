"""Exercise admission at the actual standalone native config entrypoint."""

import importlib.util
import json
from pathlib import Path
import shutil

import pytest


REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(params=["template-repo", "bcf_governance/pack/template-repo"])
def native_config(tmp_path, request):
    repo = tmp_path / "repo"
    gate = repo / "backend/tests/architecture/test_boundaries_ast.py"
    admission = repo / "scripts/_bcf_runtime/architecture_policy_input.py"
    gate.parent.mkdir(parents=True)
    admission.parent.mkdir(parents=True)
    shutil.copyfile(REPO / request.param / "backend/tests/architecture/test_boundaries_ast.py", gate)
    shutil.copyfile(REPO / request.param / "scripts/_bcf_runtime/architecture_policy_input.py", admission)
    specification = importlib.util.spec_from_file_location("native_architecture_input_fixture", gate)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return repo / "architecture-boundaries.yml", module


def test_actual_native_entrypoint_keeps_finite_legacy_aliases(native_config):
    path, module = native_config
    path.write_text("architecture: {layers: &layers {tooling: {}}, copy: *layers}\n")
    result = module._architecture_config()
    assert result["layers"] == {"tooling": {}} and result["copy"] == result["layers"]


def test_actual_native_entrypoint_keeps_true_absence_legacy_defaults(native_config):
    path, module = native_config
    assert not path.exists() and not path.is_symlink()
    assert module._architecture_config() == module.DEFAULT_CONFIG["architecture"]


@pytest.mark.parametrize("value", ["null", "{}", "[]", json.dumps({
    "version": "1.0", "components": [{
        "id": "tools", "layer": "tooling", "context": "catalog", "rationale": "Catalog tools",
        "members": {"scripts/catalog.py": "a" * 64}, "managed_pack": None,
        "context_authority": {"kind": "independently_inferred_inventory", "version": "1.0", "selector": "catalog"},
    }],
})])
def test_actual_native_entrypoint_refuses_any_present_unsupported_contract(native_config, value):
    path, module = native_config
    path.write_text("architecture: {source_component_ownership: " + value + ", layers: {tooling: {}}}\n")
    with pytest.raises(module.SourceComponentUnsupportedError, match="qualified native ownership consumer"):
        module._architecture_config()


@pytest.mark.parametrize("source, diagnostic", [
    ("architecture: {source_component_ownership: null}\narchitecture: {layers: {tooling: {}}}\n", "duplicate YAML mapping key"),
    ("architecture: {source_component_ownership: null, source_component_ownership: {}}\n", "duplicate YAML mapping key"),
    ("defaults: &defaults {source_component_ownership: null}\narchitecture: {<<: *defaults, layers: {tooling: {}}}\n", "explicit string key"),
    ("architecture: &recursive {layers: *recursive}\n", "cyclic or excessive"),
    ("architecture: {true: ignored, layers: {tooling: {}}}\n", "explicit string key"),
])
def test_actual_native_entrypoint_refuses_ambiguity_before_present_can_be_erased(native_config, source, diagnostic):
    path, module = native_config
    path.write_text(source)
    with pytest.raises(ValueError, match=diagnostic):
        module._architecture_config()


def test_actual_native_entrypoint_refuses_symlink_config(native_config):
    path, module = native_config
    other = path.with_name("other.yml")
    other.write_text("architecture: {layers: {tooling: {}}}\n")
    path.symlink_to(other)
    with pytest.raises(ValueError, match="canonical absolute path"):
        module._architecture_config()


def test_actual_native_entrypoint_refuses_oversized_config_before_yaml_parse(native_config):
    path, module = native_config
    path.write_bytes(b"#" * (2 * 1024**2 + 1))
    with pytest.raises(ValueError, match="bounded regular file"):
        module._architecture_config()


def test_actual_native_entrypoint_refuses_dangling_symlink_instead_of_defaults(native_config):
    path, module = native_config
    path.symlink_to(path.with_name("missing.yml"))
    with pytest.raises(ValueError, match="canonical absolute path"):
        module._architecture_config()


@pytest.mark.parametrize("mutation", ["missing", "symlink"])
def test_actual_native_entrypoint_typed_refuses_unavailable_or_noncanonical_input_owner(native_config, mutation):
    path, module = native_config
    path.write_text("architecture: {source_component_ownership: null, layers: {tooling: {}}}\n")
    owner = path.parent / "scripts/_bcf_runtime/architecture_policy_input.py"
    if mutation == "missing":
        owner.unlink()
    else:
        moved = owner.with_name("moved.py")
        owner.rename(moved)
        owner.symlink_to(moved)
    with pytest.raises(module.SourceComponentUnsupportedError, match="maintained architecture input owner"):
        module._architecture_config()

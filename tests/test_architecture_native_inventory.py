"""Real Git subjects and source bytes for the maintained context profile."""

from dataclasses import replace
import importlib
import importlib.util
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml


REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module", params=["canonical", "template", "packaged_template"])
def native(request):
    if request.param == "canonical":
        module = importlib.import_module("bcf_governance.tooling.architecture_native_inventory")
        expected = REPO / "bcf_governance/tooling/architecture_native_inventory.py"
    else:
        relative = "template-repo" if request.param == "template" else "bcf_governance/pack/template-repo"
        runtime = REPO / relative / "scripts/_bcf_runtime"
        name = "_architecture_context_" + request.param
        assert name not in sys.modules
        specification = importlib.util.spec_from_file_location(name, runtime / "__init__.py",
                                                              submodule_search_locations=[str(runtime)])
        assert specification is not None and specification.loader is not None
        package = importlib.util.module_from_spec(specification)
        sys.modules[name] = package
        specification.loader.exec_module(package)
        module = importlib.import_module(name + ".architecture_native_inventory")
        expected = runtime / "architecture_native_inventory.py"
    assert Path(module.__file__).resolve() == expected
    return module


def git(root, *args):
    result = subprocess.run([
        "/usr/bin/git", "--no-optional-locks", "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false", "-C", str(root), *args,
    ], capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr[:2000]
    return result.stdout


def commit(root):
    git(root, "add", "-A")
    git(root, "commit", "--quiet", "-m", "native context subject")


def config(root):
    return json.loads((root / "architecture-boundaries.yml").read_text())


def write_config(root, value):
    (root / "architecture-boundaries.yml").write_text(json.dumps(value, indent=2) + "\n")


@pytest.fixture
def subject(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    configuration = yaml.safe_load((REPO / "template-repo/architecture-boundaries.yml").read_text())
    architecture = configuration["architecture"]
    architecture["source_roots"] = ["src"]
    architecture["layers"]["composition"] = {
        "path_tokens": ["bootstrap"], "required": False, "forbidden_import_prefixes": [],
        "forbidden_layer_imports": [], "forbidden_import_names": [],
    }
    architecture["package_metadata_ownership"] = [{
        "path": "src/bootstrap/__init__.py", "layer": "composition", "context": "bootstrap", "exports": ["__doc__"],
    }]
    write_config(root, configuration)
    (root / "schemas").mkdir()
    shutil.copyfile(REPO / "schemas/architecture-boundaries.schema.json", root / "schemas/architecture-boundaries.schema.json")
    for relative, text in {
        "src/bootstrap/__init__.py": '"""Bootstrap composition package."""\n',
        "src/domain/orders/rules.py": "VALUE = 1\n",
        "src/loose.py": "VALUE = 7\n",
    }.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    git(root, "init", "--quiet")
    git(root, "config", "user.email", "context-fixture@example.test")
    git(root, "config", "user.name", "Context Fixture")
    commit(root)
    return root


def test_native_factory_binds_whole_subject_config_members_and_preserves_unknown_findings(subject, native):
    inventory = native.build_native_inventory(subject)
    assert tuple(member.path for member in inventory.members) == (
        "src/bootstrap/__init__.py", "src/domain/orders/rules.py", "src/loose.py",
    )
    assert inventory.config_sha256 == hashlib.sha256((subject / "architecture-boundaries.yml").read_bytes()).hexdigest()
    assert inventory.observation.source_sha256 == tuple((member.path, member.sha256) for member in inventory.members)
    assert inventory.observation.metadata_modules == ("src/bootstrap/__init__.py",)
    assert {(row.rule, row.path) for row in inventory.observation.violations} == {
        ("layer_membership", "src/loose.py"), ("context_membership", "src/loose.py"),
    }
    current = dict(inventory.subject)
    expected_subject = hashlib.sha256(json.dumps(current, sort_keys=True, ensure_ascii=True,
                                                separators=(",", ":")).encode()).hexdigest()
    assert all(binding.subject_sha256 == expected_subject and binding.config_sha256 == inventory.config_sha256
               for binding in inventory.contexts)
    assert not hasattr(inventory, "released_pack_authenticated") and not hasattr(inventory, "ownership_accepted")


@pytest.mark.parametrize("kind, selector, context", [
    ("qualified_package_metadata_context", "src/bootstrap/__init__.py", "bootstrap"),
    ("independently_inferred_inventory", "orders", "orders"),
])
def test_real_native_owner_resolves_only_its_current_exact_context(subject, native, kind, selector, context):
    inventory = native.build_native_inventory(subject)
    binding = native.resolve_native_context(subject, inventory=inventory, kind=kind, version="1.0", selector=selector)
    assert binding.context == context and binding.selector == selector and len(binding.member_sha256) == 64


@pytest.mark.parametrize("source", [
    '"""Doc."""\nimport os\n', '"""Doc."""\nVALUE = 1\n', "class Thing: pass\n", '"""Doc."""\npass\n',
])
def test_metadata_profile_refuses_executable_or_additional_source(subject, native, source):
    (subject / "src/bootstrap/__init__.py").write_text(source)
    commit(subject)
    with pytest.raises(native.ArchitectureInventoryError, match="only its docstring"):
        native.build_native_inventory(subject)


@pytest.mark.parametrize("violation", ["exports", "layer", "context", "unobserved", "padded_context"])
def test_metadata_owner_cannot_bypass_existing_scope_or_inferred_ownership(subject, native, violation):
    configuration = config(subject)
    metadata = configuration["architecture"]["package_metadata_ownership"][0]
    diagnostic = {
        "exports": "unsupported metadata exports", "layer": "conflicts with inferred layers",
        "context": "conflicts with inferred contexts", "unobserved": "unobserved or unsupported",
        "padded_context": "canonical metadata context",
    }[violation]
    if violation == "exports":
        metadata["exports"] = ["__doc__", "Thing"]
    elif violation == "layer":
        metadata["layer"] = "domain"
    elif violation == "context":
        target = subject / "src/domain/orders/__init__.py"
        (subject / metadata["path"]).rename(target)
        metadata["path"], metadata["layer"] = "src/domain/orders/__init__.py", "domain"
    elif violation == "unobserved":
        path = subject / "elsewhere/__init__.py"
        path.parent.mkdir()
        path.write_text('"""Outside configured production."""\n')
        metadata["path"] = "elsewhere/__init__.py"
    else:
        metadata["context"] = " bootstrap"
    write_config(subject, configuration)
    commit(subject)
    with pytest.raises(native.ArchitectureInventoryError, match=diagnostic):
        native.build_native_inventory(subject)


@pytest.mark.parametrize("alias", ["leaf", "directory", "hardlink"])
def test_independent_production_admission_refuses_source_aliases(subject, native, alias):
    if alias == "hardlink":
        outside = subject.parent / "other-link.py"
        outside.hardlink_to(subject / "src/loose.py")
        diagnostic = "hardlink alias"
    elif alias == "leaf":
        source = subject / "src/loose.py"
        source.rename(subject / "copied.py")
        source.symlink_to("../copied.py")
        commit(subject)
        diagnostic = "source alias"
    else:
        source = subject / "src/domain/orders"
        source.rename(subject / "orders-real")
        source.symlink_to(subject / "orders-real", target_is_directory=True)
        commit(subject)
        diagnostic = "directory alias"
    with pytest.raises(native.ArchitectureInventoryError, match=diagnostic):
        native.build_native_inventory(subject)


@pytest.mark.parametrize("relative", ["src/loose.py", "architecture-boundaries.yml", "schemas/architecture-boundaries.schema.json"])
def test_native_git_blob_join_refuses_assume_unchanged_source_or_config(subject, native, relative):
    path = subject / relative
    git(subject, "update-index", "--assume-unchanged", relative)
    path.write_bytes(path.read_bytes() + b"\n")
    assert not git(subject, "status", "--porcelain=v1", "--untracked-files=all")
    with pytest.raises(native.ArchitectureInventoryError, match="exact committed subject bytes"):
        native.build_native_inventory(subject)


@pytest.mark.parametrize("relative, diagnostic", [
    ("src/loose.py", "exact committed subject bytes"),
    ("architecture-boundaries.yml", "exact committed subject bytes"),
    ("schemas/architecture-boundaries.schema.json", "exact committed subject bytes"),
])
def test_consuming_native_owner_reauthenticates_current_bytes_even_with_hidden_index_flags(subject, native, relative, diagnostic):
    inventory = native.build_native_inventory(subject)
    git(subject, "update-index", "--assume-unchanged", relative)
    path = subject / relative
    path.write_bytes(path.read_bytes() + b"\n")
    assert not git(subject, "status", "--porcelain=v1", "--untracked-files=all")
    with pytest.raises(native.ArchitectureInventoryError, match=diagnostic):
        native.resolve_native_context(subject, inventory=inventory, kind="qualified_package_metadata_context", version="1.0",
                                      selector="src/bootstrap/__init__.py")


def test_new_committed_member_cannot_reuse_prior_whole_population_binding(subject, native):
    inventory = native.build_native_inventory(subject)
    (subject / "src/new.py").write_text("NEW = 1\n")
    commit(subject)
    with pytest.raises(native.ArchitectureInventoryError, match="cached native inventory differs"):
        native.reauthenticate_inventory(subject, inventory)


@pytest.mark.parametrize("kind, version, selector", [
    ("qualified_package_metadata_context", "2.0", "src/bootstrap/__init__.py"),
    ("qualified_package_metadata_context", "1.0", "src/foreign/__init__.py"),
    ("maintained_native_context_contract", "1.0", "bootstrap"),
])
def test_unknown_owner_or_selector_is_not_native_authority(subject, native, kind, version, selector):
    inventory = native.build_native_inventory(subject)
    assert native.resolve_native_context(subject, inventory=inventory, kind="qualified_package_metadata_context", version="1.0",
                                         selector="src/bootstrap/__init__.py").context == "bootstrap"
    with pytest.raises(native.ArchitectureInventoryError, match="unsupported or unresolved"):
        native.resolve_native_context(subject, inventory=inventory, kind=kind, version=version, selector=selector)


@pytest.mark.parametrize("mutation", ["contexts", "policy", "members", "raw", "observation", "root"])
def test_caller_forged_inventory_never_replaces_fresh_native_derivation(subject, native, mutation):
    inventory = native.build_native_inventory(subject)
    arguments = {"kind": "qualified_package_metadata_context", "version": "1.0",
                 "selector": "src/bootstrap/__init__.py"}
    healthy = native.resolve_native_context(subject, inventory=inventory, **arguments)
    assert healthy.context == "bootstrap"
    if mutation == "contexts":
        forged = replace(inventory, contexts=tuple(
            replace(binding, context="foreign", member_sha256="f" * 64)
            if binding.kind == "qualified_package_metadata_context" else binding
            for binding in inventory.contexts
        ))
    elif mutation == "policy":
        forged = replace(inventory, policy=replace(inventory.policy, source_roots=("../not-a-native-source-root",)))
    elif mutation == "members":
        forged = replace(inventory, members=inventory.members[:-1])
    elif mutation == "raw":
        forged = replace(inventory, members=(replace(inventory.members[0], raw=b"fabricated"), *inventory.members[1:]))
    elif mutation == "observation":
        forged = replace(inventory, observation=replace(inventory.observation, violations=()))
    else:
        forged = replace(inventory, root=subject.parent / "not-the-native-root")
    with pytest.raises(native.ArchitectureInventoryError, match="cached native inventory differs"):
        native.resolve_native_context(subject, inventory=forged, **arguments)
    with pytest.raises(native.ArchitectureInventoryError, match="cached native inventory differs"):
        native.reauthenticate_inventory(subject, forged)
    assert native.resolve_native_context(subject, inventory=inventory, **arguments) == healthy

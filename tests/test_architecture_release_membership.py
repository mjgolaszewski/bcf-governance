"""Real installed bytes and existing closed provider fixtures; no live identity.

All subjects/assets are generated under the fixture root. This source is UNRUN.
No factory, custody owner, source reader or projection function is mocked.
"""
import hashlib
import json
from pathlib import Path
import shutil

import pytest
import yaml

from bcf_governance import __version__
from bcf_governance.tooling import architecture_release_membership as adapter
from bcf_governance.tooling import install_governance_pack as installer
from bcf_governance.tooling.governance_install import release_custody
from bcf_governance.tooling.governance_install.runtime_custody import RUNTIME_LOCK_PATH
from bcf_governance.tooling.architecture_source_components import SourceComponentError
from test_install_release_custody import _Provider, _release_assets, TEMPLATE_ROOT
from test_architecture_native_inventory import commit, git


@pytest.fixture(scope="module")
def installed_release(tmp_path_factory):
    base = tmp_path_factory.mktemp("release_membership")
    assets, digests = _release_assets(base / "assets")
    template = base / "executing-template"
    shutil.copytree(TEMPLATE_ROOT, template)
    target = base / "subject"
    target.mkdir()
    provider = _Provider(digests)
    custody = release_custody.prepare_release_custody(
        assets, installed_version=__version__, template_root=template, token="", api=provider,
    )
    manifest = installer._pack_manifest(template)
    selected = release_custody.selected_runtime_inventory_paths(
        manifest.files, installer.UPGRADE_REFRESH_PATHS,
    )
    for relative in sorted(selected):
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(release_custody._project_bytes(
            custody.released_template_files[relative], {"PLACEHOLDER": "TOKEN"},
        ))
    configuration = yaml.safe_load((template / "architecture-boundaries.yml").read_text())
    architecture = configuration["architecture"]
    architecture["source_roots"] = ["scripts"]
    architecture["package_metadata_ownership"] = []
    (target / "architecture-boundaries.yml").write_text(yaml.safe_dump(configuration))
    release_custody.write_runtime_lock(
        target, custody=custody, manifest_entries=manifest.files,
        upgrade_paths=installer.UPGRADE_REFRESH_PATHS, preserved={},
        placeholder_values={"PLACEHOLDER": "TOKEN"},
    )
    git(target, "init", "--quiet")
    git(target, "config", "user.email", "release-membership@example.invalid")
    git(target, "config", "user.name", "Release Membership Fixture")
    commit(target)
    return target, assets, template, digests


def _query(subject, provider=None):
    target, assets, template, digests = subject
    return adapter.authenticate_release_membership(
        target, assets_root=assets, template_root=template, token="",
        api=provider if provider is not None else _Provider(digests),
    )


def test_existing_owner_authenticates_exact_installed_membership(installed_release):
    target, _, _, _ = installed_release
    result = _query(installed_release)
    lock = json.loads((target / RUNTIME_LOCK_PATH).read_text())
    assert result.release_version == __version__
    assert result.lock_sha256 == hashlib.sha256((target / RUNTIME_LOCK_PATH).read_bytes()).hexdigest()
    assert result.classifications
    assert all(row.ownership == "managed" and lock["files"][row.path] == row.sha256
               for row in result.classifications)


@pytest.mark.parametrize("mutation,diagnostic", [
    ("provenance", "persisted release identity differs"),
    ("omitted-member", "omits or adds maintained release members"),
    ("extra-member", "omits or adds maintained release members"),
    ("edited-and-rehashed-source", "differs from canonical installer projection"),
    ("adaptation", "adaptation inventory differs"),
    ("duplicate-lock-field", "duplicate JSON field"),
    ("candidate-marker", "candidate qualification has no immutable release authority"),
    ("manifest-metadata", "pack manifest differs from authenticated wheel"),
    ("forged-preservation-one", "consumer preservation requires independent maintained authority"),
    ("forged-preservation-all-runtime", "consumer preservation requires independent maintained authority"),
])
def test_persisted_claims_cannot_replace_release_owner(installed_release, mutation, diagnostic):
    target, _, template, _ = installed_release
    lock_path = target / RUNTIME_LOCK_PATH
    originals = {lock_path: lock_path.read_bytes()}
    payload = json.loads(originals[lock_path])
    created = []
    if mutation == "provenance": payload["release_id"] += 1
    elif mutation == "omitted-member": payload["files"].pop(next(iter(payload["files"])))
    elif mutation == "extra-member":
        path = target / "scripts/_bcf_runtime/unexplained.py"
        path.write_bytes(b"VALUE = 1\n")
        created.append(path)
        payload["files"][path.relative_to(target).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    elif mutation == "edited-and-rehashed-source":
        relative = "scripts/_bcf_runtime/__init__.py"
        path = target / relative
        originals[path] = path.read_bytes()
        path.write_bytes(originals[path] + b"UNRELEASED = True\n")
        payload["files"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    elif mutation == "adaptation": payload["official_installer_adaptations"] = {}
    elif mutation.startswith("forged-preservation-"):
        relative = "scripts/_bcf_runtime/__init__.py"
        path = target / relative
        originals[path] = path.read_bytes()
        path.write_bytes(originals[path] + b"UNRELEASED = True\n")
        payload["files"][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        moved = ([relative] if mutation == "forged-preservation-one" else
                 [name for name in payload["files"] if name.startswith("scripts/_bcf_runtime/")])
        for name in moved:
            payload["preserved_consumer_files"][name] = payload["files"].pop(name)
            payload["official_installer_adaptations"].pop(name, None)
    elif mutation == "candidate-marker":
        path = target / "governance/bcf-candidate-qualification.json"
        path.write_text("{}\n")
        created.append(path)
    elif mutation == "manifest-metadata":
        path = template / ".bcf-pack-manifest.json"
        originals[path] = path.read_bytes()
        manifest = json.loads(originals[path])
        manifest["files"][next(iter(manifest["files"]))]["operation"] = "preserve"
        path.write_text(json.dumps(manifest))
    elif mutation != "duplicate-lock-field": raise AssertionError(mutation)
    lock_path.write_text(json.dumps(payload))
    if mutation == "duplicate-lock-field":
        raw = lock_path.read_text()
        lock_path.write_text('{"version":"duplicate",' + raw[1:])
    commit(target)
    try:
        with pytest.raises(SourceComponentError, match=diagnostic) as failure:
            _query(installed_release)
        assert any(entry.name == "authenticate_release_membership" or entry.name == "_unique_object" or entry.name == "bound_wheel_manifest"
                   for entry in failure.traceback)
    finally:
        for path, raw in originals.items(): path.write_bytes(raw)
        for path in created: path.unlink()
        commit(target)
    assert _query(installed_release).release_version == __version__


@pytest.mark.parametrize("mutation", ["missing", "symlink"])
def test_missing_or_aliased_lock_never_means_project_owned(installed_release, mutation):
    target, _, _, _ = installed_release
    path = target / RUNTIME_LOCK_PATH
    original = path.read_bytes()
    path.unlink()
    if mutation == "symlink": path.symlink_to("../architecture-boundaries.yml")
    commit(target)
    try:
        if mutation == "missing":
            with pytest.raises(FileNotFoundError) as failure:
                _query(installed_release)
            assert failure.value.filename == str(path)
        else:
            with pytest.raises(ValueError, match="policy input must have a canonical absolute path") as failure:
                _query(installed_release)
        assert any(entry.name == "_read" for entry in failure.traceback)
    finally:
        if path.is_symlink(): path.unlink()
        path.write_bytes(original)
        commit(target)
    assert _query(installed_release).release_version == __version__


@pytest.mark.parametrize("binding_state", ["exact", "null", "stale"])
def test_native_compiler_joins_real_release_before_managed_requests(installed_release, binding_state):
    from bcf_governance.tooling import architecture_membership_compilation as compiler
    target, assets, template, digests = installed_release
    config_path = target / "architecture-boundaries.yml"
    original = config_path.read_bytes()
    payload = yaml.safe_load(original)
    architecture = payload["architecture"]
    architecture["bounded_contexts"]["context_root_tokens"].append("scripts")
    architecture["layers"]["tooling"] = {
        "path_tokens": ["tools"], "required": False,
        "forbidden_import_prefixes": [], "forbidden_layer_imports": [],
        "forbidden_import_names": [],
    }
    path = "scripts/_bcf_runtime/__init__.py"
    lock_digest = hashlib.sha256((target / RUNTIME_LOCK_PATH).read_bytes()).hexdigest()
    binding = {"runtime_lock_path": RUNTIME_LOCK_PATH, "runtime_lock_sha256": lock_digest}
    if binding_state == "null": binding = None
    elif binding_state == "stale": binding["runtime_lock_sha256"] = "0" * 64
    architecture["source_component_ownership"] = {"version": "1.0", "components": [{
        "id": "runtime-package", "layer": "tooling", "context": "_bcf_runtime",
        "rationale": "One exact authenticated installed source member",
        "members": {path: hashlib.sha256((target / path).read_bytes()).hexdigest()},
        "managed_pack": binding,
        "context_authority": {"kind": "independently_inferred_inventory",
                              "version": "1.0", "selector": "_bcf_runtime"},
    }]}
    config_path.write_text(yaml.safe_dump(payload))
    commit(target)
    inputs = compiler.NativeReleaseInputs(assets, template, api=_Provider(digests))
    try:
        if binding_state == "exact":
            result = compiler.build_effective_inventory(target, release_inputs=inputs)
            assert result.release is not None and result.release.lock_sha256 == lock_digest
            assert result.projection.raw_observation is result.native.observation
            assigned = [row for row in result.projection.members if row.component_id is not None]
            assert len(assigned) == 1 and assigned[0].path == path
            assert assigned[0].effective_layers == ("tooling",)
            compiler.reauthenticate_effective_inventory(target, result, release_inputs=inputs)
            installed = compiler.build_effective_inventory(target)
            assert installed.release is None and installed.installed is not None
            assert installed.installed.lock_sha256 == lock_digest
            assert installed.projection == result.projection
            compiler.reauthenticate_effective_inventory(target, installed)
            from bcf_governance.tooling.architecture_native_gate import compile_gate_ownership
            from bcf_governance.tooling.architecture_release_context import released_native_membership
            with released_native_membership(target, assets_root=assets, template_root=template,
                                            api=_Provider(digests)) as owned:
                consumed = compile_gate_ownership(target, release_inputs=owned)
                assert consumed.release == result.release and consumed.candidate is None
                assert consumed.projection == result.projection

        else:
            with pytest.raises(SourceComponentError, match="managed declaration differs") as failure:
                compiler.build_effective_inventory(target, release_inputs=inputs)
            assert any(entry.name == "_reduce_membership" for entry in failure.traceback)
    finally:
        config_path.write_bytes(original)
        commit(target)
    assert _query(installed_release).release_version == __version__


def test_installed_membership_needs_no_supplier_assets_token_or_provider(installed_release, monkeypatch):
    target, assets, _, _ = installed_release

    def forbidden(*args, **kwargs):
        raise AssertionError("installed validation must never authenticate against supplier")

    monkeypatch.setattr(adapter, "prepare_release_custody", forbidden)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    unavailable = assets.with_name(assets.name + "-unavailable")
    assets.rename(unavailable)
    try:
        result = adapter.inspect_installed_membership(target)
        assert result.classifications
        assert all(row.ownership == "managed" for row in result.classifications)
        assert not hasattr(result, "release_commit")
        assert adapter.inspect_installed_membership(target) == result
        captured = release_custody.capture_installed_runtime(
            target, expected_version=__version__,
            schema_path=target / "schemas/bcf-runtime-lock.schema.json",
        )
        assert captured["acquisition"] == "native_installed_runtime_integrity"
        assert captured["runtime_lock_sha256"] == result.lock_sha256
        assert {row.path for row in result.classifications} <= set(captured["files"])
    finally:
        unavailable.rename(assets)


@pytest.mark.parametrize("mutation", ["bytes", "unexplained-runtime", "reclassified-runtime", "candidate"])
def test_local_installed_membership_rejects_actual_drift(installed_release, mutation):
    target, _, _, _ = installed_release
    path = target / "scripts/_bcf_runtime/__init__.py"
    lock_path = target / RUNTIME_LOCK_PATH
    original_source, original_lock = path.read_bytes(), lock_path.read_bytes()
    added = None
    if mutation == "bytes":
        path.write_bytes(original_source + b"DRIFT = True\n")
    elif mutation == "unexplained-runtime":
        added = target / "scripts/_bcf_runtime/unexplained.py"
        added.write_text("VALUE = 1\n")
    elif mutation == "reclassified-runtime":
        payload = json.loads(original_lock)
        relative = path.relative_to(target).as_posix()
        payload["preserved_consumer_files"][relative] = payload["files"].pop(relative)
        payload["official_installer_adaptations"].pop(relative, None)
        lock_path.write_text(json.dumps(payload))
    else:
        added = target / "governance/bcf-candidate-qualification.json"
        added.write_text("{}\n")
    commit(target)
    try:
        with pytest.raises(SourceComponentError):
            adapter.inspect_installed_membership(target)
    finally:
        path.write_bytes(original_source)
        lock_path.write_bytes(original_lock)
        if added is not None:
            added.unlink()
        commit(target)

"""Adoption reuses complete local dependency closures without installing them."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from bcf_governance.tooling import semantic_adoption_dependencies as dependencies
from bcf_governance.tooling.semantic_ownership_typescript import TypeScriptContract


def _contract(prefix: str = "") -> TypeScriptContract:
    return TypeScriptContract("node", prefix + "tsconfig.json", prefix + "package-lock.json", ("src",), ())


def _fixture(tmp_path: Path, prefixes: tuple[str, ...] = ("",)):
    root, shadow = tmp_path / "consumer", tmp_path / "shadow"
    root.mkdir()
    shadow.mkdir()
    for prefix in prefixes:
        package = root / prefix
        package.mkdir(exist_ok=True, parents=True)
        lock = {"packages": {"node_modules/typescript": {"version": "6.0.3"}}}
        (package / "package-lock.json").write_text(json.dumps(lock))
        compiler = package / "node_modules/typescript"
        (compiler / "lib").mkdir(parents=True)
        (compiler / "package.json").write_text(json.dumps({"version": "6.0.3"}))
        (compiler / "lib/typescript.js").write_text("exports.version = '6.0.3';\n")
        (compiler / "lib/tsc.js").write_text("#!/usr/bin/env node\n")
        (compiler / "lib/tsc.js").chmod(0o755)
        typing = package / "node_modules/@consumer/shared-types"
        typing.mkdir(parents=True)
        (typing / "index.d.ts").write_text("export interface Request { id: string }\n")
        binary = package / "node_modules/.bin"
        binary.mkdir()
        (binary / "tsc").symlink_to("../typescript/lib/tsc.js")
        (shadow / prefix).mkdir(exist_ok=True, parents=True)
        shutil.copyfile(package / "package-lock.json", shadow / prefix / "package-lock.json")
    return root, shadow, tuple(_contract(prefix) for prefix in prefixes)


def test_copies_complete_dependencies_per_package_root_without_mutating_original(tmp_path) -> None:
    root, shadow, contracts = _fixture(tmp_path, ("", "frontend/"))
    originals = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    snapshot = dependencies.snapshot_adoption_dependencies(root, shadow, contracts + contracts)
    assert len(snapshot.trees) == 2
    for prefix in ("", "frontend/"):
        copied = shadow / prefix / "node_modules"
        assert (copied / "@consumer/shared-types/index.d.ts").read_bytes() == (
            root / prefix / "node_modules/@consumer/shared-types/index.d.ts"
        ).read_bytes()
        assert (copied / ".bin/tsc").is_symlink()
        assert os.readlink(copied / ".bin/tsc") == "../typescript/lib/tsc.js"
        assert (copied / ".bin/tsc").resolve().is_relative_to(shadow)
        assert (copied / "typescript/lib/tsc.js").stat().st_mode & 0o777 == 0o755
    snapshot.validate_unchanged()
    assert originals == {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}


def test_no_typescript_contract_needs_no_dependencies(tmp_path) -> None:
    root, shadow = tmp_path / "root", tmp_path / "shadow"
    root.mkdir()
    shadow.mkdir()
    snapshot = dependencies.snapshot_adoption_dependencies(root, shadow, ())
    snapshot.validate_unchanged()
    assert list(shadow.iterdir()) == []


@pytest.mark.parametrize("link_kind", ["package_directory", "package_json", "compiler_file"])
def test_internal_compiler_links_are_preserved_and_validated(tmp_path, link_kind) -> None:
    root, shadow, contracts = _fixture(tmp_path)
    modules = root / "node_modules"
    store = modules / ".store"
    store.mkdir()
    relative = {
        "package_directory": "typescript", "package_json": "typescript/package.json",
        "compiler_file": "typescript/lib/typescript.js",
    }[link_kind]
    original = modules / relative
    destination = store / original.name
    original.rename(destination)
    original.symlink_to(os.path.relpath(destination, original.parent), target_is_directory=link_kind == "package_directory")
    snapshot = dependencies.snapshot_adoption_dependencies(root, shadow, contracts)
    copied = shadow / "node_modules" / relative
    assert copied.is_symlink()
    assert os.readlink(copied) == os.readlink(original)
    assert copied.resolve().is_relative_to(shadow / "node_modules")
    snapshot.validate_unchanged()


@pytest.mark.parametrize("link_kind", ["absolute_inside", "relative_escape", "indirect_absolute"])
def test_unsafe_compiler_links_are_rejected_before_reading(tmp_path, link_kind) -> None:
    root, shadow, contracts = _fixture(tmp_path)
    modules = root / "node_modules"
    compiler = modules / "typescript"
    actual = modules / "real-typescript"
    compiler.rename(actual)
    if link_kind == "absolute_inside":
        target = str(actual)
    elif link_kind == "relative_escape":
        actual.rename(root / "outside-typescript")
        target = "../outside-typescript"
    else:
        (modules / "intermediate").symlink_to(str(actual), target_is_directory=True)
        target = "intermediate"
    compiler.symlink_to(target, target_is_directory=True)
    with pytest.raises(dependencies.SemanticDependencyError, match="symlink"):
        dependencies.snapshot_adoption_dependencies(root, shadow, contracts)
    assert not (shadow / "node_modules").exists()


@pytest.mark.parametrize("bad_link", ["absolute", "escaping", "missing", "cycle", "indirect_escape"])
def test_unsafe_dependency_links_are_rejected_before_copy(tmp_path, bad_link) -> None:
    root, shadow, contracts = _fixture(tmp_path)
    modules = root / "node_modules"
    external = root / "outside.d.ts"
    external.write_text("outside")
    if bad_link == "absolute":
        target = str(modules / "typescript/lib/tsc.js")
    elif bad_link == "escaping":
        target = "../outside.d.ts"
    elif bad_link == "missing":
        target = "missing.d.ts"
    elif bad_link == "cycle":
        target = "bad"
    else:
        (modules / "escape").symlink_to("../outside.d.ts")
        target = "escape"
    (modules / "bad").symlink_to(target)
    with pytest.raises(dependencies.SemanticDependencyError, match="symlink"):
        dependencies.snapshot_adoption_dependencies(root, shadow, contracts)
    assert not (shadow / "node_modules").exists()


@pytest.mark.parametrize("missing", ["package-lock.json", "node_modules", "node_modules/typescript/lib/typescript.js"])
def test_missing_installed_inputs_fail_closed(tmp_path, missing) -> None:
    root, shadow, contracts = _fixture(tmp_path)
    path = root / missing
    shutil.rmtree(path) if path.is_dir() else path.unlink()
    with pytest.raises(dependencies.SemanticDependencyError):
        dependencies.snapshot_adoption_dependencies(root, shadow, contracts)
    assert not (shadow / "node_modules").exists()


@pytest.mark.parametrize("lock", [{}, {"packages": {}}, {"packages": {"node_modules/typescript": {"version": "5.0"}}}])
def test_compiler_and_declared_lock_must_agree(tmp_path, lock) -> None:
    root, shadow, contracts = _fixture(tmp_path)
    (root / "package-lock.json").write_text(json.dumps(lock))
    with pytest.raises(dependencies.SemanticDependencyError, match="pin|differ"):
        dependencies.snapshot_adoption_dependencies(root, shadow, contracts)


@pytest.mark.parametrize("side", ["consumer", "shadow"])
@pytest.mark.parametrize("change", ["types", "compiler", "lock", "link", "new_file", "mode"])
def test_dependency_drift_is_rejected_before_contract_promotion(tmp_path, side, change) -> None:
    root, shadow, contracts = _fixture(tmp_path)
    snapshot = dependencies.snapshot_adoption_dependencies(root, shadow, contracts)
    target = tmp_path / side
    if change == "lock":
        path = target / "package-lock.json"
        path.write_text(path.read_text() + "\n")
    elif change == "link":
        path = target / "node_modules/.bin/tsc"
        path.unlink()
        path.symlink_to("../typescript/lib/typescript.js")
    elif change == "mode":
        (target / "node_modules/typescript/lib/tsc.js").chmod(0o644)
    else:
        name = {"types": "@consumer/shared-types/index.d.ts", "compiler": "typescript/lib/typescript.js", "new_file": "new.d.ts"}[change]
        (target / "node_modules" / name).write_text("changed\n")
    with pytest.raises(dependencies.SemanticDependencyError, match="changed during adoption"):
        snapshot.validate_unchanged()


def test_existing_shadow_dependencies_cannot_be_silently_merged(tmp_path) -> None:
    root, shadow, contracts = _fixture(tmp_path)
    (shadow / "node_modules").mkdir()
    with pytest.raises(dependencies.SemanticDependencyError, match="already exists"):
        dependencies.snapshot_adoption_dependencies(root, shadow, contracts)


def test_original_and_shadow_lock_bytes_must_match(tmp_path) -> None:
    root, shadow, contracts = _fixture(tmp_path)
    path = shadow / "package-lock.json"
    path.write_text(path.read_text() + "\n")
    with pytest.raises(dependencies.SemanticDependencyError, match="package lock changed"):
        dependencies.snapshot_adoption_dependencies(root, shadow, contracts)


def test_package_root_symlinks_are_not_followed(tmp_path) -> None:
    root, shadow, contracts = _fixture(tmp_path, ("frontend/",))
    (root / "frontend").rename(root / "actual")
    (root / "frontend").symlink_to("actual", target_is_directory=True)
    with pytest.raises(dependencies.SemanticDependencyError, match="crosses a symlink"):
        dependencies.snapshot_adoption_dependencies(root, shadow, contracts)


def test_special_dependency_files_are_rejected(tmp_path) -> None:
    root, shadow, contracts = _fixture(tmp_path)
    os.mkfifo(root / "node_modules/pipe")
    with pytest.raises(dependencies.SemanticDependencyError, match="unsupported"):
        dependencies.snapshot_adoption_dependencies(root, shadow, contracts)


def test_copy_time_dependency_mutation_is_rejected(tmp_path, monkeypatch) -> None:
    root, shadow, contracts = _fixture(tmp_path)
    copytree = dependencies.shutil.copytree

    def changing_copy(*args, **kwargs):
        result = copytree(*args, **kwargs)
        (root / "node_modules/typescript/lib/typescript.js").write_text("changed")
        return result

    monkeypatch.setattr(dependencies.shutil, "copytree", changing_copy)
    with pytest.raises(dependencies.SemanticDependencyError, match="changed during adoption"):
        dependencies.snapshot_adoption_dependencies(root, shadow, contracts)


@pytest.mark.parametrize("lock", ["../package-lock.json", "/package-lock.json"])
def test_declared_lock_paths_cannot_escape_the_repository(tmp_path, lock) -> None:
    root, shadow, _ = _fixture(tmp_path)
    contract = TypeScriptContract("node", "tsconfig.json", lock, ("src",), ())
    with pytest.raises(dependencies.SemanticDependencyError, match="inside"):
        dependencies.snapshot_adoption_dependencies(root, shadow, (contract,))

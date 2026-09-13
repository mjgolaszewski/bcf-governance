"""Exercise the real locked offline compiler and fail closed before installation."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github/scripts/bootstrap_test_toolchain.py"
SPEC = importlib.util.spec_from_file_location("test_toolchain_bootstrap", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("the locked test toolchain must not request network access")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(ROOT / BOOTSTRAP.FIXTURE, root / BOOTSTRAP.FIXTURE,
                    ignore=shutil.ignore_patterns("node_modules", "__pycache__"))
    return root


def _json(path: Path, edit) -> None:
    data = json.loads(path.read_text())
    edit(data)
    path.write_text(json.dumps(data))


def _archive(fixture: Path, members: list[tuple[str, bytes | str]]) -> None:
    archive = fixture / "typescript-6.0.3.tgz"
    with tarfile.open(archive, "w:gz") as output:
        for name, value in members:
            info = tarfile.TarInfo(name)
            if isinstance(value, str):
                info.type = tarfile.SYMTYPE; info.linkname = value
                output.addfile(info)
            else:
                info.size = len(value); output.addfile(info, io.BytesIO(value))
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode()
    _json(fixture / "package-lock.json", lambda lock: lock["packages"]["node_modules/typescript"].update(integrity=integrity))


def _snapshot(root: Path) -> dict:
    return {str(path.relative_to(root)): (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
            for path in sorted(root.rglob("*")) if path.is_file() and not path.is_symlink()}


def test_fresh_offline_bootstrap_installs_real_compiler_and_declared_types(repository: Path) -> None:
    fixture = repository / BOOTSTRAP.FIXTURE
    assert not (fixture / "node_modules").exists()
    report = BOOTSTRAP.bootstrap(repository)
    assert report["status"] == "test_toolchain_ready" and report["network_requests"] == 0
    assert report["node_version"] == "v22.23.2" and report["typescript_version"] == "6.0.3"
    assert report["compiler_files"] > 100
    assert BOOTSTRAP._tree(fixture / "node_modules/@bcf-test/declared-types") == BOOTSTRAP._tree(fixture / "declared-types")
    source = fixture / "fixture.ts"
    source.write_text("import type { DeclaredValue } from '@bcf-test/declared-types';\nconst value: DeclaredValue = { value: 1 };\n")
    command = [shutil.which("node"), str(fixture / "node_modules/typescript/bin/tsc"),
               "--noEmit", "--strict", str(source)]
    result = subprocess.run(command, cwd=fixture, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    source.write_text(source.read_text().replace("value: 1", "value: 'wrong'"))
    rejected = subprocess.run(command, cwd=fixture, capture_output=True, text=True)
    assert rejected.returncode == 2 and "not assignable to type 'number'" in rejected.stdout
    before = _snapshot(repository)
    checked = subprocess.run([sys.executable, str(SCRIPT), "--repo-root", str(repository), "--check"],
                             capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr
    assert json.loads(checked.stdout)["status"] == "test_toolchain_checked"
    assert _snapshot(repository) == before
    BOOTSTRAP.bootstrap(repository)
    assert _snapshot(repository) == before


@pytest.mark.parametrize("case", ["archive", "integrity"])
def test_changed_archive_or_lock_integrity_is_rejected_before_install(repository: Path, case: str) -> None:
    fixture = repository / BOOTSTRAP.FIXTURE
    if case == "archive":
        with (fixture / "typescript-6.0.3.tgz").open("ab") as output: output.write(b"changed")
    else:
        _json(fixture / "package-lock.json", lambda lock: lock["packages"]["node_modules/typescript"].update(integrity="sha512-incorrect"))
    with pytest.raises(ValueError, match="npm lock integrity"): BOOTSTRAP.bootstrap(repository)
    assert not (fixture / "node_modules").exists()


def test_archive_parser_consumes_only_the_bytes_whose_integrity_was_verified(repository: Path, monkeypatch) -> None:
    fixture = repository / BOOTSTRAP.FIXTURE
    _archive(fixture, [("package/payload", b"verified bytes")])
    archive = fixture / "typescript-6.0.3.tgz"
    integrity = json.loads((fixture / "package-lock.json").read_text())["packages"]["node_modules/typescript"]["integrity"]
    regular = BOOTSTRAP._regular
    def replaced_after_read(path):
        data = regular(path)
        _archive(fixture, [("package/payload", b"unchecked replacement")])
        return data
    monkeypatch.setattr(BOOTSTRAP, "_regular", replaced_after_read)
    assert BOOTSTRAP._compiler_files(archive, integrity) == {"payload": b"verified bytes"}


@pytest.mark.parametrize("package", [{"name": "typescript", "version": "0.0.0"},
                                    {"name": "substitute", "version": "6.0.3"}])
def test_archive_identity_must_match_the_exact_locked_compiler(repository: Path, package: dict) -> None:
    fixture = repository / BOOTSTRAP.FIXTURE
    _archive(fixture, [("package/package.json", json.dumps(package).encode())])
    with pytest.raises(ValueError, match="archive package version differs"): BOOTSTRAP.bootstrap(repository)
    assert not (fixture / "node_modules").exists()


@pytest.mark.parametrize("members", [
    [("package/../../outside", b"escape")], [("/outside", b"escape")],
    [("package/link", "../../outside")], [("package/a", b"one"), ("package/a", b"two")],
    [("package/a\\b", b"ambiguous")], [("other/package.json", b"{}")],
])
def test_matching_integrity_does_not_authorize_unsafe_archive_members(repository: Path, members) -> None:
    fixture = repository / BOOTSTRAP.FIXTURE; _archive(fixture, members)
    with pytest.raises(ValueError, match="unsafe member|non-regular member|ambiguous member"):
        BOOTSTRAP.bootstrap(repository)
    assert not (fixture / "node_modules").exists()


@pytest.mark.parametrize("case", ["version", "resolved", "root-dependencies", "unsafe-version"])
def test_manifest_and_npm_lock_must_bind_one_exact_compiler(repository: Path, case: str) -> None:
    fixture = repository / BOOTSTRAP.FIXTURE
    def edit(lock):
        row = lock["packages"]["node_modules/typescript"]
        if case == "version": row["version"] = "0.0.0"
        elif case == "resolved": row["resolved"] = "https://example.test/substitute.tgz"
        elif case == "root-dependencies": lock["packages"][""]["dependencies"]["typescript"] = "latest"
        else: row["version"] = "../../outside"
    _json(fixture / "package-lock.json", edit)
    with pytest.raises(ValueError, match="manifest and lock differ"): BOOTSTRAP.bootstrap(repository)
    assert not (fixture / "node_modules").exists()


@pytest.mark.parametrize("case", ["name", "version", "types", "resolved", "dependency"])
def test_local_declaration_contract_is_validated_before_any_install(repository: Path, case: str) -> None:
    fixture = repository / BOOTSTRAP.FIXTURE
    if case in {"name", "version", "types"}:
        _json(fixture / "declared-types/package.json", lambda package: package.update({case: "substitute"}))
    elif case == "resolved":
        _json(fixture / "package-lock.json", lambda lock: lock["packages"]["node_modules/@bcf-test/declared-types"].update(resolved="file:elsewhere"))
    else:
        _json(fixture / "package.json", lambda package: package["dependencies"].update({"@bcf-test/declared-types": "file:elsewhere"}))
        _json(fixture / "package-lock.json", lambda lock: lock["packages"][""]["dependencies"].update({"@bcf-test/declared-types": "file:elsewhere"}))
    with pytest.raises(ValueError, match="local declarations differ"): BOOTSTRAP.bootstrap(repository)
    assert not (fixture / "node_modules").exists()


@pytest.mark.parametrize("case", ["missing", "wrong"])
def test_missing_or_wrong_node_fails_without_skipping_or_installing(repository: Path, monkeypatch, case: str) -> None:
    if case == "missing": monkeypatch.setattr(BOOTSTRAP.shutil, "which", lambda name: None)
    else:
        monkeypatch.setattr(BOOTSTRAP.subprocess, "run", lambda *args, **kwargs:
                            subprocess.CompletedProcess(args[0], 0, stdout="v20.0.0\n", stderr=""))
    with pytest.raises(ValueError, match="requires Node v22.23.2"): BOOTSTRAP.bootstrap(repository)
    assert not (repository / BOOTSTRAP.FIXTURE / "node_modules").exists()


@pytest.mark.parametrize("relative", [
    "tests", "tests/fixtures", "tests/fixtures/typescript-toolchain",
    "tests/fixtures/typescript-toolchain/node_modules",
    "tests/fixtures/typescript-toolchain/node_modules/@bcf-test",
    "tests/fixtures/typescript-toolchain/node_modules/typescript",
    "tests/fixtures/typescript-toolchain/node_modules/@bcf-test/declared-types",
    "tests/fixtures/typescript-toolchain/declared-types",
    "tests/fixtures/typescript-toolchain/declared-types/index.d.ts",
    "tests/fixtures/typescript-toolchain/typescript-6.0.3.tgz",
])
def test_symlink_inputs_and_installation_paths_cannot_escape_repository(repository: Path, relative: str) -> None:
    path = repository / relative; outside = repository.parent / "outside"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists(): path.rename(outside)
    else: outside.mkdir()
    path.symlink_to(outside, target_is_directory=outside.is_dir())
    before = _snapshot(outside) if outside.is_dir() else outside.read_bytes()
    with pytest.raises(ValueError, match="symlink|regular file|not a directory"):
        BOOTSTRAP.bootstrap(repository)
    assert (_snapshot(outside) if outside.is_dir() else outside.read_bytes()) == before


@pytest.mark.parametrize("package", ["typescript", "@bcf-test/declared-types"])
def test_dangling_install_target_symlinks_are_rejected(repository: Path, package: str) -> None:
    path = repository / BOOTSTRAP.FIXTURE / "node_modules" / package
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(repository.parent / "missing", target_is_directory=True)
    with pytest.raises(ValueError, match="cannot be a symlink"): BOOTSTRAP.bootstrap(repository)
    assert path.is_symlink() and not (repository.parent / "missing").exists()


@pytest.mark.parametrize("package,file", [("typescript", "lib/typescript.js"),
                                         ("@bcf-test/declared-types", "index.d.ts")])
def test_check_never_repairs_stale_packages_but_bootstrap_restores_exact_bytes(repository: Path, package: str, file: str) -> None:
    BOOTSTRAP.bootstrap(repository)
    target = repository / BOOTSTRAP.FIXTURE / "node_modules" / package / file
    original = target.read_bytes(); target.write_bytes(b"stale")
    before = _snapshot(repository)
    with pytest.raises(ValueError, match="missing or stale"): BOOTSTRAP.bootstrap(repository, check=True)
    assert _snapshot(repository) == before
    BOOTSTRAP.bootstrap(repository)
    assert target.read_bytes() == original


def test_check_missing_toolchain_has_no_installation_side_effect(repository: Path) -> None:
    before = _snapshot(repository)
    with pytest.raises(ValueError, match="missing or stale"): BOOTSTRAP.bootstrap(repository, check=True)
    assert _snapshot(repository) == before
    assert not (repository / BOOTSTRAP.FIXTURE / "node_modules").exists()

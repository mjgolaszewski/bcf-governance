"""Materialize the locked real TypeScript test compiler without network or npm hooks."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile


NODE_VERSION = "v22.23.2"
FIXTURE = Path("tests/fixtures/typescript-toolchain")


def _regular(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"test toolchain input is not a regular file: {path}")
    return path.read_bytes()


def _tree(root: Path) -> dict[str, bytes]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"test toolchain package is not a directory: {root}")
    values = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"test toolchain package contains a symlink: {path}")
        if path.is_file():
            values[path.relative_to(root).as_posix()] = _regular(path)
        elif not path.is_dir():
            raise ValueError(f"test toolchain package contains a special file: {path}")
    return values


def _compiler_files(archive: Path, integrity: str) -> dict[str, bytes]:
    data = _regular(archive)
    algorithm, expected = integrity.split("-", 1)
    if algorithm != "sha512" or base64.b64encode(hashlib.sha512(data).digest()).decode() != expected:
        raise ValueError("test compiler archive differs from the npm lock integrity")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as source:
        for member in source.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "package":
                raise ValueError("test compiler archive has an unsafe member")
            if member.isdir():
                continue
            if not member.isfile() or len(path.parts) < 2:
                raise ValueError("test compiler archive has a non-regular member")
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            if relative in files or "\\" in relative:
                raise ValueError("test compiler archive has an ambiguous member")
            handle = source.extractfile(member)
            if handle is None:
                raise ValueError("test compiler archive member is unreadable")
            files[relative] = handle.read()
    return files


def _install_package(target: Path, files: dict[str, bytes], *, check: bool) -> None:
    if target.is_symlink():
        raise ValueError(f"test toolchain package cannot be a symlink: {target}")
    if target.exists() and _tree(target) == files:
        return
    if check:
        raise ValueError(f"test toolchain is missing or stale; bootstrap it before tests: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".bcf-toolchain-", dir=target.parent) as temporary:
        staged = Path(temporary) / "package"
        staged.mkdir()
        for relative, data in files.items():
            path = staged / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        backup = Path(temporary) / "previous"
        if target.exists():
            target.rename(backup)
        try:
            staged.rename(target)
        except BaseException:
            if backup.exists():
                backup.rename(target)
            raise


def bootstrap(repo_root: Path, *, check: bool = False) -> dict[str, object]:
    root = repo_root.resolve()
    fixture = root / FIXTURE
    parents = [root.joinpath(*FIXTURE.parts[:index]) for index in range(1, len(FIXTURE.parts) + 1)]
    for parent in (*parents, fixture / "node_modules", fixture / "node_modules/@bcf-test"):
        if parent.is_symlink():
            raise ValueError(f"test toolchain path cannot be a symlink: {parent}")
    lock_bytes = _regular(fixture / "package-lock.json")
    lock = json.loads(lock_bytes)
    row = lock["packages"]["node_modules/typescript"]
    manifest = json.loads(_regular(fixture / "package.json"))
    if (not isinstance(row["version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", row["version"])
            or row["version"] != manifest["dependencies"]["typescript"]
            or row["resolved"] != f"https://registry.npmjs.org/typescript/-/typescript-{row['version']}.tgz"
            or lock["packages"][""]["dependencies"] != manifest["dependencies"]):
        raise ValueError("test compiler manifest and lock differ")
    node = shutil.which("node")
    if node is None:
        raise ValueError(f"test toolchain requires Node {NODE_VERSION}")
    version = subprocess.run([node, "--version"], capture_output=True, text=True, check=True).stdout.strip()
    if version != NODE_VERSION:
        raise ValueError(f"test toolchain requires Node {NODE_VERSION}; observed {version}")
    archive = fixture / f"typescript-{row['version']}.tgz"
    files = _compiler_files(archive, row["integrity"])
    compiler = json.loads(files["package.json"])
    if compiler["name"] != "typescript" or compiler["version"] != row["version"]:
        raise ValueError("test compiler archive package version differs")
    declaration_files = _tree(fixture / "declared-types")
    declaration = json.loads(declaration_files["package.json"])
    local = lock["packages"]["node_modules/@bcf-test/declared-types"]
    if (manifest["dependencies"]["@bcf-test/declared-types"] != "file:declared-types"
            or local["resolved"] != "file:declared-types"
            or declaration["name"] != "@bcf-test/declared-types"
            or declaration["version"] != local["version"]
            or declaration["types"] not in declaration_files):
        raise ValueError("test local declarations differ from the manifest or lock")
    installed = fixture / "node_modules"
    if installed.is_symlink():
        raise ValueError("test toolchain node_modules cannot be a symlink")
    _install_package(installed / "typescript", files, check=check)
    _install_package(installed / "@bcf-test/declared-types", declaration_files, check=check)
    return {
        "status": "test_toolchain_checked" if check else "test_toolchain_ready",
        "node_version": version,
        "node_executable_sha256": hashlib.sha256(Path(node).resolve().read_bytes()).hexdigest(),
        "typescript_version": row["version"],
        "archive_sha256": hashlib.sha256(_regular(archive)).hexdigest(),
        "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "compiler_files": len(files),
        "network_requests": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        report = bootstrap(args.repo_root, check=args.check)
    except (ValueError, KeyError, OSError, tarfile.TarError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"test-toolchain-failed: {exc}\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()

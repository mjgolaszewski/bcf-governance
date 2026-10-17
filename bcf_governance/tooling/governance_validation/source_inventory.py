"""Prove that a source distribution contains its Git-owned source checkout."""

from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath
import subprocess
import tarfile
import hashlib
from glob import glob
import tomllib
import zipfile


def tracked_source_inventory(repo_root: Path) -> frozenset[str]:
    """Return the exact Git-owned source inventory."""

    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise ValueError("source inventory requires Git custody")
    values = result.stdout.split(b"\0")
    if values and values[-1] == b"":
        values.pop()
    try:
        tracked = frozenset(value.decode("utf-8") for value in values)
    except UnicodeDecodeError as exc:
        raise ValueError("tracked source path is not UTF-8") from exc
    if not tracked:
        raise ValueError("source inventory is empty")
    return tracked


def sdist_source_inventory(sdist: Path) -> frozenset[str]:
    """Return safe regular-file paths beneath an archive's single source root."""

    try:
        with tarfile.open(sdist, "r:gz") as archive:
            members = archive.getmembers()
    except (OSError, tarfile.TarError) as exc:
        raise ValueError("source archive is unreadable") from exc
    roots: set[str] = set()
    files: set[str] = set()
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or len(path.parts) < 1:
            raise ValueError("source archive contains an unsafe path")
        roots.add(path.parts[0])
        if member.isfile() and len(path.parts) > 1:
            files.add(PurePosixPath(*path.parts[1:]).as_posix())
    if len(roots) != 1:
        raise ValueError("source archive must have one top-level directory")
    return frozenset(files)


def validate_sdist_source_inventory(repo_root: Path, sdist: Path) -> None:
    """Reject an sdist that omits or changes any Git-owned source byte."""

    tracked = tracked_source_inventory(repo_root)
    missing = sorted(tracked - sdist_source_inventory(sdist))
    if missing:
        raise ValueError("source archive omits tracked source: " + ", ".join(missing))
    with tarfile.open(sdist, "r:gz") as archive:
        members = {PurePosixPath(member.name).parts[1:]: member for member in archive.getmembers() if member.isfile()}
        changed: list[str] = []
        for relative in sorted(tracked):
            member = members.get(tuple(PurePosixPath(relative).parts))
            stream = archive.extractfile(member) if member is not None else None
            if stream is None:
                changed.append(relative)
                continue
            archived = hashlib.sha256(stream.read()).digest()
            source = hashlib.sha256((repo_root / relative).read_bytes()).digest()
            if archived != source:
                changed.append(relative)
    if changed:
        raise ValueError("source archive changes tracked source: " + ", ".join(changed))


def discovered_wheel_runtime_assets(source_root: Path) -> tuple[str, ...]:
    """Discover pack resources and ordinary non-Python package dependencies."""

    package_root = source_root / "bcf_governance"
    if package_root.is_symlink():
        raise RuntimeError("runtime asset source is a symlink: bcf_governance")
    pack_root = package_root / "pack/template-repo"
    assets = []
    for path in sorted(package_root.rglob("*")):
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        if path.is_symlink():
            raise RuntimeError(f"runtime asset source is a symlink: {path.relative_to(source_root)}")
        if not path.is_file() or (path.suffix == ".py" and not path.is_relative_to(pack_root)):
            continue
        assets.append(path.relative_to(source_root).as_posix())
    return tuple(assets)

def validate_package_data_contract(source_root: Path) -> tuple[str, ...]:
    """Prove every discovered runtime asset is selected by package metadata."""

    assets = discovered_wheel_runtime_assets(source_root)
    if not assets:
        raise RuntimeError("no package runtime assets discovered")
    pyproject = tomllib.loads((source_root / "pyproject.toml").read_text(encoding="utf-8"))
    tool = pyproject.get("tool", {})
    if not isinstance(tool, dict) or not isinstance(tool.get("setuptools", {}), dict):
        raise RuntimeError("package data metadata must contain tables")
    setuptools = tool.get("setuptools", {})
    tables = [setuptools.get(key, {}) for key in ("package-data", "exclude-package-data")]
    if any(not isinstance(table, dict) for table in tables):
        raise RuntimeError("package data patterns require table mappings")
    patterns, exclusions = [table.get("bcf_governance", []) for table in tables]
    for entries in (patterns, exclusions):
        if (not isinstance(entries, list)
                or any(not isinstance(pattern, str) or not pattern for pattern in entries)):
            raise RuntimeError("package data patterns require lists of nonempty strings")
        for pattern in entries:
            if (PurePosixPath(pattern).is_absolute() or PureWindowsPath(pattern).drive
                    or ".." in PurePosixPath(pattern).parts or "\\" in pattern):
                raise RuntimeError("package data pattern is outside the package namespace")
    package_root = source_root / "bcf_governance"
    selections = [
        {Path(path).as_posix() for pattern in entries
         for path in glob(str(pattern), root_dir=package_root, recursive=True)}
        for entries in (patterns, exclusions)
    ]
    package_prefix = "bcf_governance/"
    missing = [
        asset
        for asset in assets
        if asset.removeprefix(package_prefix) not in selections[0] - selections[1]
    ]
    if missing:
        raise RuntimeError("package data excludes runtime assets: " + ", ".join(missing))
    return assets

def validate_wheel_runtime_assets(wheel: Path, source_root: Path) -> None:
    """Prove the built wheel contains every mechanically discovered runtime file."""

    required = validate_package_data_contract(source_root)
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        payload = set(names)
        missing = [asset for asset in required if asset not in payload]
        if missing:
            raise RuntimeError("wheel missing runtime assets: " + ", ".join(missing))
        for asset in required:
            if names.count(asset) != 1:
                raise RuntimeError(f"wheel runtime asset is duplicated: {asset}")
            if archive.read(asset) != (source_root / asset).read_bytes():
                raise RuntimeError(f"wheel runtime asset differs from source: {asset}")


def validate_sdist_manifest_coverage(repo_root: Path) -> dict[str, object]:
    """Check static setuptools declarations without building or running commands.

    This query requires the caller's working directory to be the source root.
    It never substitutes for validation of the actual built archive bytes.
    """
    from contextlib import closing
    import tomllib

    root = repo_root.resolve()
    if root != Path.cwd().resolve():
        raise ValueError("source declaration query requires its exact working directory")
    tracked = tracked_source_inventory(root)
    for relative in tracked:
        path = root / relative
        if not path.is_file() or path.is_symlink() or path.resolve() != path:
            raise ValueError("source declaration requires regular owned files: " + relative)
    inputs = {name: (root / name).read_bytes() for name in ("pyproject.toml", "MANIFEST.in")}
    project = tomllib.loads(inputs["pyproject.toml"].decode("utf-8"))
    backend = project.get("build-system", {})
    if (root / "bcf_governance/pack/template-repo").is_dir():
        validate_package_data_contract(root)
    options = project.get("tool", {}).get("setuptools", {})
    from setuptools import Distribution
    from setuptools.command.sdist import sdist
    from setuptools._distutils.filelist import FileList
    from setuptools._distutils.text_file import TextFile
    from setuptools._distutils.errors import DistutilsError
    dynamic = project.get("project", {}).get("dynamic", [])
    dynamic_options = options.get("dynamic", {})
    if dynamic:
        # The framework's declared version attribute is AST-readable through the
        # backend's own static reader; never permit its module-execution fallback.
        from importlib.util import spec_from_file_location
        from setuptools.config.expand import StaticModule
        if (dynamic != ["version"] or dynamic_options != {
                "version": {"attr": "bcf_governance._version.__version__"}}):
            raise ValueError("source declaration query cannot prove dynamic configuration")
        if "bcf_governance/_version.py" not in tracked:
            raise ValueError("source version attribute is outside the tracked source population")
        version_path = root / "bcf_governance/_version.py"
        inputs["bcf_governance/_version.py"] = version_path.read_bytes()
        spec = spec_from_file_location("bcf_governance._version", version_path)
        try:
            if spec is None or not isinstance(StaticModule("bcf_governance._version", spec).__version__, str):
                raise ValueError("version attribute is not a static string")
        except AttributeError as exc:
            raise ValueError("source declaration query cannot prove a static version") from exc
    elif dynamic_options:
        raise ValueError("source declaration query has unbound dynamic metadata")
    if (backend.get("build-backend") != "setuptools.build_meta" or backend.get("backend-path")
            or any(options.get(key) for key in ("cmdclass", "ext-modules"))
            or any((root / name).exists() for name in ("setup.py", "setup.cfg"))):
        raise ValueError("source declaration query requires static setuptools configuration")

    class DeclarationDistribution(Distribution):
        def run_command(self, command):
            raise ValueError("source declaration query cannot execute backend command: " + command)

    class DeclarationQuery(sdist):
        def _add_defaults_python(self):
            if self.distribution.has_pure_modules():
                build_py = self.get_finalized_command("build_py")
                self.filelist.extend(build_py.get_source_files())
                # MANIFEST rules are applied below. Do not run egg_info or read a
                # possibly stale SOURCES.txt to discover package data recursively.
                build_py.manifest_files = {}
                for package in self.distribution.packages or ():
                    self.filelist.extend(build_py.find_data_files(package, build_py.get_package_dir(package)))

    distribution = DeclarationDistribution()
    distribution.script_name = "setup.py"
    distribution.parse_config_files()
    query = DeclarationQuery(distribution)
    query.ensure_finalized()
    query.filelist = FileList()
    query.filelist.allfiles = sorted(tracked)
    query.add_defaults()
    query.filelist.append("MANIFEST.in")
    try:
        with closing(TextFile(str(root / "MANIFEST.in"), strip_comments=True, skip_blanks=True,
                              join_lines=True, lstrip_ws=True, rstrip_ws=True, collapse_join=True)) as template:
            while (line := template.readline()) is not None:
                query.filelist.process_template_line(line)
    except (DistutilsError, ValueError) as exc:
        raise ValueError("invalid source manifest declaration: " + str(exc)) from exc
    if (any((root / name).read_bytes() != raw for name, raw in inputs.items())
            or tracked_source_inventory(root) != tracked):
        raise ValueError("source declaration inputs changed during inventory")
    missing = sorted(tracked - frozenset(query.filelist.files))
    if missing:
        raise ValueError("source manifest omits tracked source: " + ", ".join(missing))
    return {"authority": False, "scope": "static_source_declaration_coverage",
            "file_count": len(tracked), "built_bytes_verified": False}


def main() -> None:
    import argparse
    import json
    parser = argparse.ArgumentParser(description="Check source-distribution declaration coverage.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        result = validate_sdist_manifest_coverage(args.repo_root)
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

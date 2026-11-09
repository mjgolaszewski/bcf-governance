"""Build an exact-commit trusted controller from source or an installed BCF pack."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement

from .bootstrap.contracts import ChildProcessEnvironment
from .bootstrap.environment import child_process_environment as _default_child_process_environment
from .ci_github_bootstrap import verify_controller_inventory

RUNTIME_REQUIREMENTS = (
    "defusedxml>=0.7.1,<1", "PyYAML>=6.0,<7", "jsonschema>=4.21,<5", "packaging>=24,<27",
)


class TrustedControllerBuildError(ValueError):
    """Raised when exact installed runtime cannot become one closed controller."""


def _git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo_root, check=False, capture_output=True, text=True
    )
    if result.returncode:
        raise TrustedControllerBuildError("trusted-controller Git identity is unavailable")
    return result.stdout.strip()


def _run(repo_root: Path, argv: list[str], *, environment: dict[str, str] | None = None) -> None:
    subprocess.run(argv, cwd=repo_root, env=environment, check=True)


def _require_clean_head(repo_root: Path) -> None:
    if _git(repo_root, "status", "--porcelain", "--untracked-files=all"):
        raise TrustedControllerBuildError("trusted-controller source must be a clean committed HEAD")


def _exact_node(path: Path, *, directory: bool = False) -> tuple[int, ...]:
    value = path.lstat()
    if path.resolve(strict=True) != path or not (
        stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)
    ):
        raise TrustedControllerBuildError("exact-source custody path is not canonical")
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink)


def _exact_read(path: Path) -> tuple[bytes, tuple[int, ...]]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = _exact_node(path)
        if before != tuple(getattr(os.fstat(descriptor), key) for key in (
            "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size",
            "st_mtime_ns", "st_ctime_ns", "st_nlink"
        )) or before[5] > 65536:
            raise TrustedControllerBuildError("exact-source custody file changed")
        raw = os.read(descriptor, 65537)
        after = _exact_node(path)
        held = os.fstat(descriptor)
        held_identity = (held.st_dev, held.st_ino, held.st_mode, held.st_uid, held.st_gid,
                         held.st_size, held.st_mtime_ns, held.st_ctime_ns, held.st_nlink)
        if before != after or before != held_identity or len(raw) != before[5]:
            raise TrustedControllerBuildError("exact-source custody file changed")
        return raw, before
    finally:
        os.close(descriptor)


def _exact_git(repo_root: Path, *args: str,
               process_environment: ChildProcessEnvironment | None = None) -> str:
    process_environment = _default_child_process_environment() if process_environment is None else process_environment
    # Native hook/filter/configuration applicability is qualified by the caller.
    try:
        result = subprocess.run(
            ["git", "-c", "gc.auto=0", "-c", "maintenance.auto=false", *args],
            cwd=repo_root, check=False, capture_output=True, text=True, timeout=30,
            env={**process_environment.snapshot(), "GIT_OPTIONAL_LOCKS": "0"},
        )
    except subprocess.TimeoutExpired as failure:
        raise _ExactSourceGitError(failure) from failure
    if result.returncode:
        raise _ExactSourceGitError(result)
    return result.stdout.strip()


def _exact_subject(repo_root: Path) -> tuple[str, str]:
    if _exact_git(repo_root, "rev-parse", "--show-toplevel") != str(repo_root):
        raise TrustedControllerBuildError("exact-source native Git selected another repository root")
    gitdir = Path(_exact_git(repo_root, "rev-parse", "--absolute-git-dir"))
    common = Path(_exact_git(repo_root, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    _exact_node(gitdir, directory=True)
    _exact_node(common, directory=True)
    marker = repo_root / ".git"
    if marker.is_dir():
        _exact_node(marker, directory=True)
        selected = marker
    else:
        raw, _ = _exact_read(marker)
        if not raw.startswith(b"gitdir: ") or raw.count(b"\n") != 1:
            raise TrustedControllerBuildError("exact-source repository marker is ambiguous")
        selected = Path(raw[8:-1].decode())
        selected = selected if selected.is_absolute() else repo_root / selected
    if selected.resolve(strict=True) != gitdir:
        raise TrustedControllerBuildError("exact-source repository marker differs from native Git selection")
    commondir = gitdir / "commondir"
    if os.path.lexists(commondir):
        raw, _ = _exact_read(commondir)
        if raw.count(b"\n") != 1 or not raw.endswith(b"\n"):
            raise TrustedControllerBuildError("exact-source common-store marker is ambiguous")
        selected_common = (gitdir / raw[:-1].decode()).resolve(strict=True)
    else:
        selected_common = gitdir
    if selected_common != common:
        raise TrustedControllerBuildError("exact-source common-store selection differs from its marker")
    if _exact_git(repo_root, "status", "--porcelain", "--untracked-files=all"):
        raise TrustedControllerBuildError("trusted-controller source must be a clean committed HEAD")
    return (_exact_git(repo_root, "rev-parse", "HEAD"),
            _exact_git(repo_root, "rev-parse", "HEAD^{tree}"))


def _exact_sync(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _exact_link(source: Path, common: Path, subject: tuple[str, str]) -> dict[str, object]:
    marker, marker_identity = _exact_read(source / ".git")
    prefix = b"gitdir: "
    if not marker.startswith(prefix) or marker.count(b"\n") != 1:
        raise TrustedControllerBuildError("exact-source worktree marker is ambiguous")
    admin = Path(marker[len(prefix):-1].decode("utf-8"))
    if admin.parent != common / "worktrees":
        raise TrustedControllerBuildError("exact-source administration is outside common store")
    admin_identity = _exact_node(admin, directory=True)[:5]
    if (_exact_read(admin / "commondir")[0] != b"../..\n"
            or _exact_read(admin / "gitdir")[0] != str(source / ".git").encode() + b"\n"
            or _exact_read(admin / "HEAD")[0] != subject[0].encode() + b"\n"
            or _exact_subject(source) != subject):
        raise TrustedControllerBuildError("exact-source administration does not bind the subject")
    return {"admin": str(admin), "admin_identity": admin_identity,
            "marker_identity": marker_identity, "marker_sha256": hashlib.sha256(marker).hexdigest(),
            "source_identity": _exact_node(source, directory=True)[:5]}


class _ExactSourceCustodyError(TrustedControllerBuildError):
    """Private recovery state; never a receipt or release claim."""

    def __init__(self, stage: str, recovery: dict[str, object], secondary: BaseException) -> None:
        self.stage = stage
        self.recovery = dict(recovery)
        self.secondary_failure = secondary
        self.recovery_intent = None if recovery["intent_unlinked"] else Path(str(recovery["intent"]))
        state = ("source_admin_retired_cleanup_unqualified"
                 if recovery["source_admin_retirement_durable"]
                 else "source_admin_absence_observed_durability_unqualified"
                 if recovery["source_admin_absence_verified"] else "unresolved")
        super().__init__(f"exact-source custody {state} at {stage}; recovery={self.recovery}")
        self.add_note(f"secondary failure type: {type(secondary).__name__}")


class _ExactSourceGitError(TrustedControllerBuildError):
    """Retain the exact bounded-admission native outcome for private recovery."""

    def __init__(self, outcome: subprocess.CompletedProcess[str] | subprocess.TimeoutExpired) -> None:
        self.native_outcome = outcome
        super().__init__("exact-source native Git failed; exact outcome retained for recovery")


def _exact_unresolved(
    intent: Path, stage: str, failure: BaseException, recovery: dict[str, object]
) -> TrustedControllerBuildError:
    return _ExactSourceCustodyError(stage, recovery, failure)


@contextmanager
def exact_head_source(repo_root: Path) -> Iterator[Path]:
    """Yield exact committed source; preserve uncertain native mutation for recovery."""
    repo_root = repo_root.resolve()
    subject = _exact_subject(repo_root)
    common = Path(_exact_git(repo_root, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    common_identity = _exact_node(common, directory=True)[:5]
    parent = Path(tempfile.mkdtemp(prefix="bcf-exact-source-"))
    source, intent = parent / "source", parent / "intent.json"
    recovery: dict[str, object] = {
        "parent": str(parent), "intent": str(intent), "source": str(source),
        "common": str(common), "admin": None, "subject": list(subject),
        "mutation_may_have_started": False, "source_admin_absence_verified": False,
        "source_admin_retirement_durable": False, "intent_unlinked": False, "parent_removed": False,
    }
    try:
        parent = parent.resolve(strict=True)
        source, intent = parent / "source", parent / "intent.json"
        recovery.update(parent=str(parent), source=str(source), intent=str(intent))
        parent_identity = _exact_node(parent, directory=True)[:5]
        if parent_identity[3] != os.getuid() or parent_identity[2] & 0o077 or list(parent.iterdir()):
            raise TrustedControllerBuildError("exact-source parent is not exclusively owned and empty")
        recovery["parent_identity"] = parent_identity
        payload = {"kind": "private_exact_source_recovery_intent", "version": 1,
                   "repo": str(repo_root), "subject": list(subject), "common": str(common),
                   "common_identity": common_identity, "parent_identity": parent_identity,
                   "source": str(source), "purpose": "exact committed build source",
                   "retirement": "only after verified checkout/admin absence and retained subject"}
        raw = (json.dumps(payload, sort_keys=True) + "\n").encode()
        descriptor = os.open(intent, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        _exact_sync(parent)
        _exact_sync(parent.parent)
        intent_raw, intent_identity = _exact_read(intent)
        if intent_raw != raw or intent_identity[-1] != 1:
            raise TrustedControllerBuildError("exact-source intent is not exclusively owned")
        recovery["mutation_may_have_started"] = True
        _exact_git(repo_root, "worktree", "add", "--quiet", "--detach", str(source), subject[0])
        binding = _exact_link(source, common, subject)
        recovery['admin'] = binding['admin']
        if (_exact_subject(repo_root) != subject
                or _exact_node(common, directory=True)[:5] != common_identity
                or _exact_node(parent, directory=True)[:5] != parent_identity):
            raise TrustedControllerBuildError("retained exact-source owner changed during creation")
    except BaseException as failure:
        raise _exact_unresolved(intent, "creation", failure, recovery) from failure

    primary: BaseException | None = None
    try:
        yield source
    except BaseException as failure:
        primary = failure
        raise
    finally:
        try:
            if (_exact_node(parent, directory=True)[:5] != parent_identity
                    or _exact_node(common, directory=True)[:5] != common_identity
                    or _exact_subject(repo_root) != subject
                    or _exact_link(source, common, subject) != binding
                    or _exact_read(intent) != (raw, intent_identity)):
                raise TrustedControllerBuildError("exact-source owner changed before removal")
            _exact_git(repo_root, "worktree", "remove", "--force", str(source))
            if os.path.lexists(source) or os.path.lexists(Path(str(binding["admin"]))):
                raise TrustedControllerBuildError("native removal left checkout or administration")
            recovery['source_admin_absence_verified'] = True
            if (_exact_subject(repo_root) != subject
                    or _exact_node(common, directory=True)[:5] != common_identity
                    or _exact_node(parent, directory=True)[:5] != parent_identity
                    or _exact_read(intent) != (raw, intent_identity)
                    or sorted(path.name for path in parent.iterdir()) != ["intent.json"]):
                raise TrustedControllerBuildError("retained source changed during retirement")
            administration_root = common / "worktrees"
            _exact_sync(administration_root if administration_root.exists() else common)
            _exact_sync(parent)
            recovery['source_admin_retirement_durable'] = True
            intent.unlink()
            recovery['intent_unlinked'] = True
            _exact_sync(parent)
            parent.rmdir()
            recovery['parent_removed'] = True
            _exact_sync(parent.parent)
        except BaseException as failure:
            unresolved = _exact_unresolved(intent, "retirement", failure, recovery)
            if primary is not None:
                raise unresolved from primary
            raise unresolved from failure


def _source_requirements(repo_root: Path) -> tuple[str, ...]:
    project = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    values = project.get("project", {}).get("dependencies")
    if not isinstance(values, list) or not values:
        raise TrustedControllerBuildError("project runtime dependency inventory is missing")
    result: list[str] = []
    for value in values:
        try:
            requirement = Requirement(value)
        except (InvalidRequirement, TypeError) as exc:
            raise TrustedControllerBuildError(
                "project runtime dependency inventory is invalid"
            ) from exc
        if requirement.url is not None:
            raise TrustedControllerBuildError(
                "controller runtime dependencies may not use direct URLs"
            )
        result.append(str(value))
    return tuple(result)


def _materialize_installed_source(repo_root: Path, destination: Path) -> Path:
    _require_clean_head(repo_root.resolve())
    runtime = repo_root / "scripts/_bcf_runtime"
    schemas = repo_root / "schemas"
    if not runtime.is_dir() or runtime.is_symlink() or not schemas.is_dir():
        raise TrustedControllerBuildError("installed controller runtime is incomplete")
    source = destination / "source"
    tooling = source / "bcf_governance/tooling"
    pack_schemas = source / "bcf_governance/pack/template-repo/schemas"
    shutil.copytree(runtime, tooling)
    shutil.copytree(schemas, pack_schemas)
    (source / "bcf_governance/__init__.py").write_text(
        "from .tooling._version import __version__\n", encoding="utf-8"
    )
    (source / "bcf_governance/cli.py").write_text(
        """from __future__ import annotations
import sys
from .tooling import ci_commands, ci_github_commands

COMMANDS = {"ci": ci_commands.main, "ci-github": ci_github_commands.main}

def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in COMMANDS:
        print("usage: bcf {ci,ci-github} ...", file=sys.stderr)
        raise SystemExit(2)
    COMMANDS[args[0]](args[1:])
""",
        encoding="utf-8",
    )
    (source / "pyproject.toml").write_text(
        f"""[build-system]
requires = ["setuptools>=75", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "bcf-governance"
version = "0.0.0"
requires-python = ">=3.11"
dependencies = {json.dumps(list(RUNTIME_REQUIREMENTS))}

[project.scripts]
bcf = "bcf_governance.cli:main"

[tool.setuptools.packages.find]
include = ["bcf_governance*"]

[tool.setuptools.package-data]
bcf_governance = ["pack/template-repo/schemas/*.json", "tooling/*.mjs"]
""",
        encoding="utf-8",
    )
    return source


def _verify_offline_install(repo_root: Path, destination: Path, wheel: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="bcf-controller-install-") as name:
        root = Path(name)
        _run(repo_root, [sys.executable, "-m", "venv", str(root)])
        _run(
            repo_root,
            [
                str(root / "bin/python"), "-m", "pip", "install", "--no-index",
                "--find-links", str(destination), str(wheel),
            ],
        )
        _run(repo_root, [str(root / "bin/bcf"), "ci-github", "--help"])


def build(
    repo_root: Path,
    output: Path,
    *,
    run_id: str,
    run_attempt: str,
    process_environment: ChildProcessEnvironment | None=None,
) -> dict[str, object]:
    process_environment = _default_child_process_environment() if process_environment is None else process_environment
    repo_root = repo_root.resolve()
    destination = output if output.is_absolute() else repo_root / output
    if destination.is_symlink() or not destination.resolve().is_relative_to(repo_root):
        raise TrustedControllerBuildError(
            "trusted-controller output must be a nonsymlink repository path"
        )
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise TrustedControllerBuildError("trusted-controller output must begin empty")
    with ExitStack() as stack:
        if (repo_root / "bcf_governance/cli.py").is_file():
            source_root = stack.enter_context(exact_head_source(repo_root))
            requirements = _source_requirements(source_root)
        else:
            temporary = stack.enter_context(
                tempfile.TemporaryDirectory(prefix="bcf-installed-controller-")
            )
            source_root = _materialize_installed_source(repo_root, Path(temporary))
            requirements = RUNTIME_REQUIREMENTS
        environment = process_environment.snapshot()
        environment["SOURCE_DATE_EPOCH"] = _git(repo_root, "show", "-s", "--format=%ct", "HEAD")
        _run(
            source_root,
            [sys.executable, "-m", "build", "--wheel", "--outdir", str(destination)],
            environment=environment,
        )
        _run(
            repo_root,
            [sys.executable, "-m", "pip", "download", "--only-binary=:all:", "--dest", str(destination), *requirements],
        )
        metadata = {
            "schema_version": "1.1",
            "commit_sha": _git(repo_root, "rev-parse", "HEAD"),
            "tree_sha": _git(repo_root, "rev-parse", "HEAD^{tree}"),
            "workflow_run_id": run_id,
            "workflow_run_attempt": run_attempt,
            **default_environment(),
        }
        metadata["extra"] = ""
        metadata_path = destination / "CONTROL-METADATA.json"
        metadata_path.write_text(
            json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        admitted = sorted(destination.glob("*.whl")) + [metadata_path]
        (destination / "SHA256SUMS").write_text(
            "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                for path in admitted
            ),
            encoding="utf-8",
        )
        wheel, _ = verify_controller_inventory(destination.resolve())
        _verify_offline_install(repo_root, destination, wheel)
        return metadata


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(build(args.repo_root, args.output, run_id=args.run_id, run_attempt=args.run_attempt), sort_keys=True))


if __name__ == "__main__":
    main()

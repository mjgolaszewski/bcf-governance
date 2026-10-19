"""Prove that the pinned trusted controller covers the current runtime source."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import StrEnum
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
from .evidence_process_supervisor import run_admitted_command
import sys
import tempfile
from typing import Any, Iterable

import yaml

from .ci_authority_pins import (
    CIAuthorityPinError,
    compiled_workflow_job_names,
)


TRUSTED_ENTRYPOINT = PurePosixPath(
    "bcf_governance/tooling/ci_github_commands.py"
)
DIRECT_RUNTIME_FILES = (
    PurePosixPath("bcf_governance/__init__.py"),
    PurePosixPath("bcf_governance/_version.py"),
    PurePosixPath("bcf_governance/cli.py"),
)
PACKAGED_SCHEMA_ROOT = PurePosixPath(
    "bcf_governance/pack/template-repo/schemas"
)
INSTALLED_RUNTIME_ROOT = PurePosixPath("scripts/_bcf_runtime")
INSTALLED_SCHEMA_ROOT = PurePosixPath("schemas")
SCHEMA_REQUIREMENTS_FILE = PurePosixPath("AGENTS.yml")
VERSION_METADATA_FILE = PurePosixPath("bcf_governance/_version.py")
VERSION_METADATA_PATTERN = re.compile(
    r'\A"""Single authoritative BCF release version\."""\n\n'
    r'__version__ = "(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+)?)"\n\Z'
)
GOVERNANCE_WORKFLOW = PurePosixPath(".github/workflows/governance.yml")
PR_EVIDENCE_INVENTORY_CAPABILITY_FILES = (
    PurePosixPath("bcf_governance/tooling/prior_evidence_transport.py"),
    PurePosixPath("bcf_governance/tooling/provider_job_inventory.py"),
)
AUTHORITY_CONTRACT = PurePosixPath("governance/ci-authority.yml")
INSTALLED_AUTHORITY_VALIDATOR = PurePosixPath(
    "bcf_governance/tooling/ci_authority_contracts.py"
)
INSTALLED_TOPOLOGY_CLASSIFIER = PurePosixPath(
    "bcf_governance/tooling/ci_github_membership.py"
)
ALTERNATE_LANE_WORKFLOWS = {
    "bootstrap": PurePosixPath(
        ".github/workflows/bcf-trusted-control-bootstrap.yml"
    ),
    "probe": PurePosixPath(".github/workflows/bcf-trusted-control-probe.yml"),
}
INSTALLED_AUTHORITY_VALIDATION_PROGRAM = (
    "import pathlib,runpy,sys,yaml;"
    "owner=runpy.run_path(sys.argv[1]);"
    "payload=yaml.safe_load(pathlib.Path(sys.argv[3]).read_text(encoding='utf-8'));"
    "owner['validate_ci_contract'](pathlib.Path(sys.argv[2]),'authority',payload)"
)


class TrustedControllerCompatibilityError(ValueError):
    """Raised when trusted jobs need runtime bytes newer than their target."""


class TrustedControllerRuntimeStaleError(TrustedControllerCompatibilityError):
    """Raised only when an otherwise valid ancestor target has stale runtime bytes."""


class TrustedControllerBootstrapIncompatibleError(TrustedControllerCompatibilityError):
    """Raised when controller N cannot authenticate a changed PR producer topology."""


class TrustedControllerRoutineRotationIncompatibleError(
    TrustedControllerCompatibilityError
):
    """Raised when installed N cannot authorize the candidate pending topology."""


class TrustedControllerApplicabilityState(StrEnum):
    """Non-authoritative execution applicability derived from compatibility."""

    CURRENT = "current"
    PENDING_ROTATION = "pending_rotation"


@dataclass(frozen=True)
class TrustedControllerCompatibility:
    target_commit: str
    source_files: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "target_commit": self.target_commit,
            "source_file_count": len(self.source_files),
        }


@dataclass(frozen=True)
class TrustedControllerApplicability:
    """Route exact-main work without conferring certification authority."""

    state: TrustedControllerApplicabilityState
    target_commit: str

    def as_dict(self) -> dict[str, object]:
        return {
            "controller_state": self.state.value,
            "semantic_evidence_applicable": (
                self.state is TrustedControllerApplicabilityState.CURRENT
            ),
            "target_commit": self.target_commit,
        }


def _git_command(*arguments: str) -> list[str]:
    if any(name in os.environ for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR",
            "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_NAMESPACE", "GIT_SHALLOW_FILE", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT")):
        raise TrustedControllerCompatibilityError("Git environment namespace redirection is unauthenticated")
    return ["git", "--no-replace-objects", "-c", f"core.hooksPath={os.devnull}",
            "-c", "core.fsmonitor=false", *arguments]


def _git(repo_root: Path, *arguments: str) -> str:
    result = run_admitted_command(
        _git_command(*arguments),
        unbound_runner=subprocess.run, cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise TrustedControllerCompatibilityError(
            result.stderr.strip() or f"git {' '.join(arguments)} failed"
        )
    return result.stdout.strip()


def _committed_tree(repo_root: Path, ref: str) -> tuple[str, dict[str, tuple[str, str, str]]]:
    """Capture exact regular/source facts without candidate layout or Git redirection."""
    if Path(_git(repo_root, "rev-parse", "--show-toplevel")).resolve() != repo_root.resolve():
        raise TrustedControllerCompatibilityError("trusted controller repository root differs")
    commit = _git(repo_root, "rev-parse", "--verify", f"{ref}^{{commit}}")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise TrustedControllerCompatibilityError("trusted controller commit identity is malformed")
    raw = _git(repo_root, "ls-tree", "-rz", "--full-tree", commit)
    inventory = {}
    if raw and not raw.endswith("\0"):
        raise TrustedControllerCompatibilityError("trusted controller Git inventory is truncated")
    for row in raw.split("\0"):
        if not row:
            continue
        try:
            header, path = row.split("\t", 1)
            mode, kind, oid = header.split()
        except ValueError as exc:
            raise TrustedControllerCompatibilityError("trusted controller Git inventory is malformed") from exc
        relative = PurePosixPath(path)
        if (relative.is_absolute() or ".." in relative.parts or relative.as_posix() != path
                or path in inventory or not re.fullmatch(r"[0-7]{6}", mode)
                or not re.fullmatch(r"[0-9a-f]{" + str(len(commit)) + r"}", oid)):
            raise TrustedControllerCompatibilityError("trusted controller Git inventory is ambiguous")
        inventory[path] = (mode, kind, oid)
    return commit, inventory


def _regular_entry(inventory, path: PurePosixPath) -> None:
    entry = inventory.get(path.as_posix())
    if entry is None or entry[0] not in {"100644", "100755"} or entry[1] != "blob":
        raise TrustedControllerCompatibilityError(f"trusted controller source is absent or unsafe: {path}")


def _module_file(repo_root: Path, module: str, *, inventory=None) -> PurePosixPath | None:
    if module != "bcf_governance" and not module.startswith("bcf_governance."):
        return None
    relative = PurePosixPath(*module.split("."))
    candidates = (PurePosixPath(str(relative) + ".py"), relative / "__init__.py")
    if inventory is not None:
        found = [path for path in candidates if path.as_posix() in inventory]
        if len(found) > 1:
            raise TrustedControllerCompatibilityError("protected Python module inventory is ambiguous")
        if found:
            _regular_entry(inventory, found[0])
            return found[0]
        return None
    return next((path for path in candidates if (repo_root / path).is_file()), None)


def _imported_modules(path: PurePosixPath, tree: ast.Module) -> Iterable[str]:
    package = list(path.with_suffix("").parts[:-1])
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
            continue
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:
            keep = len(package) - (node.level - 1)
            if keep < 1:
                continue
            base = package[:keep]
            if node.module:
                base.extend(node.module.split("."))
                yield ".".join(base)
                for alias in node.names:
                    yield ".".join([*base, alias.name])
            else:
                for alias in node.names:
                    yield ".".join([*base, alias.name])
        elif node.module:
            yield node.module
            for alias in node.names:
                yield node.module + "." + alias.name


def _required_packaged_schemas(
    repo_root: Path,
    *,
    ref: str | None,
    schema_root: PurePosixPath = PACKAGED_SCHEMA_ROOT,
) -> set[PurePosixPath]:
    source = (
        _git(repo_root, "show", f"{ref}:{SCHEMA_REQUIREMENTS_FILE.as_posix()}")
        if ref is not None
        else (repo_root / SCHEMA_REQUIREMENTS_FILE).read_text(encoding="utf-8")
    )
    try:
        payload = yaml.safe_load(source)
        required = payload["governance"]["structural_schema_contract"][
            "required_schemas"
        ]
    except (KeyError, TypeError, yaml.YAMLError) as exc:
        raise TrustedControllerCompatibilityError(
            "trusted controller schema requirements are invalid"
        ) from exc
    if not isinstance(required, list) or not required:
        raise TrustedControllerCompatibilityError(
            "trusted controller schema requirements are invalid"
        )
    canonical: set[PurePosixPath] = set()
    for value in required:
        path = PurePosixPath(value) if isinstance(value, str) else PurePosixPath(".")
        if (
            not isinstance(value, str)
            or path.is_absolute()
            or len(path.parts) < 2
            or path.parts[0] != "schemas"
            or ".." in path.parts
            or path.suffix != ".json"
        ):
            raise TrustedControllerCompatibilityError(
                "trusted controller schema requirements are invalid"
            )
        canonical.add(schema_root / path.relative_to("schemas"))
    if len(canonical) != len(required):
        raise TrustedControllerCompatibilityError(
            "trusted controller schema requirements are invalid"
        )
    return canonical


def _require_packaged_schemas(
    repo_root: Path, paths: set[PurePosixPath], *, ref: str | None, inventory=None
) -> None:
    for path in paths:
        if ref is not None:
            if inventory is not None:
                try:
                    _regular_entry(inventory, path)
                except TrustedControllerCompatibilityError as exc:
                    raise TrustedControllerCompatibilityError(f"required trusted controller schema is absent or unsafe: {path}") from exc
            else:
                _git(repo_root, "cat-file", "-e", f"{ref}:{path.as_posix()}")
            continue
        source = repo_root / path
        if not source.is_file() or source.is_symlink():
            raise TrustedControllerCompatibilityError(f"required trusted controller schema is absent or unsafe: {path}")


def _runtime_source_files(root: Path, *, ref: str | None, inventory=None) -> set[str]:
    """One existing import/schema population walker, qualified by source context."""
    installed_entrypoint = INSTALLED_RUNTIME_ROOT / "ci_github_commands.py"
    present = (lambda path: path.as_posix() in inventory) if inventory is not None else (lambda path: (root / path).is_file())
    source_layout, private_layout = present(TRUSTED_ENTRYPOINT), present(installed_entrypoint)
    if inventory is not None:
        _regular_entry(inventory, SCHEMA_REQUIREMENTS_FILE)
        if source_layout and private_layout:
            raise TrustedControllerCompatibilityError("protected runtime layout is ambiguous")
    if not source_layout and private_layout:
        if inventory is None:
            runtime_files = {path.relative_to(root).as_posix() for path in (root / INSTALLED_RUNTIME_ROOT).rglob("*")
                             if path.is_file() and not path.is_symlink() and path.suffix in {".py", ".mjs"}}
        else:
            runtime_files = {path for path in inventory if PurePosixPath(path).is_relative_to(INSTALLED_RUNTIME_ROOT)
                             and PurePosixPath(path).suffix in {".py", ".mjs"}}
            for path in runtime_files:
                _regular_entry(inventory, PurePosixPath(path))
        schemas = _required_packaged_schemas(root, ref=ref, schema_root=INSTALLED_SCHEMA_ROOT)
        _require_packaged_schemas(root, schemas, ref=ref, inventory=inventory)
        wrappers = {path for path in ("scripts/build_trusted_controller.py", "requirements-governance.txt")
                    if present(PurePosixPath(path))}
        if inventory is not None:
            for path in wrappers:
                _regular_entry(inventory, PurePosixPath(path))
        if not runtime_files or not schemas:
            raise TrustedControllerCompatibilityError("installed trusted controller runtime is incomplete")
        return runtime_files | {path.as_posix() for path in schemas} | wrappers
    pending, observed = [TRUSTED_ENTRYPOINT], set(DIRECT_RUNTIME_FILES)
    if inventory is not None:
        for path in observed:
            _regular_entry(inventory, path)
    while pending:
        relative = pending.pop()
        if relative in observed:
            continue
        source = root / relative
        if inventory is not None:
            _regular_entry(inventory, relative)
        elif not source.is_file() or source.is_symlink():
            raise TrustedControllerCompatibilityError(f"trusted controller source is absent or unsafe: {relative}")
        observed.add(relative)
        try:
            raw = _git(root, "show", f"{ref}:{relative}") if ref is not None else source.read_text(encoding="utf-8")
            tree = ast.parse(raw, filename=str(relative))
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            raise TrustedControllerCompatibilityError(f"trusted controller source is invalid: {relative}") from exc
        for module in _imported_modules(relative, tree):
            imported = _module_file(root, module, inventory=inventory)
            if imported is not None and imported not in observed:
                pending.append(imported)
    schemas = _required_packaged_schemas(root, ref=ref)
    _require_packaged_schemas(root, schemas, ref=ref, inventory=inventory)
    return {path.as_posix() for path in observed | schemas}


def trusted_runtime_source_files(repo_root: Path, *, target_commit: str | None = None) -> tuple[str, ...]:
    """Compare candidate and protected populations without candidate-defined exclusions."""
    root = repo_root.resolve()
    if target_commit is None:
        return tuple(sorted(_runtime_source_files(root, ref=None)))
    current, current_inventory = _committed_tree(root, "HEAD")
    target, target_inventory = _committed_tree(root, target_commit)
    return tuple(sorted(_runtime_source_files(root, ref=current, inventory=current_inventory)
                        | _runtime_source_files(root, ref=target, inventory=target_inventory)))


def _version_metadata_only(
    repo_root: Path, *, target_commit: str, path: PurePosixPath, current_commit: str | None = None
) -> bool:
    """Admit only a canonical inert release-version literal as metadata drift."""

    current = ((repo_root / path).read_text(encoding="utf-8") if current_commit is None
               else _git(repo_root, "show", f"{current_commit}:{path.as_posix()}") + "\n")
    target = _git(repo_root, "show", f"{target_commit}:{path.as_posix()}") + "\n"
    return (
        VERSION_METADATA_PATTERN.fullmatch(current) is not None
        and VERSION_METADATA_PATTERN.fullmatch(target) is not None
    )


def _workflow_job_inventory(repo_root: Path, *, ref: str | None) -> tuple[str, ...]:
    try:
        raw = (
            _git(repo_root, "show", f"{ref}:{GOVERNANCE_WORKFLOW.as_posix()}").encode()
            if ref is not None
            else (repo_root / GOVERNANCE_WORKFLOW).read_bytes()
        )
        return compiled_workflow_job_names(raw)
    except (CIAuthorityPinError, OSError) as exc:
        raise TrustedControllerBootstrapIncompatibleError(
            "governance workflow job inventory cannot be projected"
        ) from exc


def _verify_installed_authority_consumability(
    repo_root: Path, *, target_commit: str
) -> None:
    """Run candidate authority through installed N's exact canonical validator."""

    authority_path = repo_root / AUTHORITY_CONTRACT
    if not authority_path.is_file() or authority_path.is_symlink():
        return
    try:
        with tempfile.TemporaryDirectory(prefix="bcf-installed-authority-") as raw:
            checkout = Path(raw) / "controller"
            materialized = run_admitted_command(
                _git_command("worktree", "add", "--detach", str(checkout), target_commit),
                unbound_runner=subprocess.run, cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )
            if materialized.returncode != 0:
                raise ValueError(
                    materialized.stderr.strip() or "installed controller unavailable"
                )
            try:
                source_layout = (checkout / INSTALLED_AUTHORITY_VALIDATOR).is_file()
                validator = (
                    checkout / INSTALLED_AUTHORITY_VALIDATOR
                    if source_layout
                    else checkout / INSTALLED_RUNTIME_ROOT / "ci_authority_contracts.py"
                )
                schema_root = (
                    checkout / "bcf_governance/pack/template-repo"
                    if source_layout
                    else checkout
                )
                result = run_admitted_command(
                    [
                        sys.executable,
                        "-c",
                        INSTALLED_AUTHORITY_VALIDATION_PROGRAM,
                        str(validator),
                        str(schema_root),
                        str(authority_path),
                    ],
                    unbound_runner=subprocess.run, cwd=repo_root,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode != 0:
                    detail = result.stderr.strip().splitlines()
                    raise ValueError(
                        detail[-1] if detail else "installed validation failed"
                    )
            finally:
                run_admitted_command(
                    _git_command("worktree", "remove", "--force", str(checkout)),
                    unbound_runner=subprocess.run, cwd=repo_root,
                    capture_output=True,
                    text=True,
                    check=False,
                )
    except Exception as exc:
        raise TrustedControllerBootstrapIncompatibleError(
            "candidate authority cannot be consumed by installed controller "
            f"{target_commit}: {exc}"
        ) from exc


def ordinary_alternate_lane_available(repo_root: Path) -> bool:
    """Recognize only the complete governed bootstrap/probe compatibility lane."""

    authority_path = repo_root / AUTHORITY_CONTRACT
    if not authority_path.is_file() or authority_path.is_symlink():
        return False
    try:
        authority = yaml.safe_load(authority_path.read_text(encoding="utf-8"))
        registry = authority["workflow_registry"]
        roles = authority["roles"]
    except (KeyError, TypeError, yaml.YAMLError):
        return False
    for role, relative in ALTERNATE_LANE_WORKFLOWS.items():
        entry = registry.get(role) if isinstance(registry, dict) else None
        path = repo_root / relative
        if (
            not isinstance(entry, dict)
            or entry.get("active_path") != relative.as_posix()
            or roles.get(role) != role
            or not path.is_file()
            or path.is_symlink()
        ):
            return False
    return True


def _candidate_pending_topology(
    repo_root: Path,
) -> tuple[dict[str, Any], list[dict[str, str]], list[str]]:
    authority = yaml.safe_load((repo_root / AUTHORITY_CONTRACT).read_text(encoding="utf-8"))
    workflow_entry = authority["workflow_registry"]["admission"]
    workflow = yaml.safe_load(
        (repo_root / workflow_entry["active_path"]).read_text(encoding="utf-8")
    )
    roles = workflow_entry["job_roles"]
    jobs = workflow["jobs"]
    facades = [
        jobs[job_id]["name"]
        for job_id, role in roles.items()
        if role == "producer"
    ]
    provider_jobs = [
        *(
            {"name": str(value["job_id"]), "status": "completed", "conclusion": "success"}
            for value in authority.get("controller_builder_jobs", [])
        ),
        *(
            {"name": str(value["job_id"]), "status": "completed", "conclusion": "skipped"}
            for value in authority["admission_jobs"]
        ),
        *(
            {"name": str(name), "status": "completed", "conclusion": "skipped"}
            for name in facades
        ),
    ]
    return authority, provider_jobs, facades


def _verify_installed_pending_topology(
    repo_root: Path, *, target_commit: str
) -> None:
    """Run installed N's exact topology classifier on the candidate provider shape."""

    target_commit, inventory = _committed_tree(repo_root, target_commit)
    candidates = (INSTALLED_TOPOLOGY_CLASSIFIER, INSTALLED_RUNTIME_ROOT / "ci_github_membership.py")
    found = [path for path in candidates if path.as_posix() in inventory]
    if not found:
        return
    if len(found) != 1:
        raise TrustedControllerCompatibilityError("protected topology classifier inventory is ambiguous")
    topology_path = found[0]
    _regular_entry(inventory, topology_path)
    source_layout = topology_path == INSTALLED_TOPOLOGY_CLASSIFIER
    try:
        authority, jobs, facades = _candidate_pending_topology(repo_root)
        with tempfile.TemporaryDirectory(prefix="bcf-installed-topology-") as raw:
            root = Path(raw)
            checkout = root / "controller"
            materialized = run_admitted_command(
                _git_command("worktree", "add", "--detach", str(checkout), target_commit),
                unbound_runner=subprocess.run, cwd=repo_root,
                capture_output=True,
                text=True,
                check=False,
            )
            if materialized.returncode != 0:
                raise ValueError(
                    materialized.stderr.strip() or "installed controller unavailable"
                )
            try:
                program = (
                    "import importlib,json,pathlib,sys,types;"
                    "base=pathlib.Path(sys.argv[1]);source=sys.argv[2]=='source';"
                    "sys.path.insert(0,str(base if source else base/'scripts'));"
                    "name='bcf_governance.tooling.ci_github_membership' if source else '_bcf_runtime.ci_github_membership';"
                    "m=importlib.import_module(name);"
                    "expected=base/pathlib.Path(sys.argv[3]);"
                    "assert pathlib.Path(m.__file__).resolve()==expected.resolve(),'protected classifier origin differs';"
                    "m.authenticate_trusted_run=lambda *a,**k:None;"
                    "m._reference_map=lambda *a,**k:{};"
                    "m._validate_reference_inventory=lambda *a,**k:None;"
                    "fixture=json.load(sys.stdin);"
                    "authority=fixture['authority'];jobs=fixture['jobs'];facades=fixture['facades'];"
                    "m._pending_producer_facades=lambda *a,**k:facades if hasattr(m,'_pending_producer_facades') else None;"
                    "api=types.SimpleNamespace(run=lambda *a,**k:{'run_attempt':1},jobs=lambda *a,**k:jobs);"
                    "main=types.SimpleNamespace(checkout_sha='a'*40);"
                    "result=m.classify_admission_topology(api,repository='owner/repo',main=main,authority=authority,admission_run_id=1,admission_run_attempt=1);"
                    "print(str(result.state.value)+':'+result.reason)"
                )
                result = run_admitted_command(
                    [
                        sys.executable,
                        "-I", "-c",
                        program,
                        str(checkout), "source" if source_layout else "private", str(topology_path),
                    ],
                    unbound_runner=subprocess.run, cwd=repo_root,
                    capture_output=True,
                    text=True,
                    input=json.dumps(
                        {"authority": authority, "jobs": jobs, "facades": facades}
                    ),
                    check=False,
                )
                observed = result.stdout.strip()
                if result.returncode != 0 or not observed.startswith(
                    "pending_rotation:"
                ):
                    errors = result.stderr.strip().splitlines()
                    detail = observed or (errors[-1] if errors else "")
                    raise ValueError(detail or "installed topology classification failed")
            finally:
                run_admitted_command(
                    _git_command("worktree", "remove", "--force", str(checkout)),
                    unbound_runner=subprocess.run, cwd=repo_root,
                    capture_output=True,
                    text=True,
                    check=False,
                )
    except Exception as exc:
        raise TrustedControllerRoutineRotationIncompatibleError(
            "installed controller cannot authorize candidate pending topology: "
            f"{exc}"
        ) from exc


def verify_pr_bootstrap_compatibility(
    repo_root: Path, *, base_commit: str, target_commit: str
) -> None:
    """Reject a PR topology change that installed controller N cannot transport."""

    root = repo_root.resolve()
    before = _workflow_job_inventory(root, ref=base_commit)
    after = _workflow_job_inventory(root, ref=None)
    if before == after:
        return
    unavailable: list[str] = []
    for path in PR_EVIDENCE_INVENTORY_CAPABILITY_FILES:
        target = run_admitted_command(
            _git_command("cat-file", "-e", f"{target_commit}:{path.as_posix()}"),
            unbound_runner=subprocess.run, cwd=root,
            capture_output=True,
            check=False,
        )
        current = root / path
        if target.returncode != 0 or not current.is_file() or current.is_symlink():
            unavailable.append(path.as_posix())
    changed = _git(
        root,
        "diff",
        "--name-only",
        target_commit,
        "HEAD",
        "--",
        *(path.as_posix() for path in PR_EVIDENCE_INVENTORY_CAPABILITY_FILES),
    ).splitlines()
    bootstrap_incompatible = sorted(set(unavailable + changed))
    if bootstrap_incompatible:
        raise TrustedControllerBootstrapIncompatibleError(
            "PR producer job inventory changed before installed controller support: "
            + ", ".join(bootstrap_incompatible)
        )


def _require_candidate_subject(root: Path, expected: str) -> None:
    if _git(root, "rev-parse", "HEAD") != expected or _git(root, "status", "--porcelain"):
        raise TrustedControllerCompatibilityError("candidate subject changed during trusted applicability")


def verify_trusted_controller_compatibility(
    repo_root: Path, *, target_commit: str
) -> TrustedControllerCompatibility:
    """Evaluate exact committed subjects and reject movement through consumption."""
    root = repo_root.resolve()
    target_commit, target_inventory = _committed_tree(root, target_commit)
    current_commit, current_inventory = _committed_tree(root, "HEAD")
    _require_candidate_subject(root, current_commit)
    try:
        ancestor = run_admitted_command(
            _git_command("merge-base", "--is-ancestor", target_commit, current_commit),
            unbound_runner=subprocess.run, cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if ancestor.returncode != 0:
            raise TrustedControllerCompatibilityError(
                "trusted controller target is not an ancestor of committed HEAD"
            )
        paths = tuple(sorted(
            _runtime_source_files(root, ref=current_commit, inventory=current_inventory)
            | _runtime_source_files(root, ref=target_commit, inventory=target_inventory)))
        changed = _git(root, "diff", "--name-only", target_commit, current_commit, "--", *paths)
        incompatible = changed.splitlines()
        if changed:
            incompatible = [
                path
                for path in changed.splitlines()
                if path != VERSION_METADATA_FILE.as_posix()
                or not _version_metadata_only(
                    root, target_commit=target_commit, path=VERSION_METADATA_FILE,
                    current_commit=current_commit
                )
            ]
        _require_candidate_subject(root, current_commit)
        if incompatible:
            _verify_installed_authority_consumability(
                root, target_commit=target_commit
            )
            _require_candidate_subject(root, current_commit)
            _verify_installed_pending_topology(root, target_commit=target_commit)
            raise TrustedControllerRuntimeStaleError(
                "trusted controller target is stale for runtime files: "
                + ", ".join(incompatible)
            )
        return TrustedControllerCompatibility(target_commit, paths)

    finally:
        _require_candidate_subject(root, current_commit)


def classify_trusted_controller_applicability(
    repo_root: Path, *, target_commit: str
) -> TrustedControllerApplicability:
    """Classify only execution applicability using the canonical compatibility owner.

    Bootstrap-incompatible candidates still raise. A stale but consumable controller is
    noncertifying and may build N+1, but must not allocate semantic evidence.
    """

    try:
        verify_trusted_controller_compatibility(
            repo_root, target_commit=target_commit
        )
    except TrustedControllerRoutineRotationIncompatibleError:
        if not ordinary_alternate_lane_available(repo_root):
            raise
        state = TrustedControllerApplicabilityState.PENDING_ROTATION
    except TrustedControllerRuntimeStaleError:
        state = TrustedControllerApplicabilityState.PENDING_ROTATION
    else:
        state = TrustedControllerApplicabilityState.CURRENT
    return TrustedControllerApplicability(state, target_commit)

"""Prove that the pinned trusted controller covers the current runtime source."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import StrEnum
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
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


def _git(repo_root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise TrustedControllerCompatibilityError(
            result.stderr.strip() or f"git {' '.join(arguments)} failed"
        )
    return result.stdout.strip()


def _module_file(repo_root: Path, module: str) -> PurePosixPath | None:
    if module != "bcf_governance" and not module.startswith("bcf_governance."):
        return None
    relative = PurePosixPath(*module.split("."))
    file_candidate = PurePosixPath(str(relative) + ".py")
    package_candidate = relative / "__init__.py"
    if (repo_root / file_candidate).is_file():
        return file_candidate
    if (repo_root / package_candidate).is_file():
        return package_candidate
    return None


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
            else:
                for alias in node.names:
                    yield ".".join([*base, alias.name])
        elif node.module:
            yield node.module


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
    repo_root: Path, paths: set[PurePosixPath], *, ref: str | None
) -> None:
    for path in paths:
        if ref is not None:
            _git(repo_root, "cat-file", "-e", f"{ref}:{path.as_posix()}")
            continue
        source = repo_root / path
        if not source.is_file() or source.is_symlink():
            raise TrustedControllerCompatibilityError(
                f"required trusted controller schema is absent or unsafe: {path}"
            )


def trusted_runtime_source_files(
    repo_root: Path, *, target_commit: str | None = None
) -> tuple[str, ...]:
    """Derive the trusted CLI closure and active packaged schema requirements."""

    root = repo_root.resolve()
    installed_entrypoint = INSTALLED_RUNTIME_ROOT / "ci_github_commands.py"
    if not (root / TRUSTED_ENTRYPOINT).is_file() and (root / installed_entrypoint).is_file():
        runtime_files = {
            path.relative_to(root).as_posix()
            for path in (root / INSTALLED_RUNTIME_ROOT).rglob("*")
            if path.is_file() and not path.is_symlink() and path.suffix in {".py", ".mjs"}
        }
        schema_files = _required_packaged_schemas(
            root, ref=None, schema_root=INSTALLED_SCHEMA_ROOT
        )
        _require_packaged_schemas(root, schema_files, ref=None)
        if target_commit is not None:
            target_schemas = _required_packaged_schemas(
                root, ref=target_commit, schema_root=INSTALLED_SCHEMA_ROOT
            )
            _require_packaged_schemas(root, target_schemas, ref=target_commit)
            schema_files.update(target_schemas)
        wrappers = {
            path
            for path in (
                "scripts/build_trusted_controller.py",
                "requirements-governance.txt",
            )
            if (root / path).is_file() and not (root / path).is_symlink()
        }
        observed_installed = runtime_files | {
            value.as_posix() for value in schema_files
        } | wrappers
        if not runtime_files or not schema_files:
            raise TrustedControllerCompatibilityError(
                "installed trusted controller runtime is incomplete"
            )
        if target_commit is not None:
            for relative in observed_installed:
                _git(root, "cat-file", "-e", f"{target_commit}:{relative}")
        return tuple(sorted(observed_installed))
    pending = [TRUSTED_ENTRYPOINT]
    observed = set(DIRECT_RUNTIME_FILES)
    while pending:
        relative = pending.pop()
        if relative in observed:
            continue
        source = root / relative
        if not source.is_file() or source.is_symlink():
            raise TrustedControllerCompatibilityError(
                f"trusted controller source is absent or unsafe: {relative}"
            )
        observed.add(relative)
        try:
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(relative))
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            raise TrustedControllerCompatibilityError(
                f"trusted controller source is invalid: {relative}"
            ) from exc
        for module in _imported_modules(relative, tree):
            imported = _module_file(root, module)
            if imported is not None and imported not in observed:
                pending.append(imported)
    current_schemas = _required_packaged_schemas(root, ref=None)
    _require_packaged_schemas(root, current_schemas, ref=None)
    observed.update(current_schemas)
    if target_commit is not None:
        target_schemas = _required_packaged_schemas(root, ref=target_commit)
        _require_packaged_schemas(root, target_schemas, ref=target_commit)
        observed.update(target_schemas)
    return tuple(sorted(path.as_posix() for path in observed))


def _version_metadata_only(
    repo_root: Path, *, target_commit: str, path: PurePosixPath
) -> bool:
    """Admit only a canonical inert release-version literal as metadata drift."""

    current = (repo_root / path).read_text(encoding="utf-8")
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
            materialized = subprocess.run(
                ["git", "worktree", "add", "--detach", str(checkout), target_commit],
                cwd=repo_root,
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
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        INSTALLED_AUTHORITY_VALIDATION_PROGRAM,
                        str(validator),
                        str(schema_root),
                        str(authority_path),
                    ],
                    cwd=repo_root,
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
                subprocess.run(
                    ["git", "worktree", "remove", "--force", str(checkout)],
                    cwd=repo_root,
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

    topology_path = (
        INSTALLED_TOPOLOGY_CLASSIFIER
        if (repo_root / INSTALLED_TOPOLOGY_CLASSIFIER).is_file()
        else INSTALLED_RUNTIME_ROOT / "ci_github_membership.py"
    )
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{target_commit}:{topology_path}"],
        cwd=repo_root,
        capture_output=True,
        check=False,
    )
    if exists.returncode != 0:
        return
    try:
        authority, jobs, facades = _candidate_pending_topology(repo_root)
        with tempfile.TemporaryDirectory(prefix="bcf-installed-topology-") as raw:
            root = Path(raw)
            checkout = root / "controller"
            materialized = subprocess.run(
                ["git", "worktree", "add", "--detach", str(checkout), target_commit],
                cwd=repo_root,
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
                    "sys.path.insert(0,sys.argv[1]);"
                    "name='bcf_governance.tooling.ci_github_membership' if (pathlib.Path(sys.argv[1])/'bcf_governance').is_dir() else '_bcf_runtime.ci_github_membership';"
                    "m=importlib.import_module(name);"
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
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        program,
                        str(checkout),
                    ],
                    cwd=repo_root,
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
                subprocess.run(
                    ["git", "worktree", "remove", "--force", str(checkout)],
                    cwd=repo_root,
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
        target = subprocess.run(
            ["git", "cat-file", "-e", f"{target_commit}:{path.as_posix()}"],
            cwd=root,
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


def verify_trusted_controller_compatibility(
    repo_root: Path, *, target_commit: str
) -> TrustedControllerCompatibility:
    """Reject a target whose trusted runtime closure differs from committed HEAD."""

    root = repo_root.resolve()
    _git(root, "cat-file", "-e", f"{target_commit}^{{commit}}")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", target_commit, "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if ancestor.returncode != 0:
        raise TrustedControllerCompatibilityError(
            "trusted controller target is not an ancestor of committed HEAD"
        )
    paths = trusted_runtime_source_files(root, target_commit=target_commit)
    changed = _git(root, "diff", "--name-only", target_commit, "HEAD", "--", *paths)
    incompatible = changed.splitlines()
    if changed:
        incompatible = [
            path
            for path in changed.splitlines()
            if path != VERSION_METADATA_FILE.as_posix()
            or not _version_metadata_only(
                root, target_commit=target_commit, path=VERSION_METADATA_FILE
            )
        ]
    if incompatible:
        _verify_installed_authority_consumability(
            root, target_commit=target_commit
        )
        _verify_installed_pending_topology(root, target_commit=target_commit)
        raise TrustedControllerRuntimeStaleError(
            "trusted controller target is stale for runtime files: "
            + ", ".join(incompatible)
        )
    return TrustedControllerCompatibility(target_commit, paths)


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

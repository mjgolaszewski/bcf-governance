"""Compile and project one atomic existing-repository adoption inventory."""

from __future__ import annotations

import hashlib
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..governance_profiles import render_profile_surface


NATIVE_GUIDANCE_PATH = "docs/governance/native-agent-guidance.md"
NO_AUTHENTICATED_NATIVE_BASELINE = "no_authenticated_native_baseline"


@dataclass(frozen=True)
class ExistingAdoptionInventory:
    source_roots: tuple[str, ...]
    test_roots: tuple[str, ...]
    native_agents_sha256: str | None
    source_commit: str | None
    source_tree: str | None
    native_governed_files: tuple[tuple[str, str, str], ...]
    transaction_paths: tuple[str, ...]


def _legacy_audit_move_transaction_paths(repo_root: Path) -> tuple[str, ...]:
    from .. import cleanup_governance_pack as cleanup

    actions = cleanup._audit_move_actions(repo_root)
    replacements = cleanup._reference_replacements(actions)
    paths = {
        value
        for action in actions
        for value in (action.source, action.destination)
        if value is not None
    }
    for path in cleanup._iter_repo_files(repo_root):
        if not cleanup._is_text_file(path):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if any(old in text for old in replacements):
            paths.add(cleanup._repo_relative(repo_root, path))
    return tuple(sorted(paths))


def _apply_legacy_audit_moves(repo_root: Path) -> None:
    from .. import cleanup_governance_pack as cleanup

    actions = cleanup._audit_move_actions(repo_root)
    for action in actions:
        if action.destination is None:
            raise ValueError("legacy audit move is missing its destination")
        cleanup._move_file(repo_root, action.source, action.destination)
    cleanup._prune_empty_dirs(repo_root)
    cleanup._rewrite_references(repo_root, cleanup._reference_replacements(actions))


def _mapping(value: object, *, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be a mapping")
    return value


def _strings(value: object, *, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{context} must be a non-empty string list")
    return tuple(value)


def _safe_roots(repo_root: Path, values: tuple[str, ...], *, context: str) -> tuple[str, ...]:
    roots: list[str] = []
    for raw in values:
        relative = Path(raw)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise ValueError(f"{context} contains unsafe path {raw!r}")
        normalized = relative.as_posix().rstrip("/")
        path = repo_root / normalized
        if not path.is_dir() or path.is_symlink():
            raise ValueError(f"{context} path is not a repository directory: {normalized}")
        tracked = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "--", normalized],
            capture_output=True,
            text=True,
            check=False,
        )
        if tracked.returncode or not tracked.stdout.strip():
            raise ValueError(f"{context} path has no tracked files: {normalized}")
        roots.append(normalized)
    return tuple(sorted(set(roots)))


def _python_roots(repo_root: Path) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    path = repo_root / "pyproject.toml"
    if not path.is_file() or path.is_symlink():
        return None
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    tool = _mapping(payload.get("tool", {}), context="pyproject.toml tool")
    hatch = _mapping(tool.get("hatch", {}), context="pyproject.toml tool.hatch")
    build = _mapping(hatch.get("build", {}), context="pyproject.toml tool.hatch.build")
    targets = _mapping(build.get("targets", {}), context="pyproject.toml tool.hatch.build.targets")
    wheel = _mapping(targets.get("wheel", {}), context="pyproject.toml tool.hatch.build.targets.wheel")
    pytest = _mapping(tool.get("pytest", {}), context="pyproject.toml tool.pytest")
    ini = _mapping(pytest.get("ini_options", {}), context="pyproject.toml tool.pytest.ini_options")
    packages = wheel.get("packages")
    testpaths = ini.get("testpaths")
    if packages is None and testpaths is None:
        return None
    if packages is None or testpaths is None:
        raise ValueError(
            "existing adoption requires both Hatch wheel packages and pytest testpaths when either is declared"
        )
    return (
        _safe_roots(repo_root, _strings(packages, context="Hatch wheel packages"), context="source root"),
        _safe_roots(repo_root, _strings(testpaths, context="pytest testpaths"), context="test root"),
    )


def compile_existing_adoption_inventory(
    repo_root: Path, *, template_root: Path
) -> ExistingAdoptionInventory:
    """Derive every mechanically knowable existing-adoption input before mutation."""

    derived = _python_roots(repo_root)
    source_roots, test_roots = derived or ((), ())
    native = repo_root / "AGENTS.md"
    template_native = template_root / "AGENTS.md"
    native_digest: str | None = None
    transaction_paths = set(_legacy_audit_move_transaction_paths(repo_root))
    if native.is_file() and native.read_bytes() != template_native.read_bytes():
        archive = repo_root / NATIVE_GUIDANCE_PATH
        if archive.exists() and archive.read_bytes() != native.read_bytes():
            raise ValueError(
                f"native instruction custody target already differs: {NATIVE_GUIDANCE_PATH}"
            )
        native_digest = hashlib.sha256(native.read_bytes()).hexdigest()
        transaction_paths.add(NATIVE_GUIDANCE_PATH)
    from .. import cleanup_governance_pack as cleanup

    tracked = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z"],
        capture_output=True,
        check=True,
    ).stdout.split(b"\0")
    governed: list[tuple[str, str, str]] = []
    for raw in tracked:
        if not raw:
            continue
        source = raw.decode("utf-8")
        path = repo_root / source
        if path.suffix.lower() not in {".md", ".yaml", ".yml"} or not any(
            source.startswith(prefix) for prefix in ("docs/", "audits/", "governance/", "plans/", "phases/")
        ):
            continue
        content = path.read_bytes()
        committed = subprocess.run(
            ["git", "-C", str(repo_root), "show", f"HEAD:{source}"],
            capture_output=True,
            check=True,
        ).stdout
        if content != committed:
            raise ValueError(f"native governed file differs from HEAD: {source}")
        governed.append(
            (source, cleanup._destination_for_move(source) or source, hashlib.sha256(content).hexdigest())
        )
    subject = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD", "HEAD^{tree}"],
        capture_output=True,
        text=True,
        check=False,
    )
    identities = subject.stdout.splitlines() if subject.returncode == 0 else []
    if governed and len(identities) != 2:
        raise ValueError("native governed baseline requires an exact Git commit and tree")
    return ExistingAdoptionInventory(
        source_roots=source_roots,
        test_roots=test_roots,
        native_agents_sha256=native_digest,
        source_commit=identities[0] if identities else None,
        source_tree=identities[1] if identities else None,
        native_governed_files=tuple(governed),
        transaction_paths=tuple(sorted(transaction_paths)),
    )


def prepare_existing_adoption_shadow(
    repo_root: Path, *, inventory: ExistingAdoptionInventory | None
) -> None:
    """Project the precompiled inventory inside the install transaction shadow."""

    if inventory is None:
        return
    if inventory.native_agents_sha256 is not None:
        native = repo_root / "AGENTS.md"
        content = native.read_bytes()
        if hashlib.sha256(content).hexdigest() != inventory.native_agents_sha256:
            raise ValueError("native AGENTS.md changed after adoption inventory compilation")
        archive = repo_root / NATIVE_GUIDANCE_PATH
        archive.parent.mkdir(parents=True, exist_ok=True)
        if archive.exists() and archive.read_bytes() != content:
            raise ValueError("native instruction custody target changed during adoption")
        archive.write_bytes(content)
        native.unlink()
    _apply_legacy_audit_moves(repo_root)


def project_existing_adoption_roots(
    repo_root: Path, *, inventory: ExistingAdoptionInventory | None
) -> None:
    """Project authenticated repository roots into their canonical generated owners."""

    if inventory is None:
        return
    if inventory.source_roots and inventory.test_roots:
        agents_path = repo_root / "AGENTS.yml"
        agents = yaml.safe_load(agents_path.read_text(encoding="utf-8"))
        agents["testing_governance"]["test_roots"] = list(inventory.test_roots)
        agents_path.write_text(render_profile_surface(agents, width=120), encoding="utf-8")

        architecture_path = repo_root / "architecture-boundaries.yml"
        architecture = yaml.safe_load(architecture_path.read_text(encoding="utf-8"))
        architecture["architecture"]["source_roots"] = list(inventory.source_roots)
        architecture_path.write_text(
            render_profile_surface(architecture, width=120), encoding="utf-8"
        )
    adoption_path = repo_root / "governance/existing-repo-adoption.yml"
    adoption = yaml.safe_load(adoption_path.read_text(encoding="utf-8"))
    adoption["required_inventory"]["source_roots"] = list(inventory.source_roots)
    adoption["required_inventory"]["test_roots"] = list(inventory.test_roots)
    if inventory.native_governed_files:
        adoption["native_baseline"] = {
            "transition_class": "existing_repository_adoption",
            "source": {
                "commit_sha": inventory.source_commit,
                "tree_sha": inventory.source_tree,
            },
            "files": [
                {
                    "source_path": source,
                    "projected_path": projected,
                    "source_sha256": source_sha256,
                    "projected_sha256": hashlib.sha256(
                        (repo_root / projected).read_bytes()
                    ).hexdigest(),
                }
                for source, projected, source_sha256 in inventory.native_governed_files
            ],
        }
    else:
        adoption["native_baseline"] = {
            "transition_class": NO_AUTHENTICATED_NATIVE_BASELINE,
            "source": None,
            "files": [],
        }
    adoption_path.write_text(render_profile_surface(adoption, width=120), encoding="utf-8")


def migrate_existing_adoption_contract(repo_root: Path) -> None:
    """Expand a legacy installed adoption contract before candidate validation."""

    path = repo_root / "governance/existing-repo-adoption.yml"
    if not path.is_file():
        return
    adoption = _mapping(
        yaml.safe_load(path.read_text(encoding="utf-8")),
        context="governance/existing-repo-adoption.yml",
    )
    baseline = adoption.get("native_baseline")
    legacy_empty = {
        "transition_class": "not_applicable_to_fresh_install",
        "source": None,
        "files": [],
    }
    if baseline is None or baseline == legacy_empty:
        adoption["native_baseline"] = {
            "transition_class": NO_AUTHENTICATED_NATIVE_BASELINE,
            "source": None,
            "files": [],
        }
        path.write_text(render_profile_surface(adoption, width=120), encoding="utf-8")
        return
    baseline = _mapping(baseline, context="existing adoption native_baseline")
    if baseline.get("transition_class") not in {
        NO_AUTHENTICATED_NATIVE_BASELINE,
        "existing_repository_adoption",
    }:
        raise ValueError("existing adoption native_baseline is not an exact migratable shape")


def extend_existing_adoption_paths(
    paths: tuple[str, ...], inventory: ExistingAdoptionInventory | None
) -> tuple[str, ...]:
    return tuple(dict.fromkeys(paths + (inventory.transaction_paths if inventory else ())))

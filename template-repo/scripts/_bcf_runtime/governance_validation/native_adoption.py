"""Authenticate byte-bound native documents during existing-repository adoption."""
# ruff: noqa: F403,F405

from __future__ import annotations

import hashlib
import subprocess

from .common import *  # noqa: F403,F405


def _native_adoption_relative(value: object, *, context: str) -> str:
    raw = _require_string(value, context=context)
    path = Path(raw)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise GovernanceValidationError(f"{context} must be a safe repository-relative path")
    return path.as_posix()


def authenticated_native_adoption_files(repo_root: Path) -> set[str]:
    adoption_path = repo_root / "governance/existing-repo-adoption.yml"
    if not adoption_path.is_file():
        return set()
    profile = _load_yaml(repo_root / "governance-profile.yml")
    ledger = _load_yaml(repo_root / "plans/phase-ledger.yml")
    if profile.get("profile", {}).get("selected") not in {"lite", "standard", "regulated"} or ledger.get(
        "active_phase", {}
    ).get("lifecycle_status") == "completed":
        return set()
    baseline = _require_mapping(
        _load_yaml(adoption_path).get("native_baseline"),
        context="governance/existing-repo-adoption.yml native_baseline",
    )
    if baseline == {
        "transition_class": "no_authenticated_native_baseline",
        "source": None,
        "files": [],
    }:
        return set()
    if baseline.get("transition_class") != "existing_repository_adoption":
        raise GovernanceValidationError("existing adoption native baseline has invalid transition class")
    source = _require_mapping(baseline.get("source"), context="existing adoption native baseline source")
    commit = _require_string(source.get("commit_sha"), context="native baseline source commit")
    tree = _require_string(source.get("tree_sha"), context="native baseline source tree")
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or not re.fullmatch(r"[a-f0-9]{40}", tree):
        raise GovernanceValidationError("existing adoption native baseline has malformed Git identity")
    observed_tree = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", f"{commit}^{{tree}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    ancestor = subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", "--is-ancestor", commit, "HEAD"],
        capture_output=True,
        check=False,
    )
    if observed_tree.returncode or observed_tree.stdout.strip() != tree or ancestor.returncode:
        raise GovernanceValidationError("existing adoption native baseline is not bound to repository history")
    files = baseline.get("files")
    if not isinstance(files, list):
        raise GovernanceValidationError("existing adoption native baseline files must be a list")
    authenticated: set[str] = set()
    for entry_value in files:
        entry = _require_mapping(entry_value, context="existing adoption native baseline file")
        source_path = _native_adoption_relative(
            entry.get("source_path"), context="native baseline source_path"
        )
        projected_path = _native_adoption_relative(
            entry.get("projected_path"), context="native baseline projected_path"
        )
        source_sha = _require_string(entry.get("source_sha256"), context="native baseline source_sha256")
        projected_sha = _require_string(
            entry.get("projected_sha256"), context="native baseline projected_sha256"
        )
        if not re.fullmatch(r"[a-f0-9]{64}", source_sha) or not re.fullmatch(
            r"[a-f0-9]{64}", projected_sha
        ):
            raise GovernanceValidationError("existing adoption native baseline has malformed digest")
        original = subprocess.run(
            ["git", "-C", str(repo_root), "show", f"{commit}:{source_path}"],
            capture_output=True,
            check=False,
        )
        projected = repo_root / projected_path
        if (
            original.returncode
            or hashlib.sha256(original.stdout).hexdigest() != source_sha
            or not projected.is_file()
            or projected.is_symlink()
            or hashlib.sha256(projected.read_bytes()).hexdigest() != projected_sha
            or projected_path in authenticated
        ):
            raise GovernanceValidationError("existing adoption native baseline file binding is invalid")
        authenticated.add(projected_path)
    return authenticated

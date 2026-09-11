"""Transactional semantic-authority scaffold, adoption, and locking commands."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from .governance_install.transaction import apply_transaction, copy_repository_shadow
from .semantic_adoption_diagnostics import validate_adoption_repository
from .semantic_authority_contracts import (
    FAMILIES_PATH,
    LOCK_PATH,
    OPERATIONS_PATH,
    REPRESENTATIONS_PATH,
    SemanticAuthorityError,
    atomic_write,
    build_semantic_lock,
    render_lock_yaml,
    validate_semantic_authority,
)
from .semantic_ownership_inventory import discover_python_source
from .semantic_ownership_registry import load_registry


MANAGED_PATHS = (
    FAMILIES_PATH.as_posix(),
    OPERATIONS_PATH.as_posix(),
    REPRESENTATIONS_PATH.as_posix(),
    LOCK_PATH.as_posix(),
    "governance-profile.yml",
)


def _load_config(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise SemanticAuthorityError("semantic adoption config must be a regular file")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SemanticAuthorityError("semantic adoption config must contain a mapping")
    contracts = payload.get("contracts")
    if not isinstance(contracts, dict):
        raise SemanticAuthorityError("semantic adoption config requires contracts")
    expected = {"semantic_families", "application_operations", "canonical_representations"}
    if set(contracts) != expected or not all(isinstance(value, dict) for value in contracts.values()):
        raise SemanticAuthorityError(
            "semantic adoption contracts must contain semantic_families, application_operations, and canonical_representations"
        )
    unresolved = payload.get("unresolved_classifications", [])
    if not isinstance(unresolved, list) or unresolved:
        raise SemanticAuthorityError(
            "semantic adoption config retains unresolved classifications"
        )
    return payload


def _contract_bytes(payload: dict[str, Any], key: str) -> bytes:
    return yaml.safe_dump(payload["contracts"][key], sort_keys=False, width=1000).encode("utf-8")


def _lock(repo_root: Path, *, apply: bool) -> dict[str, Any]:
    inventory = discover_python_source(repo_root)
    registry = load_registry(repo_root)
    evaluation = validate_semantic_authority(repo_root, inventory, registry, require_lock=False)
    expected = build_semantic_lock(repo_root, inventory, evaluation.projection_outputs)
    path = repo_root / LOCK_PATH
    if apply:
        atomic_write(path, render_lock_yaml(expected))
    else:
        if not path.is_file() or yaml.safe_load(path.read_text(encoding="utf-8")) != expected:
            raise SemanticAuthorityError(
                "governance/semantic-lock.yml is stale; run bcf semantic-ownership lock --apply"
            )
    return expected


def _set_capabilities(repo_root: Path) -> None:
    path = repo_root / "governance-profile.yml"
    profile = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(profile, dict):
        raise SemanticAuthorityError("governance-profile.yml must contain a mapping")
    selected = profile.get("profile", {}).get("selected")
    if selected not in {"standard", "regulated"} or profile.get("profile_contract_version") != "2.0":
        raise SemanticAuthorityError("semantic adoption requires Standard-v2 or Regulated-v2")
    profile["semantic_capabilities"] = {
        "semantic_family_completeness": "blocking",
        "application_operation_inventory": "blocking",
        "representation_provenance": "blocking",
    }
    atomic_write(path, yaml.safe_dump(profile, sort_keys=False, width=120).encode("utf-8"))


def _apply_config(repo_root: Path, payload: dict[str, Any]) -> None:
    atomic_write(repo_root / FAMILIES_PATH, _contract_bytes(payload, "semantic_families"))
    atomic_write(repo_root / OPERATIONS_PATH, _contract_bytes(payload, "application_operations"))
    atomic_write(repo_root / REPRESENTATIONS_PATH, _contract_bytes(payload, "canonical_representations"))
    _set_capabilities(repo_root)
    inventory = discover_python_source(repo_root)
    registry = load_registry(repo_root)
    validate_adoption_repository(repo_root, inventory, registry)
    _lock(repo_root, apply=True)
    validate_semantic_authority(repo_root, inventory, registry)


def _adopt(repo_root: Path, config: Path, *, apply: bool) -> None:
    payload = _load_config(config)
    if apply:
        apply_transaction(
            repo_root,
            managed_paths=MANAGED_PATHS,
            mutate_shadow=lambda shadow: _apply_config(shadow, payload),
            preserve_git_history=True,
        )
        return
    with tempfile.TemporaryDirectory(prefix="bcf-semantic-adopt-") as temporary:
        shadow = Path(temporary) / "repo"
        copy_repository_shadow(repo_root, shadow, preserve_git_history=True)
        _apply_config(shadow, payload)


def _scaffold(repo_root: Path, output: Path) -> None:
    inventory = discover_python_source(repo_root)
    existing: dict[str, Any] = {}
    pairs = (
        ("semantic_families", FAMILIES_PATH),
        ("application_operations", OPERATIONS_PATH),
        ("canonical_representations", REPRESENTATIONS_PATH),
    )
    for key, relative in pairs:
        path = repo_root / relative
        if path.is_file() and not path.is_symlink():
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                existing[key] = loaded
    unresolved = []
    if len(existing) != len(pairs):
        unresolved = [
            {
                "kind": "human_semantic_classification_required",
                "source_file_count": len(inventory["files"]),
                "discovered_type_count": len(inventory["types"]),
                "instruction": "classify material families, public operations, and secondary representations before adoption",
            }
        ]
    payload = {
        "document": {
            "kind": "semantic_authority_adoption_candidate",
            "version": "1.0.0",
            "authority": "non_authoritative_until_complete_adoption",
        },
        "contracts": existing,
        "unresolved_classifications": unresolved,
    }
    target = output if output.is_absolute() else repo_root / output
    atomic_write(target, yaml.safe_dump(payload, sort_keys=False, width=1000).encode("utf-8"))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="bcf semantic-ownership")
    parser.add_argument("command", choices=("scaffold", "adopt", "lock"))
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    parser.add_argument("--config", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    result: dict[str, object]
    try:
        if args.command == "scaffold":
            if args.output is None or args.check or args.apply:
                raise SemanticAuthorityError("scaffold requires --output and no mutation mode")
            _scaffold(repo_root, args.output)
            result = {"status": "candidate_written", "output": str(args.output)}
        elif args.command == "adopt":
            if args.config is None or args.check == args.apply:
                raise SemanticAuthorityError("adopt requires --config and exactly one of --check or --apply")
            _adopt(repo_root, args.config.resolve(), apply=args.apply)
            result = {"status": "adoption_applied" if args.apply else "adoption_check_passed"}
        else:
            if args.check == args.apply:
                raise SemanticAuthorityError("lock requires exactly one of --check or --apply")
            lock = _lock(repo_root, apply=args.apply)
            result = {
                "status": "lock_applied" if args.apply else "lock_check_passed",
                "projection_outputs": len(lock["projection_outputs"]),
            }
    except SemanticAuthorityError as exc:
        print(f"semantic-ownership-{args.command}-failed: {exc}")
        raise SystemExit(1) from exc
    print(json.dumps(result, sort_keys=True))

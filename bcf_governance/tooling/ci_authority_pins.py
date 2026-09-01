"""Deterministically bind CI authority entries to committed workflow bytes."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
from itertools import product
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any

import yaml


class CIAuthorityPinError(ValueError):
    """Raised when workflow custody cannot be derived exactly from Git."""


@dataclass(frozen=True)
class CIAuthorityPinResult:
    status: str
    changed_paths: tuple[str, ...]
    definition_commit: str
    references: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "changed_paths": list(self.changed_paths),
            "definition_commit": self.definition_commit,
            "references": list(self.references),
        }


def _git(root: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise CIAuthorityPinError("workflow custody is not available from exact Git history")
    return result.stdout


def _mapping(path: Path) -> tuple[bytes, dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise CIAuthorityPinError("CI authority must be a regular tracked file")
    raw = path.read_bytes()
    try:
        value = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise CIAuthorityPinError("CI authority is invalid YAML") from exc
    if not isinstance(value, dict):
        raise CIAuthorityPinError("CI authority must contain a mapping")
    return raw, value


def _matrix_combinations(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    axes: list[tuple[str, list[str | int | float | bool]]] = []
    for key, values in matrix.items():
        if key in {"include", "exclude"}:
            continue
        if not isinstance(key, str) or not isinstance(values, list) or not values:
            raise CIAuthorityPinError("workflow matrix axes must be nonempty lists")
        if any(not isinstance(item, (str, int, float, bool)) for item in values):
            raise CIAuthorityPinError("workflow matrix values must be scalar")
        axes.append((key, values))
    combinations = [
        dict(zip((key for key, _ in axes), values, strict=True))
        for values in (product(*(items for _, items in axes)) if axes else [()])
    ]
    excludes = matrix.get("exclude", [])
    includes = matrix.get("include", [])
    if not isinstance(excludes, list) or any(not isinstance(item, dict) for item in excludes):
        raise CIAuthorityPinError("workflow matrix exclude must be a mapping list")
    if not isinstance(includes, list) or any(not isinstance(item, dict) for item in includes):
        raise CIAuthorityPinError("workflow matrix include must be a mapping list")
    combinations = [
        combination
        for combination in combinations
        if not any(
            all(combination.get(key) == value for key, value in excluded.items())
            for excluded in excludes
        )
    ]
    for included in includes:
        if any(not isinstance(value, (str, int, float, bool)) for value in included.values()):
            raise CIAuthorityPinError("workflow matrix include values must be scalar")
        compatible = [
            combination
            for combination in combinations
            if all(key not in combination or combination[key] == value for key, value in included.items())
        ]
        if len(compatible) > 1:
            raise CIAuthorityPinError("workflow matrix include is ambiguous")
        if compatible:
            compatible[0].update(included)
        else:
            combinations.append(dict(included))
    return combinations


def _compiled_workflow_jobs(
    raw: bytes, *, roles: dict[str, str] | None
) -> list[tuple[str, dict[str, Any]]]:
    """Compile exact provider job names from one committed workflow definition."""

    try:
        workflow = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise CIAuthorityPinError("committed workflow is invalid YAML") from exc
    jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
    if not isinstance(jobs, dict) or not jobs:
        raise CIAuthorityPinError("committed workflow has no job inventory")
    role_policy = roles or {}
    if set(role_policy) - set(jobs):
        raise CIAuthorityPinError("workflow role policy names an unknown source job")
    if role_policy and set(role_policy) != set(jobs):
        raise CIAuthorityPinError("workflow role policy must classify every source job")
    inventory: list[tuple[str, dict[str, Any]]] = []
    for source_job, value in jobs.items():
        if not isinstance(source_job, str) or not isinstance(value, dict):
            raise CIAuthorityPinError("workflow job definitions must be mappings")
        display_name = value.get("name", source_job)
        if not isinstance(display_name, str) or not display_name:
            raise CIAuthorityPinError("workflow job name must be a nonempty literal")
        strategy = value.get("strategy", {})
        if not isinstance(strategy, dict):
            raise CIAuthorityPinError("workflow job strategy must be a mapping")
        matrix = strategy.get("matrix", {})
        if not isinstance(matrix, dict):
            raise CIAuthorityPinError("workflow job matrix must be a mapping")
        for observed in _matrix_combinations(matrix):
            rendered = display_name
            for key, item in observed.items():
                rendered = re.sub(
                    rf"\$\{{\{{\s*matrix\.{re.escape(key)}\s*\}}\}}",
                    str(item),
                    rendered,
                )
            if "${{" in rendered:
                raise CIAuthorityPinError(
                    "privileged workflow job names may use only declared matrix expressions"
                )
            job: dict[str, Any] = {"job_id": rendered}
            if source_job in role_policy:
                job["role"] = role_policy[source_job]
            inventory.append((source_job, job))
    if len({str(value["job_id"]) for _, value in inventory}) != len(inventory):
        raise CIAuthorityPinError("compiled provider job names are not unique")
    return inventory


def _compile_inventories(
    payload: dict[str, Any], committed_workflows: dict[str, bytes]
) -> None:
    registry = payload["workflow_registry"]
    for reference, entry in registry.items():
        if "expected_jobs" not in entry:
            continue
        roles = entry.get("job_roles")
        if roles is not None and not isinstance(roles, dict):
            raise CIAuthorityPinError("workflow role policy must be a mapping")
        entry["expected_jobs"] = [
            value
            for _, value in _compiled_workflow_jobs(
                committed_workflows[str(reference)],
                roles={str(key): str(value) for key, value in (roles or {}).items()},
            )
        ]
    roles = payload.get("roles")
    producers = payload.get("producers")
    if roles is None and producers is None:
        return
    if not isinstance(roles, dict) or not isinstance(producers, list):
        raise CIAuthorityPinError("CI authority role and producer policy is incomplete")
    admission_reference = str(roles.get("admission", ""))
    admission_entry = registry.get(admission_reference)
    if not isinstance(admission_entry, dict):
        raise CIAuthorityPinError("CI authority admission workflow is not registered")
    source_roles = admission_entry.get("job_roles")
    producer_ids = {
        str(value.get("producer_id", ""))
        for value in producers
        if isinstance(value, dict)
    }
    if source_roles is None:
        raw_jobs = _compiled_workflow_jobs(
            committed_workflows[admission_reference], roles=None
        )
        source_keys = {source for source, _ in raw_jobs}
        other = source_keys - producer_ids
        if not producer_ids.issubset(source_keys) or len(other) != 1:
            raise CIAuthorityPinError(
                "admission jobs cannot be inferred from exact producer source keys"
            )
        caller_jobs = [
            (
                source,
                {**value, "role": "producer" if source in producer_ids else "admission"},
            )
            for source, value in raw_jobs
        ]
    elif isinstance(source_roles, dict):
        caller_jobs = _compiled_workflow_jobs(
            committed_workflows[admission_reference],
            roles={str(key): str(value) for key, value in source_roles.items()},
        )
    else:
        raise CIAuthorityPinError("admission workflow source-job policy is invalid")
    admission_jobs = [
        dict(value) for _, value in caller_jobs if value.get("role") == "admission"
    ]
    for value in admission_jobs:
        value.pop("role", None)
    if len(admission_jobs) != 1:
        raise CIAuthorityPinError("admission workflow must compile exactly one admission job")
    payload["admission_jobs"] = admission_jobs
    caller_producers = {
        source: value
        for source, value in caller_jobs
        if value.get("role") == "producer"
    }
    if set(caller_producers) != producer_ids:
        raise CIAuthorityPinError(
            "admission source producer jobs must exactly match producer IDs"
        )
    for producer in producers:
        if not isinstance(producer, dict):
            raise CIAuthorityPinError("CI authority producer must be a mapping")
        producer_id = str(producer["producer_id"])
        reference = str(producer.get("workflow_ref", ""))
        if reference not in committed_workflows:
            raise CIAuthorityPinError("producer workflow reference is not registered")
        caller_name = str(caller_producers[producer_id]["job_id"])
        producer["expected_jobs"] = [
            {"job_id": f"{caller_name} / {value['job_id']}"}
            for _, value in _compiled_workflow_jobs(
                committed_workflows[reference], roles=None
            )
        ]


def verify_workflow_authority(
    repo_root: Path, *, authority_path: Path
) -> int:
    """Verify all local custody facts against exact committed workflow bytes."""

    root = repo_root.resolve()
    authority = authority_path if authority_path.is_absolute() else root / authority_path
    try:
        authority.resolve().relative_to(root)
    except ValueError as exc:
        raise CIAuthorityPinError("CI authority must remain inside the repository") from exc
    _, payload = _mapping(authority)
    registry = payload.get("workflow_registry")
    if payload.get("schema_version") != "1.1" or not isinstance(registry, dict):
        return 0
    compiled = deepcopy(payload)
    committed_workflows: dict[str, bytes] = {}
    for reference, entry in registry.items():
        if not isinstance(entry, dict):
            raise CIAuthorityPinError("workflow registry entry must be a mapping")
        path = str(entry.get("active_path", ""))
        if not path.startswith(".github/workflows/") or ".." in Path(path).parts:
            raise CIAuthorityPinError("workflow authority path is unsafe")
        definition_commit = str(entry.get("trusted_workflow_definition_commit", ""))
        if not re.fullmatch(r"[a-f0-9]{40,64}", definition_commit):
            raise CIAuthorityPinError("workflow definition commit is not exact")
        _git(root, "merge-base", "--is-ancestor", definition_commit, "HEAD")
        committed = _git(root, "show", f"{definition_commit}:{path}")
        current = root / path
        if current.is_symlink() or not current.is_file() or current.read_bytes() != committed:
            raise CIAuthorityPinError(
                f"current workflow bytes differ from authority: {reference}"
            )
        blob = _git(root, "rev-parse", f"{definition_commit}:{path}").decode().strip()
        if entry.get("trusted_workflow_blob_oid") != blob:
            raise CIAuthorityPinError(f"workflow blob pin mismatched: {reference}")
        if entry.get("trusted_workflow_sha256") != hashlib.sha256(committed).hexdigest():
            raise CIAuthorityPinError(f"workflow digest pin mismatched: {reference}")
        committed_workflows[str(reference)] = committed
    _compile_inventories(compiled, committed_workflows)
    if compiled != payload:
        raise CIAuthorityPinError(
            "workflow job inventories are not mechanically compiled from authority bytes"
        )
    return len(registry)


def pin_workflow_authority(
    repo_root: Path,
    *,
    authority_path: Path,
    definition_commit: str,
    references: tuple[str, ...],
    apply: bool,
) -> CIAuthorityPinResult:
    """Derive exact blob and SHA-256 pins; optionally update the canonical registry."""

    root = repo_root.resolve()
    if not re.fullmatch(r"[a-f0-9]{40,64}", definition_commit):
        raise CIAuthorityPinError("definition commit must be an exact Git object ID")
    if len(set(references)) != len(references):
        raise CIAuthorityPinError("workflow references must be unique")
    authority = authority_path if authority_path.is_absolute() else root / authority_path
    try:
        relative = authority.resolve().relative_to(root).as_posix()
    except ValueError as exc:
        raise CIAuthorityPinError("CI authority must remain inside the repository") from exc
    raw, payload = _mapping(authority)
    registry = payload.get("workflow_registry")
    if payload.get("schema_version") != "1.1" or not isinstance(registry, dict):
        raise CIAuthorityPinError("workflow pinning requires authority contract version 1.1")
    _git(root, "cat-file", "-e", f"{definition_commit}^{{commit}}")
    selected = references or tuple(str(value) for value in registry)
    if set(selected) != set(registry):
        raise CIAuthorityPinError(
            "workflow authority pinning must compile the complete registry"
        )
    committed_workflows: dict[str, bytes] = {}
    for reference in selected:
        entry = registry.get(reference)
        if not isinstance(entry, dict):
            raise CIAuthorityPinError(f"workflow reference is not registered: {reference}")
        path = str(entry.get("active_path", ""))
        if not path.startswith(".github/workflows/") or ".." in Path(path).parts:
            raise CIAuthorityPinError("workflow authority path is unsafe")
        committed = _git(root, "show", f"{definition_commit}:{path}")
        committed_workflows[reference] = committed
        current_path = root / path
        if current_path.is_symlink() or not current_path.is_file() or current_path.read_bytes() != committed:
            raise CIAuthorityPinError(
                f"current workflow bytes differ from definition commit: {reference}"
            )
        blob = _git(root, "rev-parse", f"{definition_commit}:{path}").decode().strip()
        entry["trusted_workflow_blob_oid"] = blob
        entry["trusted_workflow_sha256"] = hashlib.sha256(committed).hexdigest()
        entry["trusted_workflow_definition_commit"] = definition_commit
    _compile_inventories(payload, committed_workflows)
    desired_raw = yaml.safe_dump(
        payload,
        sort_keys=False,
        allow_unicode=False,
        width=1000,
    ).encode("utf-8")
    return _finish(
        authority,
        relative=relative,
        raw=raw,
        desired_raw=desired_raw,
        definition_commit=definition_commit,
        selected=selected,
        apply=apply,
    )


def _finish(
    authority: Path,
    *,
    relative: str,
    raw: bytes,
    desired_raw: bytes,
    definition_commit: str,
    selected: tuple[str, ...],
    apply: bool,
) -> CIAuthorityPinResult:
    changed = desired_raw != raw
    if changed and apply:
        descriptor, temporary = tempfile.mkstemp(prefix=".ci-authority-", dir=authority.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(desired_raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, authority.stat().st_mode & 0o777)
            os.replace(temporary, authority)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return CIAuthorityPinResult(
        status="changed" if changed else "clean",
        changed_paths=(relative,) if changed else (),
        definition_commit=definition_commit,
        references=selected,
    )

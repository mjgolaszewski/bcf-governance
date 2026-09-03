"""Deterministic generated-surface projections for trusted automation PRs."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from .automation_contracts import AutomationContractError, ProducerMatch
from .ci_github_api import GitHubAPI


def _manifest(content: bytes, *, path: str) -> dict[str, Any]:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AutomationContractError(
            f"mechanical projection manifest is not canonical JSON: {path}"
        ) from exc
    if not isinstance(value, dict) or not isinstance(value.get("files"), dict):
        raise AutomationContractError(
            f"mechanical projection manifest has no files mapping: {path}"
        )
    return value


def _set_manifest_digest(
    value: dict[str, Any], *, manifest_path: str, entry_path: str, digest: str
) -> dict[str, Any]:
    projected = copy.deepcopy(value)
    entry = projected["files"].get(entry_path)
    if not isinstance(entry, dict) or not isinstance(entry.get("sha256"), str):
        raise AutomationContractError(
            f"mechanical projection manifest entry is missing: "
            f"{manifest_path}:{entry_path}"
        )
    entry["sha256"] = digest
    return projected


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def project_automation_outputs(
    observer: GitHubAPI,
    *,
    repository: str,
    main_sha: str,
    candidate_sha: str,
    match: ProducerMatch,
) -> dict[str, bytes]:
    """Render declared copies and hash manifests without executing candidate code."""

    outputs: dict[str, bytes] = {}
    changed_sources = set(match.dependency_paths)
    changed_outputs = set(match.projection_output_paths)
    for projection in match.producer.get("mechanical_projections", []):
        source_path = str(projection["source_path"])
        copy_targets = tuple(str(path) for path in projection["exact_copy_targets"])
        manifests = tuple(projection["sha256_manifest_entries"])
        projection_outputs = set(copy_targets).union(
            str(item["manifest_path"]) for item in manifests
        )
        if source_path not in changed_sources:
            forged = sorted(projection_outputs.intersection(changed_outputs))
            if forged:
                raise AutomationContractError(
                    "mechanical projection output changed without its source: "
                    + ", ".join(forged)
                )
            continue

        main_source = observer.content(repository, source_path, ref=main_sha).content
        candidate_source = observer.content(
            repository, source_path, ref=candidate_sha
        ).content
        candidate_digest = hashlib.sha256(candidate_source).hexdigest()

        for target_path in copy_targets:
            main_target = observer.content(repository, target_path, ref=main_sha).content
            if main_target != main_source:
                raise AutomationContractError(
                    f"mechanical projection baseline copy is stale: {target_path}"
                )
            candidate_target = observer.content(
                repository, target_path, ref=candidate_sha
            ).content
            if candidate_target not in {main_target, candidate_source}:
                raise AutomationContractError(
                    f"mechanical projection copy was independently modified: {target_path}"
                )
            if candidate_target != candidate_source:
                outputs[target_path] = candidate_source

        for item in manifests:
            manifest_path = str(item["manifest_path"])
            entry_path = str(item["entry_path"])
            main_content = observer.content(
                repository, manifest_path, ref=main_sha
            ).content
            candidate_content = observer.content(
                repository, manifest_path, ref=candidate_sha
            ).content
            baseline = _manifest(main_content, path=manifest_path)
            baseline_digest = hashlib.sha256(main_source).hexdigest()
            baseline_entry = baseline["files"].get(entry_path)
            if (
                not isinstance(baseline_entry, dict)
                or baseline_entry.get("sha256") != baseline_digest
            ):
                raise AutomationContractError(
                    f"mechanical projection baseline manifest is stale: "
                    f"{manifest_path}:{entry_path}"
                )
            expected = _set_manifest_digest(
                baseline,
                manifest_path=manifest_path,
                entry_path=entry_path,
                digest=candidate_digest,
            )
            candidate = _manifest(candidate_content, path=manifest_path)
            if candidate != baseline and candidate != expected:
                raise AutomationContractError(
                    f"mechanical projection manifest was independently modified: "
                    f"{manifest_path}"
                )
            rendered = _json_bytes(expected)
            if candidate_content != rendered:
                outputs[manifest_path] = rendered
    return dict(sorted(outputs.items()))

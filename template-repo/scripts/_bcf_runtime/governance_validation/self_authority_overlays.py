"""Typed ownership and non-leakage checks for self-only authority overlays."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator


class SelfAuthorityOverlayError(ValueError):
    """The self overlay contract is incomplete, ambiguous, or leaks to adopters."""


def _mapping(value: object, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SelfAuthorityOverlayError(f"{context} must be a mapping")
    return value


def _sequence(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise SelfAuthorityOverlayError(f"{context} must be a list")
    return value


def _path(root: Path, value: object, context: str) -> tuple[str, Path]:
    if not isinstance(value, str) or not value or Path(value).is_absolute() or ".." in Path(value).parts:
        raise SelfAuthorityOverlayError(f"{context} must be a safe repository-relative path")
    return value, root / value


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        return _mapping(yaml.safe_load(path.read_text(encoding="utf-8")), str(path))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise SelfAuthorityOverlayError(f"cannot read {path}") from exc


def validate_self_authority_overlays(repo_root: Path) -> dict[str, tuple[str, ...]]:
    """Validate exact overlay ownership and derive its generated workflow inventory."""
    root = repo_root.resolve()
    contract_path = root / "governance/self-overlays.yml"
    self_policy = root / "governance/self-governance-policy.yml"
    if not contract_path.is_file():
        if self_policy.is_file():
            raise SelfAuthorityOverlayError("self-governance requires governance/self-overlays.yml")
        return {}
    contract = _load_yaml(contract_path)
    schema_path = root / "schemas/self-authority-overlays.schema.json"
    try:
        schema = _mapping(json.loads(schema_path.read_text(encoding="utf-8")), str(schema_path))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SelfAuthorityOverlayError("cannot read self overlay schema") from exc
    errors = sorted(Draft202012Validator(schema).iter_errors(contract), key=lambda error: list(error.path))
    if errors:
        raise SelfAuthorityOverlayError(
            "self overlay contract violates schema: " + errors[0].message
        )
    overlays = _sequence(contract.get("overlays"), "self overlays")
    by_id: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(overlays):
        overlay = _mapping(raw, f"self overlays[{index}]")
        overlay_id = overlay.get("id")
        if not isinstance(overlay_id, str) or overlay_id in by_id:
            raise SelfAuthorityOverlayError("self overlay ids must be unique strings")
        by_id[overlay_id] = overlay
    graph = _load_yaml(root / "governance/ci-graph.yml")
    graph_extensions = {
        str(ref.get("id")): _mapping(ref, "CI graph extension")
        for ref in _sequence(graph.get("extensions"), "CI graph extensions")
        if isinstance(ref, dict)
    }
    declared_extensions: dict[str, str] = {}
    declared_surfaces: dict[str, str] = {}
    generated_workflows: dict[str, tuple[str, ...]] = {}
    manifest_path = root / "template-repo/.bcf-pack-manifest.json"
    try:
        manifest = _mapping(json.loads(manifest_path.read_text(encoding="utf-8")), str(manifest_path))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SelfAuthorityOverlayError("cannot read canonical adopter pack manifest") from exc
    packed = set(_mapping(manifest.get("files"), "pack manifest files"))

    for overlay_id, overlay in by_id.items():
        extension_ids = tuple(_sequence(overlay.get("graph_extensions"), f"{overlay_id}.graph_extensions"))
        surfaces = _sequence(overlay.get("authority_surfaces"), f"{overlay_id}.authority_surfaces")
        for index, raw_path in enumerate(surfaces):
            relative, path = _path(root, raw_path, f"{overlay_id}.authority_surfaces[{index}]")
            if relative in declared_surfaces:
                raise SelfAuthorityOverlayError(
                    f"self authority surface {relative} is owned by multiple overlays"
                )
            if not path.is_file() or path.is_symlink():
                raise SelfAuthorityOverlayError(f"self authority surface {relative} is unavailable")
            if relative in packed:
                raise SelfAuthorityOverlayError(f"self authority surface {relative} leaks into the adopter pack")
            declared_surfaces[relative] = overlay_id

        workflow_paths: list[str] = []
        for extension_id in extension_ids:
            if not isinstance(extension_id, str) or extension_id in declared_extensions:
                raise SelfAuthorityOverlayError("CI graph extensions must have one overlay owner")
            ref = graph_extensions.get(extension_id)
            if ref is None:
                raise SelfAuthorityOverlayError(f"overlay extension {extension_id} is absent from the CI graph")
            relative, extension_path = _path(root, ref.get("path"), f"extension {extension_id}.path")
            if declared_surfaces.get(relative) != overlay_id:
                raise SelfAuthorityOverlayError(
                    f"overlay {overlay_id} must own its extension source {relative}"
                )
            expected_digest = ref.get("sha256")
            if not isinstance(expected_digest, str) or hashlib.sha256(extension_path.read_bytes()).hexdigest() != expected_digest:
                raise SelfAuthorityOverlayError(f"overlay extension {extension_id} digest is stale")
            extension = _load_yaml(extension_path)
            identity = _mapping(extension.get("extension"), f"extension {extension_id}")
            if identity.get("id") != extension_id:
                raise SelfAuthorityOverlayError(f"overlay extension {extension_id} identity differs from its graph reference")
            for workflow in _sequence(extension.get("workflows"), f"extension {extension_id}.workflows"):
                workflow_path, rendered = _path(root, _mapping(workflow, "extension workflow").get("path"), "extension workflow path")
                if not rendered.is_file() or rendered.is_symlink():
                    raise SelfAuthorityOverlayError(f"generated self workflow {workflow_path} is unavailable")
                if workflow_path in packed:
                    raise SelfAuthorityOverlayError(f"generated self workflow {workflow_path} leaks into the adopter pack")
                if any(workflow_path in paths for paths in generated_workflows.values()):
                    raise SelfAuthorityOverlayError(f"generated self workflow {workflow_path} has multiple overlay owners")
                workflow_paths.append(workflow_path)
            declared_extensions[extension_id] = overlay_id
        generated_workflows[overlay_id] = tuple(sorted(workflow_paths))

    if set(declared_extensions) != set(graph_extensions):
        raise SelfAuthorityOverlayError("every self CI graph extension must have exactly one overlay owner")
    trusted = _mapping(graph.get("trusted_controller"), "CI graph trusted_controller")
    if trusted != {
        "kind": "self_governance_policy",
        "policy_path": "governance/self-governance-policy.yml",
    } or declared_surfaces.get("governance/self-governance-policy.yml") != "self-controller-custody":
        raise SelfAuthorityOverlayError("self controller custody is not bound to its exact policy surface")
    value_sources = _mapping(graph.get("value_sources"), "CI graph value_sources")
    undeclared_self_sources = sorted(
        str(source.get("path"))
        for source in value_sources.values()
        if isinstance(source, dict)
        and isinstance(source.get("path"), str)
        and source["path"] not in packed
        and source["path"] not in declared_surfaces
    )
    if undeclared_self_sources:
        raise SelfAuthorityOverlayError(
            "self-only CI value sources lack overlay ownership: " + ", ".join(undeclared_self_sources)
        )
    non_leakage = _mapping(contract.get("non_leakage"), "self overlay non_leakage")
    adopter_extension = str(non_leakage.get("canonical_opt_in_controller_extension", ""))
    if adopter_extension not in packed or adopter_extension in declared_surfaces:
        raise SelfAuthorityOverlayError("canonical opt-in controller management must remain adopter product")
    return generated_workflows

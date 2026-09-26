"""Mechanical validation of BCF product benchmarks and simplicity custody."""

from __future__ import annotations

import math
from pathlib import Path
import statistics
from typing import Any

from ..ci_graph_contracts import validate_ci_graph


class ProductCertificationError(ValueError):
    """The empirical product-certification contract is incomplete or inconsistent."""


INVALIDATION_CLASSES = {
    "implementation",
    "test_population",
    "evidence_runtime",
    "governance_profile",
    "toolchain_dependencies",
    "workflow_trust",
    "negative_control_oracle",
}


def _mapping(value: object, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProductCertificationError(f"{context} must be a mapping")
    return value


def _list(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProductCertificationError(f"{context} must be a list")
    return value


def _nearest_rank_p95(values: list[int]) -> int:
    return sorted(values)[math.ceil(len(values) * 0.95) - 1]


def _validate_samples(
    samples: object, *, path: str, live_provider: bool
) -> tuple[int, int]:
    values = _list(samples, path)
    if len(values) < 5:
        raise ProductCertificationError(f"{path} requires at least five observations")
    feedback: list[int] = []
    certification: list[int] = []
    subjects: set[str] = set()
    for index, raw in enumerate(values):
        sample = _mapping(raw, f"{path}[{index}]")
        subject = sample.get("subject_commit")
        if not isinstance(subject, str) or len(subject) != 40 or subject in subjects:
            raise ProductCertificationError(f"{path} subjects must be unique exact commits")
        subjects.add(subject)
        if any(sample.get(key) != 0 for key in ("new_groups", "invalidated_groups")):
            raise ProductCertificationError(f"{path} all-equivalent samples executed semantic work")
        reused = sample.get("reused_groups")
        avoided = sample.get("nodes_avoided")
        if not isinstance(reused, int) or reused < 1 or avoided != reused:
            raise ProductCertificationError(f"{path} reuse inventory is incomplete")
        for key, target in (("feedback_seconds", feedback), ("certification_seconds", certification)):
            value = sample.get(key)
            if not isinstance(value, int) or value < 0:
                raise ProductCertificationError(f"{path} {key} is invalid")
            target.append(value)
        custody = _mapping(sample.get("custody"), f"{path}[{index}].custody")
        keys = (
            ("pr_run", "exact_main_run", "finalizer_run", "publisher_run")
            if live_provider
            else ("fixture_run", "proof_node")
        )
        if any(not isinstance(custody.get(key), str) or not custody[key] for key in keys):
            raise ProductCertificationError(f"{path} custody identity is incomplete")
    return int(statistics.median(feedback)), _nearest_rank_p95(certification)


def _validate_rotations(values: object, *, path: str, live_provider: bool) -> None:
    rotations = _list(values, path)
    if len(rotations) < 2:
        raise ProductCertificationError(f"{path} requires two consecutive rotations")
    installed = None
    for index, raw in enumerate(rotations):
        rotation = _mapping(raw, f"{path}[{index}]")
        if rotation.get("installed_controller") != installed and index:
            raise ProductCertificationError(f"{path} controller chain is discontinuous")
        installed = rotation.get("target_controller")
        if not isinstance(installed, str) or len(installed) != 40:
            raise ProductCertificationError(f"{path} target controller is invalid")
        if (
            rotation.get("implementation_pr_count") != 1
            or rotation.get("bookkeeping_pr_count") != 0
            or rotation.get("copied_identity_count") != 0
        ):
            raise ProductCertificationError(f"{path} retains redundant rotation ceremony")
        if live_provider:
            for key in ("transition_run", "receipt_artifact", "final_publisher_run"):
                if not isinstance(rotation.get(key), str) or not rotation[key]:
                    raise ProductCertificationError(f"{path} lacks immutable {key}")


def validate_product_certification(repo_root: Path, contract: dict[str, Any]) -> None:
    """Recompute measurements and require minimum justified product machinery."""

    equivalent = _mapping(contract.get("equivalent_transitions"), "equivalent_transitions")
    self_median, self_cert_p95 = _validate_samples(
        equivalent.get("self"), path="self", live_provider=True
    )
    _validate_samples(equivalent.get("adopter"), path="adopter", live_provider=False)
    metrics = _mapping(contract.get("derived_metrics"), "derived_metrics")
    if metrics.get("self_feedback_median_seconds") != self_median:
        raise ProductCertificationError("self feedback median is not mechanically derived")
    if metrics.get("self_certification_p95_seconds") != self_cert_p95:
        raise ProductCertificationError("self certification p95 is not mechanically derived")
    invalidation = _list(contract.get("selective_invalidation"), "selective_invalidation")
    observed = {item.get("class") for item in invalidation if isinstance(item, dict)}
    if observed != INVALIDATION_CLASSES or len(invalidation) != len(observed):
        raise ProductCertificationError("selective invalidation classes are not exact")
    manifest = set(
        (repo_root / "governance/test-manifests/test.txt").read_text(encoding="utf-8").splitlines()
    )
    for item in invalidation:
        if item.get("proof_node") not in manifest or item.get("decision") not in {
            "reuse", "invalidate", "reject"
        }:
            raise ProductCertificationError("selective invalidation proof is unavailable")
    rotations = _mapping(contract.get("routine_rotations"), "routine_rotations")
    _validate_rotations(rotations.get("self"), path="self rotations", live_provider=True)
    _validate_rotations(rotations.get("adopter"), path="adopter rotations", live_provider=False)
    adopter_node = rotations.get("adopter_proof_node")
    if adopter_node not in manifest:
        raise ProductCertificationError("installed-adopter rotation proof is unavailable")
    simplicity = _mapping(contract.get("simplicity"), "simplicity")
    workflows = _list(simplicity.get("workflows"), "simplicity.workflows")
    compiled = validate_ci_graph(repo_root)
    if sorted(item.get("id") for item in workflows if isinstance(item, dict)) != sorted(
        item["id"] for item in compiled.workflows
    ):
        raise ProductCertificationError("workflow simplicity inventory differs from graph")
    mechanisms = _list(simplicity.get("mechanisms"), "simplicity.mechanisms")
    propositions = [item.get("proposition") for item in mechanisms if isinstance(item, dict)]
    if len(mechanisms) != len(propositions) or len(propositions) != len(set(propositions)):
        raise ProductCertificationError("mandatory mechanisms lack unique propositions")
    if any(not item.get("provider_boundary") for item in mechanisms):
        raise ProductCertificationError("mandatory mechanism lacks a provider boundary")
    if contract.get("release_authority") is not False:
        raise ProductCertificationError("empirical certification cannot confer release authority")

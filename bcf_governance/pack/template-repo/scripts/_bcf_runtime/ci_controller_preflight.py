"""Preflight projection owner for self and installed controller custody."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Callable, Mapping

import yaml

from .ci_controller_policy import POLICY_PATH, load_installed_controller_policy
from .ci_github_identity import GitHubControllerError
from .ci_graph_contracts import validate_ci_graph
from .ci_self_controller import verify_self_controller_projection
from .trusted_controller_compatibility import (
    TrustedControllerCompatibilityError,
    TrustedControllerRoutineRotationIncompatibleError,
    TrustedControllerRuntimeStaleError,
    ordinary_alternate_lane_available,
    verify_pr_bootstrap_compatibility,
    verify_trusted_controller_compatibility,
)


class ControllerPreflightError(ValueError):
    """Controller state cannot be admitted before evidence."""


def controller_preflight_projection(
    repo_root: Path,
    *,
    self_verifier: Callable[[Path], int] = verify_self_controller_projection,
) -> tuple[dict[str, Any], int] | None:
    """Return validated controller policy and projection count when installed."""

    self_policy = repo_root / "governance/self-governance-policy.yml"
    installed_policy = repo_root / POLICY_PATH
    if self_policy.is_file():
        payload = yaml.safe_load(self_policy.read_text(encoding="utf-8"))
        return payload, self_verifier(repo_root)
    if installed_policy.is_file():
        payload = load_installed_controller_policy(repo_root)
        return payload, len(validate_ci_graph(repo_root).input_sha256) + 1
    return None


def self_controller_preflight(
    repo_root: Path,
    *,
    allow_stale_runtime: bool = False,
    pr_base_sha: str | None = None,
    transported_authority: Mapping[str, Any] | None = None,
    self_verifier: Callable[[Path], int] = verify_self_controller_projection,
    compatibility_verifier: Callable[..., None] = verify_trusted_controller_compatibility,
    bootstrap_verifier: Callable[..., None] = verify_pr_bootstrap_compatibility,
    alternate_lane: Callable[[Path], bool] = ordinary_alternate_lane_available,
) -> int | dict[str, Any]:
    """Compile one typed controller result for PR, release, or prospective use."""

    projection = controller_preflight_projection(
        repo_root, self_verifier=self_verifier
    )
    if projection is None:
        return 0
    payload, count = projection
    runner = payload.get("runner_security") if isinstance(payload, dict) else None
    if not isinstance(runner, dict) or "trusted_controller_artifact" not in runner:
        return 0
    try:
        target = str(runner["trusted_controller_artifact"]["BCF_BOOTSTRAP_COMMIT_SHA"])
        if transported_authority is not None:
            transported_commit = transported_authority.get("controller_commit_sha")
            transported_bundle = transported_authority.get("controller_bundle_sha256")
            if (
                set(transported_authority) != {
                    "controller_commit_sha", "controller_bundle_sha256"
                }
                or not isinstance(transported_commit, str)
                or not re.fullmatch(r"[a-f0-9]{40}", transported_commit)
                or not isinstance(transported_bundle, str)
                or not re.fullmatch(r"[a-f0-9]{64}", transported_bundle)
            ):
                raise TrustedControllerCompatibilityError(
                    "transported controller authority is invalid"
                )
            target = transported_commit
        if pr_base_sha is not None:
            bootstrap_verifier(
                repo_root, base_commit=pr_base_sha, target_commit=target
            )
        try:
            compatibility_verifier(repo_root, target_commit=target)
        except TrustedControllerRoutineRotationIncompatibleError:
            if not allow_stale_runtime or not alternate_lane(repo_root):
                raise
            return {
                "status": "pending_rotation",
                "projection_count": count,
                "transition_requirement": "alternate_lane_required",
                "release_authority": False,
            }
        except TrustedControllerRuntimeStaleError:
            if not allow_stale_runtime:
                raise
            return {
                "status": "pending_rotation",
                "projection_count": count,
                "release_authority": False,
            }
        return count
    except (
        GitHubControllerError,
        KeyError,
        TypeError,
        TrustedControllerCompatibilityError,
    ) as exc:
        raise ControllerPreflightError(
            f"self-controller preflight failed: {exc}"
        ) from exc

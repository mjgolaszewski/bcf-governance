"""Preflight projection owner for self and installed controller custody."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import yaml

from .ci_controller_policy import POLICY_PATH, load_installed_controller_policy
from .ci_graph_contracts import validate_ci_graph
from .ci_self_controller import verify_self_controller_projection


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

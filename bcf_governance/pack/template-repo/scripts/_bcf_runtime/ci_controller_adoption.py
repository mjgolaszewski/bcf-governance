"""Transactional adoption of canonical trusted-controller management."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import tempfile
from typing import Any

from .ci_graph_contracts import validate_ci_graph
from .ci_graph_render import apply_ci_graph
from .ci_graph_yaml import load_yaml_path, render_yaml
from .governance_install.ci_graph import apply_trusted_controller_management
from .governance_install.transaction import apply_transaction
from .trusted_controller_compatibility import verify_trusted_controller_compatibility
from .ci_controller_policy import (
    POLICY_PATH,
    ROTATION_EXTENSION,
    TrustedControllerPolicyError,
    validate_installed_controller_policy,
)


@dataclass(frozen=True)
class TrustedControllerAdoptionResult:
    status: str
    changed_paths: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {"status": self.status, "changed_paths": list(self.changed_paths)}


def _extension_bytes() -> bytes:
    path = (
        Path(__file__).resolve().parents[1]
        / "pack/template-repo"
        / ROTATION_EXTENSION
    )
    if path.is_symlink() or not path.is_file():
        raise TrustedControllerPolicyError(
            "packaged controller rotation extension is unavailable"
        )
    return path.read_bytes()


def _trusted_labels(graph: dict[str, Any]) -> list[str]:
    resource = graph.get("resource_classes", {}).get("trusted-control", {})
    runner = resource.get("runner") if isinstance(resource, dict) else None
    labels = [runner] if isinstance(runner, str) else runner
    if not isinstance(labels, list) or not labels or any(
        not isinstance(value, str) for value in labels
    ):
        raise TrustedControllerPolicyError(
            "CI graph trusted runner mapping is invalid"
        )
    return labels


def _project(root: Path, payload: dict[str, Any]) -> None:
    policy_path = root / POLICY_PATH
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_bytes(render_yaml(payload))
    extension_path = root / ROTATION_EXTENSION
    extension_path.parent.mkdir(parents=True, exist_ok=True)
    extension_path.write_bytes(_extension_bytes())
    graph_path = root / "governance/ci-graph.yml"
    graph = load_yaml_path(graph_path)
    current = graph.get("trusted_controller", {})
    if current.get("kind") not in {"executable", "governed_controller_policy"}:
        raise TrustedControllerPolicyError(
            "trusted controller adoption cannot replace another custody owner"
        )
    apply_trusted_controller_management(root, graph, _trusted_labels(graph), payload)
    graph_path.write_bytes(render_yaml(graph))
    apply_ci_graph(root)
    validate_ci_graph(root)


def _copy_for_plan(repo_root: Path, destination: Path) -> Path:
    shadow = destination / "repository"
    shutil.copytree(
        repo_root,
        shadow,
        symlinks=True,
        ignore=shutil.ignore_patterns(".git", ".artifacts", "__pycache__", "*.pyc"),
    )
    return shadow


def adopt_trusted_controller(
    repo_root: Path, *, config: Path, apply: bool
) -> TrustedControllerAdoptionResult:
    root = repo_root.resolve()
    payload = validate_installed_controller_policy(root, load_yaml_path(config.resolve()))
    installed = payload["runner_security"]["trusted_controller_installation"][
        "installed_commit_sha"
    ]
    verify_trusted_controller_compatibility(root, target_commit=installed)
    with tempfile.TemporaryDirectory(prefix="bcf-controller-adoption-") as raw:
        shadow = _copy_for_plan(root, Path(raw))
        _project(shadow, payload)
        candidates = {
            POLICY_PATH,
            ROTATION_EXTENSION,
            "governance/ci-graph.yml",
            *(
                path.relative_to(shadow).as_posix()
                for path in (shadow / ".github/workflows").glob("*.y*ml")
            ),
        }
        changed = tuple(
            sorted(
                relative
                for relative in candidates
                if not (root / relative).is_file()
                or (root / relative).read_bytes() != (shadow / relative).read_bytes()
            )
        )
    if not changed:
        return TrustedControllerAdoptionResult("clean", ())
    if not apply:
        return TrustedControllerAdoptionResult("actionable", changed)

    def mutate(shadow: Path) -> None:
        _project(shadow, payload)

    apply_transaction(root, managed_paths=changed, mutate_shadow=mutate)
    return TrustedControllerAdoptionResult("changed", changed)

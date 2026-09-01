"""Import an exact, non-authoritative inventory of existing GitHub workflows."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .ci_graph_contracts import CIGraphError
from .ci_graph_yaml import GraphYAMLError, load_yaml_path, render_yaml
from .governance_install.transaction import apply_transaction


INVENTORY_PATH = Path("governance/ci-workflow-inventory.yml")
INVENTORY_SCHEMA_PATH = Path("schemas/ci-workflow-inventory.schema.json")


@dataclass(frozen=True)
class WorkflowInventoryResult:
    status: str
    path: str


def _git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo_root, capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise CIGraphError(f"Git workflow inventory failed: {(result.stderr or result.stdout).strip()}")
    return result.stdout.strip()


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _artifact_steps(steps: list[Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(steps):
        if not isinstance(raw, dict):
            continue
        uses = str(raw.get("uses", ""))
        if "upload-artifact@" not in uses and "download-artifact@" not in uses:
            continue
        with_values = raw.get("with") if isinstance(raw.get("with"), dict) else {}
        result.append(
            {
                "step_index": index,
                "kind": "upload" if "upload-artifact@" in uses else "download",
                "uses": uses,
                "name": with_values.get("name"),
                "path": with_values.get("path"),
                "pattern": with_values.get("pattern"),
            }
        )
    return result


def _cleanup_steps(steps: list[Any]) -> list[int]:
    result: list[int] = []
    for index, raw in enumerate(steps):
        if not isinstance(raw, dict):
            continue
        text = " ".join(str(raw.get(key, "")) for key in ("name", "run", "if")).lower()
        if any(token in text for token in ("cleanup", "clean up", "teardown", "prune")):
            result.append(index)
    return result


def _authority_markers(job: dict[str, Any]) -> list[str]:
    encoded = json.dumps(job, sort_keys=True).lower()
    markers = []
    for token in (
        "statuses: write",
        "actions: write",
        "repository_dispatch",
        "workflow_dispatch",
        "ci-github",
        "github_token",
        "gh api",
    ):
        if token in encoded:
            markers.append(token)
    return markers


def _job(job_id: str, raw: dict[str, Any]) -> dict[str, Any]:
    steps = raw.get("steps") if isinstance(raw.get("steps"), list) else []
    strategy = raw.get("strategy") if isinstance(raw.get("strategy"), dict) else {}
    matrix = strategy.get("matrix") if isinstance(strategy.get("matrix"), dict) else {}
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "id": job_id,
        "name": str(raw.get("name", job_id)),
        "needs": _as_list(raw.get("needs")),
        "runs_on": raw.get("runs-on"),
        "permissions": raw.get("permissions"),
        "condition": raw.get("if"),
        "timeout_minutes": raw.get("timeout-minutes"),
        "matrix": matrix,
        "environment": raw.get("environment"),
        "uses": raw.get("uses"),
        "with": raw.get("with"),
        "artifacts": _artifact_steps(steps),
        "cleanup_steps": _cleanup_steps(steps),
        "authority_markers": _authority_markers(raw),
        "definition_sha256": hashlib.sha256(canonical).hexdigest(),
        "definition": raw,
    }


def inventory_github_workflows(repo_root: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    commit = _git(repo_root, "rev-parse", "HEAD")
    tree = _git(repo_root, "rev-parse", "HEAD^{tree}")
    workflow_root = repo_root / ".github/workflows"
    workflows: list[dict[str, Any]] = []
    if workflow_root.is_dir() and not workflow_root.is_symlink():
        for path in sorted(workflow_root.iterdir()):
            if not path.is_file() or path.is_symlink() or path.suffix not in {".yml", ".yaml"}:
                continue
            try:
                raw = load_yaml_path(path)
            except GraphYAMLError as exc:
                raise CIGraphError(str(exc)) from exc
            jobs = raw.get("jobs")
            if not isinstance(jobs, dict) or not jobs:
                raise CIGraphError(f"workflow has no exact job inventory: {path.relative_to(repo_root)}")
            events = raw.get("on")
            if isinstance(events, str):
                events = {events: {}}
            elif isinstance(events, list):
                events = {str(value): {} for value in events}
            if not isinstance(events, dict):
                raise CIGraphError(f"workflow has no exact event inventory: {path.relative_to(repo_root)}")
            workflows.append(
                {
                    "path": path.relative_to(repo_root).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "name": str(raw.get("name", path.stem)),
                    "events": events,
                    "permissions": raw.get("permissions"),
                    "concurrency": raw.get("concurrency"),
                    "jobs": [_job(str(job_id), job) for job_id, job in jobs.items() if isinstance(job, dict)],
                }
            )
    inventory = {
        "document": {
            "kind": "ci_workflow_inventory",
            "name": "Imported GitHub workflow inventory",
            "id": "github-ci-workflow-inventory",
            "version": "1.0.0",
            "status": "derived",
            "path": "governance/ci-workflow-inventory.yml",
        },
        "schema_version": "1.0",
        "provider": "github",
        "subject": {"commit": commit, "tree": tree},
        "workflows": workflows,
    }
    schema_path = repo_root / INVENTORY_SCHEMA_PATH
    if not schema_path.is_file():
        packaged = (
            Path(__file__).resolve().parents[1]
            / "pack/template-repo"
            / INVENTORY_SCHEMA_PATH
        )
        source = Path(__file__).resolve().parents[2] / INVENTORY_SCHEMA_PATH
        schema_path = packaged if packaged.is_file() else source
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CIGraphError(f"cannot load workflow inventory schema: {exc}") from exc
    errors = sorted(
        Draft202012Validator(schema).iter_errors(inventory),
        key=lambda item: list(item.path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(item) for item in error.absolute_path) or "<root>"
        raise CIGraphError(f"workflow inventory schema violation at {location}: {error.message}")
    return inventory


def render_workflow_inventory(repo_root: Path) -> bytes:
    return render_yaml(inventory_github_workflows(repo_root))


def check_workflow_inventory(
    repo_root: Path, output_path: Path = INVENTORY_PATH
) -> WorkflowInventoryResult:
    repo_root = repo_root.resolve()
    relative = output_path.as_posix()
    path = output_path if output_path.is_absolute() else repo_root / output_path
    desired = render_workflow_inventory(repo_root)
    status = "clean" if path.is_file() and not path.is_symlink() and path.read_bytes() == desired else "drift"
    return WorkflowInventoryResult(status=status, path=relative)


def write_workflow_inventory(
    repo_root: Path, output_path: Path = INVENTORY_PATH
) -> WorkflowInventoryResult:
    repo_root = repo_root.resolve()
    relative = output_path.as_posix()
    desired = render_workflow_inventory(repo_root)

    def mutate(shadow: Path) -> None:
        path = shadow / output_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(desired)

    apply_transaction(repo_root, managed_paths=(relative,), mutate_shadow=mutate)
    return WorkflowInventoryResult(status="written", path=relative)

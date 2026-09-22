"""Canonical job-identity and dependency-closure primitives for CI graphs."""

from __future__ import annotations

from typing import Any

from .ci_graph_errors import CIGraphError


def job_graph(workflow: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, set[str]]]:
    jobs = workflow["jobs"]
    by_id: dict[str, dict[str, Any]] = {}
    dependencies: dict[str, set[str]] = {}
    for job in jobs:
        job_id = job["id"]
        if job_id in by_id:
            raise CIGraphError(f"workflow {workflow['id']} duplicates job ID {job_id}")
        by_id[job_id] = job
        dependencies[job_id] = set(job["needs"])
    for job_id, needs in dependencies.items():
        missing = sorted(needs - set(by_id))
        if missing:
            raise CIGraphError(f"workflow {workflow['id']} job {job_id} needs missing jobs {missing}")
    return by_id, dependencies


def ancestors(job_id: str, dependencies: dict[str, set[str]]) -> set[str]:
    visited: set[str] = set()
    active: set[str] = set()

    def visit(current: str) -> None:
        if current in active:
            raise CIGraphError(f"CI graph cycle includes job {current}")
        if current in visited:
            return
        active.add(current)
        for dependency in dependencies[current]:
            visit(dependency)
        active.remove(current)
        visited.add(current)

    visit(job_id)
    visited.remove(job_id)
    return visited

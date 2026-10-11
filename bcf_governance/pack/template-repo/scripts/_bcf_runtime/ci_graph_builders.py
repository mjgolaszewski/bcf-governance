"""Small canonical constructors shared by CI graph projections."""

from __future__ import annotations

from typing import Any


def job(
    job_id: str,
    role: str,
    *,
    resource: str = "candidate-python",
    trust: str = "candidate",
    needs: list[str] | None = None,
    condition: str = "success",
    executor: dict[str, Any],
    produces: list[str] | None = None,
    consumes: list[str] | None = None,
    components: list[str] | None = None,
    permissions: dict[str, str] | None = None,
    checkout: bool | None = None,
) -> dict[str, Any]:
    return {
        "id": job_id,
        "display_name": role.replace("-", " ").title(),
        "semantic_role": role,
        "resource_class": resource,
        "trust": trust,
        "needs": needs or [],
        "condition": condition,
        "timeout_minutes": 45 if trust == "candidate" else 5,
        "permissions": permissions or {"contents": "read"},
        "checkout": (
            trust == "candidate" and executor["kind"] != "reusable_workflow"
            if checkout is None
            else checkout
        ),
        "components": components
        if components is not None
        else (
            ["checkout", "python", "governance-dependencies"]
            if trust == "candidate"
            else (["python"] if executor["kind"] in {"authority", "durable_publish"} else [])
        ),
        "executor": executor,
        "produces": produces or [],
        "consumes": consumes or [],
        "required": True,
    }


def component(
    *,
    kind: str,
    name: str,
    produces: list[str] | None = None,
    consumes: list[str] | None = None,
    environment: dict[str, str] | None = None,
    **values: Any,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "name": name,
        **values,
        "environment": environment or {},
        "produces": produces or [],
        "consumes": consumes or [],
    }

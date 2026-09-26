"""Install-time construction of a repository's canonical CI graph."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from ..ci_graph_defaults import build_reference_ci_graph
from ..ci_graph_render import apply_ci_graph
from ..ci_graph_yaml import load_yaml_path, render_yaml
from ..ci_controller_policy import (
    POLICY_PATH,
    ROTATION_EXTENSION,
    TrustedControllerPolicyError,
    validate_installed_controller_policy,
)


def _command(argv: list[str], *, environment: dict[str, str] | None = None) -> dict[str, Any]:
    return {"argv": argv, "cwd": ".", "environment": environment or {}}


def apply_trusted_controller_management(
    target_root: Path,
    graph: dict[str, Any],
    trusted_labels: list[str],
    policy_payload: dict[str, Any],
) -> None:
    """Project the opt-in canonical provider-backed rotation path."""

    raw = policy_payload
    policy_path = target_root / POLICY_PATH
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_bytes(render_yaml(raw))
    try:
        policy = validate_installed_controller_policy(target_root, raw)
    except TrustedControllerPolicyError as exc:
        raise RuntimeError(str(exc)) from exc
    runner = policy["runner_security"]
    if runner["trusted_labels"] != trusted_labels:
        raise RuntimeError(
            "trusted controller policy labels differ from the declared trusted runner mapping"
        )
    extension_path = target_root / ROTATION_EXTENSION
    if not extension_path.is_file() or extension_path.is_symlink():
        raise RuntimeError("canonical controller rotation extension is unavailable")
    graph["trusted_controller"] = {
        "kind": "governed_controller_policy",
        "policy_path": POLICY_PATH,
    }
    graph["value_sources"]["controller-policy"] = {
        "kind": "yaml",
        "path": POLICY_PATH,
        "sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
    }
    graph["extensions"].append(
        {
            "id": "bcf-controller-rotation",
            "path": ROTATION_EXTENSION,
            "sha256": hashlib.sha256(extension_path.read_bytes()).hexdigest(),
        }
    )
    graph["resource_classes"]["trusted-control-instance"] = {
        "runner": [*trusted_labels, "${{ matrix.trusted_runner }}"],
        "trust": "trusted",
        "hosted": False,
        "python_version": "3.12",
        "capabilities": ["provider-api"],
    }
    graph["artifacts"]["trusted-controller-bundle"] = {
        "path": ".artifacts/trusted-control",
        "kind": "control",
        "scope": "run-attempt",
        "retention_days": 30,
    }
    graph["conditions"].update(
        {
            "exact-main-authority-enabled": "vars.BCF_CI_AUTHORITY_ENABLED == 'true'",
            "exact-main-semantic-admission-enabled": "vars.BCF_CI_AUTHORITY_ENABLED == 'true' && needs.trusted-controller-build.outputs.semantic_evidence_applicable == 'true'",
        }
    )
    graph["commands"].update(
        {
            "build-trusted-controller": _command(
                [
                    "{python}", "scripts/build_trusted_controller.py", "--output",
                    ".artifacts/trusted-control", "--run-id", "${{ github.run_id }}",
                    "--run-attempt", "${{ github.run_attempt }}",
                ]
            ),
            "resolve-effective-controller-candidate": _command(
                [
                    "{python}", "-m", "bcf_governance.cli", "ci-github",
                    "controller-rotation", "resolve", "--repository",
                    "${{ github.repository }}",
                ],
                environment={"GITHUB_TOKEN": "${{ github.token }}"},
            ),
            "classify-exact-main-controller": _command(
                [
                    "{python}", "-m", "bcf_governance.cli", "ci",
                    "controller-applicability", "--repo-root", ".", "--target-commit",
                    "${{ steps.candidate-effective-controller.outputs.BCF_BOOTSTRAP_COMMIT_SHA }}",
                    "--github-output", "--format", "json",
                ]
            ),
            "exact-main-finalize-effective": _command(
                [
                    "${{ runner.tool_cache }}/bcf-governance/${{ steps.effective-controller.outputs.BCF_BOOTSTRAP_COMMIT_SHA }}/bin/bcf",
                    "ci-github", "exact-main", "finalize", "--repository",
                    "${{ github.repository }}", "--trigger-run-id",
                    "${{ github.event.workflow_run.id }}", "--trigger-run-attempt",
                    "${{ github.event.workflow_run.run_attempt }}", "--output",
                    "${{ runner.temp }}/bcf-exact-main-certification",
                ],
                environment={"GITHUB_TOKEN": "${{ github.token }}"},
            ),
            "exact-main-publish-effective": _command(
                [
                    "${{ runner.tool_cache }}/bcf-governance/${{ steps.effective-controller.outputs.BCF_BOOTSTRAP_COMMIT_SHA }}/bin/bcf",
                    "ci-github", "exact-main", "publish", "--repository",
                    "${{ github.repository }}", "--bundle",
                    "${{ runner.temp }}/bcf-exact-main-certification", "--target-url",
                    "https://github.com/${{ github.repository }}/actions/runs/${{ github.event.workflow_run.id }}",
                    "--collector-run-id", "${{ github.event.workflow_run.id }}",
                    "--collector-run-attempt", "${{ github.event.workflow_run.run_attempt }}",
                ],
                environment={"GITHUB_TOKEN": "${{ github.token }}"},
            ),
        }
    )
    graph["commands"].setdefault(
        "install-governance-dependencies",
        _command(["{python}", "-m", "pip", "install", "-r", "requirements-governance.txt"]),
    )
    components = graph["step_components"]
    components.setdefault(
        "checkout-candidate",
        {"kind": "action", "name": "Check out the exact candidate commit", "action": "checkout", "with": {"fetch-depth": 0, "persist-credentials": False}, "environment": {}, "produces": [], "consumes": []},
    )
    components.setdefault(
        "setup-python",
        {"kind": "action", "name": "Provision the declared Python runtime", "action": "setup-python", "with": {"python-version": "3.12"}, "environment": {}, "produces": [], "consumes": []},
    )
    components.setdefault(
        "install-governance",
        {"kind": "command", "name": "Install the declared governance environment", "command": "install-governance-dependencies", "environment": {}, "produces": [], "consumes": []},
    )
    components.update(
        {
            "build-trusted-controller": {"kind": "command", "name": "Build the exact-main trusted controller bundle", "command": "build-trusted-controller", "environment": {}, "produces": ["trusted-controller-bundle"], "consumes": []},
            "resolve-effective-controller-candidate": {"kind": "command", "name": "Observe provider-effective controller for non-authoritative routing", "id": "candidate-effective-controller", "command": "resolve-effective-controller-candidate", "environment": {}, "produces": [], "consumes": []},
            "classify-exact-main-controller": {"kind": "command", "name": "Classify exact-main semantic evidence applicability", "id": "exact-main-applicability", "command": "classify-exact-main-controller", "environment": {}, "produces": [], "consumes": []},
            "upload-trusted-controller": {"kind": "action", "name": "Upload the exact-main trusted controller bundle", "action": "upload-artifact", "with": {"name": "bcf-trusted-control-${{ github.sha }}-${{ github.run_attempt }}", "path": ".artifacts/trusted-control", "if-no-files-found": "error", "retention-days": 30}, "environment": {}, "produces": ["trusted-controller-bundle"], "consumes": []},
            "exact-main-finalize-effective": {"kind": "command", "name": "Reconstruct exact-main evidence with the effective controller", "command": "exact-main-finalize-effective", "environment": {}, "produces": ["exact-main-certification"], "consumes": []},
            "upload-exact-main-certification-effective": {"kind": "action", "name": "Upload exact-main certification bundle", "action": "upload-artifact", "with": {"name": "bcf-exact-main-certification-${{ github.run_id }}-${{ github.run_attempt }}", "path": "${{ runner.temp }}/bcf-exact-main-certification", "if-no-files-found": "error", "retention-days": 30}, "environment": {}, "produces": ["exact-main-certification"], "consumes": []},
            "download-exact-main-certification-effective": {"kind": "action", "name": "Download exact finalizer certification bundle", "action": "download-artifact", "with": {"name": "bcf-exact-main-certification-${{ github.event.workflow_run.id }}-${{ github.event.workflow_run.run_attempt }}", "github-token": "${{ github.token }}", "repository": "${{ github.repository }}", "run-id": "${{ github.event.workflow_run.id }}", "path": "${{ runner.temp }}/bcf-exact-main-certification"}, "environment": {}, "produces": [], "consumes": ["exact-main-certification"]},
            "exact-main-publish-effective": {"kind": "command", "name": "Publish authenticated exact-main status with the effective controller", "command": "exact-main-publish-effective", "environment": {}, "produces": [], "consumes": ["exact-main-certification"]},
        }
    )
    exact_main = next(item for item in graph["workflows"] if item["id"] == "exact-main")
    exact_main["display_name"] = "bcf/exact-main-admission"
    admit = next(item for item in exact_main["jobs"] if item["id"] == "admit")
    scope = admit["executor"]
    mode = str(scope.get("evaluation_mode", "closure"))
    target = str(scope.get("evaluation_target", ""))
    graph["commands"]["exact-main-admit-effective"] = _command(
        [
            "${{ runner.tool_cache }}/bcf-governance/${{ steps.effective-controller.outputs.BCF_BOOTSTRAP_COMMIT_SHA }}/bin/bcf",
            "ci-github", "exact-main", "admit", "--repository", "${{ github.repository }}",
            "--sha", "${{ github.sha }}", "--target-url",
            "https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }}",
            "--evaluation-mode", mode,
            *(["--evaluation-target", target] if target else []),
        ],
        environment={"GITHUB_TOKEN": "${{ github.token }}"},
    )
    components["exact-main-admit-effective"] = {"kind": "command", "name": "Authenticate exact-main admission with the effective controller", "command": "exact-main-admit-effective", "environment": {}, "produces": [], "consumes": []}
    admit.update(
        {
            "needs": ["trusted-controller-build"],
            "condition": "exact-main-semantic-admission-enabled",
            "controller_requirement": "current",
            "executor": {"kind": "component_sequence", "components": ["setup-python", "resolve-effective-controller", "exact-main-admit-effective"]},
        }
    )
    exact_main["jobs"].append(
        {
            "id": "trusted-controller-build", "display_name": "Build independent exact-main trusted controller",
            "semantic_role": "exact-main-controller-builder", "resource_class": "candidate-python", "trust": "candidate",
            "needs": [], "condition": "exact-main-authority-enabled", "timeout_minutes": 15,
            "permissions": {"actions": "read", "contents": "read"}, "checkout": False, "components": [],
            "outputs": {"controller_state": "${{ steps.exact-main-applicability.outputs.controller_state }}", "semantic_evidence_applicable": "${{ steps.exact-main-applicability.outputs.semantic_evidence_applicable }}", "target_commit": "${{ steps.exact-main-applicability.outputs.target_commit }}"},
            "executor": {"kind": "component_sequence", "components": ["checkout-candidate", "setup-python", "install-governance", "resolve-effective-controller-candidate", "classify-exact-main-controller", "build-trusted-controller", "upload-trusted-controller"]},
            "produces": ["trusted-controller-bundle"], "consumes": [], "required": True,
        }
    )
    finalizer = next(item for item in graph["workflows"] if item["id"] == "exact-main-finalizer")
    finalizer["events"][0]["workflows"] = ["bcf/exact-main-admission"]
    finalizer["jobs"][0].update({"controller_requirement": "current", "executor": {"kind": "component_sequence", "components": ["setup-python", "resolve-effective-controller", "exact-main-finalize-effective", "upload-exact-main-certification-effective"]}})
    publisher = next(item for item in graph["workflows"] if item["id"] == "exact-main-publisher")
    publisher["events"][0]["workflows"].append("bcf/controller-rotation")
    publisher["jobs"][0].update({"controller_requirement": "current", "executor": {"kind": "component_sequence", "components": ["setup-python", "download-exact-main-certification-effective", "resolve-effective-controller", "exact-main-publish-effective"]}})


def _sync_evidence_workflow_contract(
    target_root: Path, graph: dict[str, Any]
) -> None:
    """Project actual graph roots/events into the evidence requirement surface."""

    governance = next(
        workflow for workflow in graph["workflows"] if workflow["id"] == "governance"
    )
    policy_path = target_root / "governance/evidence-policy.yml"
    policy = load_yaml_path(policy_path)
    contract = policy.get("workflow_contract")
    if not isinstance(contract, dict):
        raise RuntimeError("evidence policy requires a workflow_contract mapping")
    contract["paths"] = [governance["path"]]
    contract["required_events"] = [
        event["type"] for event in governance["events"]
    ]
    policy_path.write_bytes(render_yaml(policy))


def _runner_mapping(
    args: Any, *, contract_version: str
) -> tuple[list[str], list[str], bool, bool]:
    if args.profile == "lite" or contract_version == "1.0":
        candidate = list(args.candidate_runner_label or [args.runner_labels])
        trusted = list(args.trusted_runner_label or candidate)
        return (
            candidate,
            trusted,
            (args.candidate_runner_kind or "hosted") == "hosted",
            (args.trusted_runner_kind or args.candidate_runner_kind or "hosted")
            == "hosted",
        )
    missing = [
        name
        for name, value in (
            ("--candidate-runner-label", args.candidate_runner_label),
            ("--trusted-runner-label", args.trusted_runner_label),
            ("--candidate-runner-kind", args.candidate_runner_kind),
            ("--trusted-runner-kind", args.trusted_runner_kind),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "Standard-v2 CI graph requires explicit runner mapping: "
            + ", ".join(missing)
        )
    return (
        list(args.candidate_runner_label),
        list(args.trusted_runner_label),
        args.candidate_runner_kind == "hosted",
        args.trusted_runner_kind == "hosted",
    )


def write_reference_ci_graph(
    args: Any, target_root: Path, contract: dict[str, Any]
) -> None:
    contract_version = str(contract.get("profile_contract_version", "1.0"))
    candidate, trusted, candidate_hosted, trusted_hosted = _runner_mapping(
        args, contract_version=contract_version
    )
    graph = build_reference_ci_graph(
        project_id=args.project_id,
        profile=args.profile,
        profile_contract_version=contract_version,
        gates=list(contract["gates"]),
        candidate_labels=candidate,
        trusted_labels=trusted,
        candidate_hosted=candidate_hosted,
        trusted_hosted=trusted_hosted,
    )
    extension_path = target_root / ROTATION_EXTENSION
    if extension_path.is_symlink():
        raise RuntimeError("canonical controller rotation extension is unsafe")
    if extension_path.exists():
        extension_path.unlink()
    storage_path = target_root / "governance/evidence-storage.yml"
    if not storage_path.is_file() or storage_path.is_symlink():
        raise RuntimeError("fresh CI graph requires governance/evidence-storage.yml")
    graph["evidence_storage"] = {
        "path": "governance/evidence-storage.yml",
        "sha256": hashlib.sha256(storage_path.read_bytes()).hexdigest(),
    }
    graph_path = target_root / "governance/ci-graph.yml"
    graph_path.parent.mkdir(parents=True, exist_ok=True)
    graph_path.write_bytes(render_yaml(graph))
    _sync_evidence_workflow_contract(target_root, graph)
    (target_root / "governance/ci-extensions").mkdir(parents=True, exist_ok=True)
    apply_ci_graph(target_root)

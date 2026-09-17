"""Provider-authenticated projection of break-glass installation into re-entry."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any

from jsonschema import Draft202012Validator
import yaml

from .break_glass_recovery import (
    RECEIPT_SCHEMA,
    REENTRY_SCHEMA,
    _load,
    _one_artifact,
    _safe_archive,
    _write_atomic,
)
from .ci_github_api import GitHubAPI
from .ci_github_identity import GitHubControllerError, resolve_main
from .ci_graph_locks import apply_ci_graph_locks
from .ci_graph_render import apply_ci_graph


def authenticate_projection_receipt(
    api: GitHubAPI, *, root: Path, repository: str, receipt_path: Path
) -> tuple[dict[str, Any], dict[str, Any], Any]:
    """Authenticate the exact provider artifact and current-main projection source."""

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    schema = json.loads((root / RECEIPT_SCHEMA).read_text(encoding="utf-8"))
    Draft202012Validator(
        schema, format_checker=Draft202012Validator.FORMAT_CHECKER
    ).validate(receipt)
    policy = _load(root)
    if repository != receipt["repository"]["name"]:
        raise GitHubControllerError("recovery receipt repository is not exact")
    artifact = _one_artifact(api, repository, policy, "receipt", receipt["operation_id"])
    raw = api.artifact_bytes(repository, artifact["id"])
    if f"sha256:{hashlib.sha256(raw).hexdigest()}" != artifact["digest"]:
        raise GitHubControllerError(
            "recovery receipt artifact bytes do not match provider digest"
        )
    with tempfile.TemporaryDirectory(prefix="bcf-recovery-reentry-receipt-") as name:
        extracted = Path(name)
        _safe_archive(raw, extracted)
        files = [path for path in extracted.rglob("*") if path.is_file()]
        if [path.relative_to(extracted).as_posix() for path in files] != [
            "receipt.json"
        ]:
            raise GitHubControllerError("recovery receipt artifact inventory is not exact")
        if files[0].read_bytes() != receipt_path.read_bytes():
            raise GitHubControllerError("local recovery receipt differs from provider artifact")
    main = resolve_main(api, repository)
    if (
        main.repository_id != receipt["repository"]["id"]
        or main.default_branch != receipt["repository"]["branch"]
    ):
        raise GitHubControllerError("recovery re-entry repository identity is not exact")
    probe_run = api.run(repository, receipt["probe"]["run_id"])
    if (
        str(artifact.get("workflow_run", {}).get("id")) != receipt["probe"]["run_id"]
        or str(probe_run.get("run_attempt")) != receipt["probe"]["run_attempt"]
        or str(probe_run.get("conclusion")) != "success"
        or str(probe_run.get("head_sha")) != receipt["subject"]["commit"]
        or str(probe_run.get("workflow_id")) != receipt["actor"]["workflow_id"]
        or str(probe_run.get("repository", {}).get("id"))
        != receipt["repository"]["id"]
    ):
        raise GitHubControllerError("recovery receipt provider run identity is not exact")
    return receipt, artifact, main


def _authorization(
    *,
    root: Path,
    receipt: dict[str, Any],
    receipt_artifact: dict[str, Any],
    source_commit: str,
    source_tree: str,
    receipt_bytes: bytes,
) -> dict[str, Any]:
    authorization = {
        "schema_version": "1.0",
        "state": "authenticated-recovery-reentry",
        "repository_id": receipt["repository"]["id"],
        "operation_id": receipt["operation_id"],
        "reason_code": receipt["reason_code"],
        "receipt_artifact": {
            "id": str(receipt_artifact["id"]),
            "name": str(receipt_artifact["name"]),
            "provider_digest": str(receipt_artifact["digest"]),
            "payload_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        },
        "installed_controller_commit": receipt["resulting_installed_controller"],
        "recovery_subject": receipt["subject"],
        "authorized_source": {"commit": source_commit, "tree": source_tree},
        "provenance": {
            "build_run_id": receipt["builder"]["run_id"],
            "build_run_attempt": receipt["builder"]["run_attempt"],
            "build_artifact_id": receipt["artifact"]["id"],
            "build_artifact_digest": receipt["artifact"]["provider_digest"],
            "install_run_id": receipt["install"]["run_id"],
            "install_run_attempt": receipt["install"]["run_attempt"],
            "probe_run_id": receipt["probe"]["run_id"],
            "probe_run_attempt": receipt["probe"]["run_attempt"],
        },
        "permitted_authority_class": "exact-main-admission",
        "recovery_only": receipt["recovery_only"],
        "governance_certified": receipt["governance_certified"],
    }
    authorization["binding_sha256"] = hashlib.sha256(
        json.dumps(authorization, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    schema = json.loads((root / REENTRY_SCHEMA).read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(authorization)
    return authorization


def project_installation(
    *,
    root: Path,
    receipt_path: Path,
    receipt_artifact: dict[str, Any],
    provider_main: Any,
) -> dict[str, Any]:
    """Project recovery-proven installation and one bounded re-entry authority."""

    receipt_bytes = receipt_path.read_bytes()
    receipt = json.loads(receipt_bytes)
    schema = json.loads((root / RECEIPT_SCHEMA).read_text(encoding="utf-8"))
    Draft202012Validator(
        schema, format_checker=Draft202012Validator.FORMAT_CHECKER
    ).validate(receipt)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if (
        provider_main.checkout_sha != head
        or provider_main.tree_sha != tree
        or provider_main.repository_id != receipt["repository"]["id"]
        or provider_main.default_branch != receipt["repository"]["branch"]
    ):
        raise GitHubControllerError("recovery re-entry source is not exact provider main")
    policy_path = root / "governance/self-governance-policy.yml"
    raw = policy_path.read_bytes()
    policy = yaml.safe_load(raw)
    runner = policy.get("runner_security", {})
    pin = runner.get("trusted_controller_artifact", {})
    current = runner.get("trusted_controller_installation", {})
    confirmation = {
        key: receipt["controller_confirmation"][key]
        for key in (
            "schema_version",
            "installed_commit_sha",
            "subject_commit_sha",
            "subject_tree_sha",
            "bootstrap_run_id",
            "bootstrap_run_attempt",
            "probe_run_id",
            "probe_run_attempt",
        )
    }
    receipt_installed = receipt["resulting_installed_controller"]
    if (
        confirmation["installed_commit_sha"] != receipt_installed
        or confirmation["subject_commit_sha"] != receipt["subject"]["commit"]
        or confirmation["subject_tree_sha"] != receipt["subject"]["tree"]
        or confirmation["bootstrap_run_id"] != receipt["install"]["run_id"]
        or confirmation["bootstrap_run_attempt"] != receipt["install"]["run_attempt"]
        or confirmation["probe_run_id"] != receipt["probe"]["run_id"]
        or confirmation["probe_run_attempt"] != receipt["probe"]["run_attempt"]
    ):
        raise GitHubControllerError(
            "recovery receipt controller confirmation is contradictory"
        )
    first_projection = current.get("installed_commit_sha") == pin.get(
        "BCF_BOOTSTRAP_COMMIT_SHA"
    )
    reentry_projection = current == confirmation and current.get(
        "installed_commit_sha"
    ) != pin.get("BCF_BOOTSTRAP_COMMIT_SHA")
    if not first_projection and not reentry_projection:
        raise GitHubControllerError(
            "controller custody cannot admit recovery re-entry projection"
        )
    if first_projection and {"commit": head, "tree": tree} != receipt["subject"]:
        raise GitHubControllerError("initial recovery projection is not exact receipt subject")
    if first_projection and receipt_installed != head:
        raise GitHubControllerError("initial recovery installation is not exact local main")
    authorization = _authorization(
        root=root,
        receipt=receipt,
        receipt_artifact=receipt_artifact,
        source_commit=head,
        source_tree=tree,
        receipt_bytes=receipt_bytes,
    )
    existing = runner.get("trusted_controller_recovery_reentry")
    if existing is not None and (
        not isinstance(existing, dict)
        or existing.get("operation_id") != authorization["operation_id"]
        or existing.get("authorized_source") != authorization["authorized_source"]
        or existing.get("installed_controller_commit")
        != authorization["installed_controller_commit"]
    ):
        raise GitHubControllerError("a different recovery re-entry authorization is active")
    confirmation_flow = yaml.safe_dump(
        confirmation, sort_keys=False, default_flow_style=True, width=1000
    ).strip()
    pattern = re.compile(rb"(?m)^  trusted_controller_installation: \{[^\r\n]*\}$")
    if len(pattern.findall(raw)) != 1:
        raise GitHubControllerError("canonical installed-controller proof is not unique")
    projected = pattern.sub(
        f"  trusted_controller_installation: {confirmation_flow}".encode(), raw
    )
    projected = re.sub(
        rb"(?m)^  trusted_controller_recovery_reentry: \{[^\r\n]*\}\r?\n?",
        b"",
        projected,
    )
    authorization_flow = yaml.safe_dump(
        authorization, sort_keys=False, default_flow_style=True, width=4000
    ).strip()
    installation_line = (
        f"  trusted_controller_installation: {confirmation_flow}".encode()
    )
    projected = projected.replace(
        installation_line,
        installation_line
        + b"\n  trusted_controller_recovery_reentry: "
        + authorization_flow.encode(),
        1,
    )
    if projected == raw:
        raise GitHubControllerError("recovery installation is already projected")
    _write_atomic(policy_path, projected)
    lock = apply_ci_graph_locks(root)
    render = apply_ci_graph(root)
    return {
        "status": "recovery_installation_projected_for_protected_pr",
        "installed_commit_sha": receipt_installed,
        "authorized_source_commit": head,
        "authorized_source_tree": tree,
        "changed_paths": sorted(
            {
                "governance/self-governance-policy.yml",
                *lock.changed_inputs,
                *render.changed_paths,
            }
        ),
    }

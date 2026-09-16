"""Owner-authorized recovery of an installed controller; never certification authority."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any
import zipfile

from jsonschema import Draft202012Validator
import yaml

from .ci_github_api import GitHubAPI
from .ci_github_bootstrap import (
    controller_metadata,
    install_controller,
    verify_controller_inventory,
    verify_controller_subject_metadata,
)
from .ci_github_identity import GitHubControllerError, resolve_main
from .ci_graph_locks import apply_ci_graph_locks
from .ci_graph_render import apply_ci_graph


POLICY = Path("governance/break-glass-recovery.yml")
POLICY_SCHEMA = Path("schemas/break-glass-recovery-policy.schema.json")
RECEIPT_SCHEMA = Path("schemas/break-glass-recovery-receipt.schema.json")


def _load(root: Path) -> dict[str, Any]:
    policy = yaml.safe_load((root / POLICY).read_text(encoding="utf-8"))
    schema = json.loads((root / POLICY_SCHEMA).read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(policy)
    return policy


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise GitHubControllerError(f"recovery environment is missing {name}")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_atomic(path: Path, raw: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, path.stat().st_mode & 0o777)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _output(**values: object) -> None:
    target = Path(_required("GITHUB_OUTPUT"))
    with target.open("a", encoding="utf-8") as stream:
        for key, value in values.items():
            stream.write(f"{key}={value}\n")


def _artifact_name(policy: dict[str, Any], kind: str, operation_id: str) -> str:
    return f"{policy['operation']['artifact_prefix']}-{kind}-{operation_id}"


def _authorize(
    api: GitHubAPI,
    *,
    root: Path,
    repository: str,
    operation_id: str,
    reason_code: str,
    stage: str,
    **_unused: Any,
) -> tuple[dict[str, Any], Any, dict[str, Any]]:
    policy = _load(root)
    operation = policy["operation"]
    authority = policy["authority"]
    if not re.fullmatch(operation["operation_id_pattern"], operation_id):
        raise GitHubControllerError("recovery operation ID is not an exact nonce")
    if reason_code not in authority["reason_codes"] or stage not in operation["stages"]:
        raise GitHubControllerError("recovery reason or stage is not authorized")
    if (
        repository != policy["repository"]["name"]
        or _required("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or _required("GITHUB_REF") != "refs/heads/main"
    ):
        raise GitHubControllerError("recovery invocation is not owner-dispatched main")
    main = resolve_main(api, repository)
    if (
        main.repository_id != policy["repository"]["repository_id"]
        or main.default_branch != policy["repository"]["default_branch"]
        or main.checkout_sha != _required("GITHUB_SHA")
    ):
        raise GitHubControllerError("recovery subject is not exact current main")
    installation = api.installation()
    expected_app = _required(authority["app_id_variable"])
    expected_installation = _required(authority["installation_id_variable"])
    if (
        str(installation.get("app_id")) != expected_app
        or str(installation.get("id")) != expected_installation
        or installation.get("repository_selection") != "selected"
    ):
        raise GitHubControllerError("recovery App installation identity is not exact")
    run_id = _required("GITHUB_RUN_ID")
    attempt = _required("GITHUB_RUN_ATTEMPT")
    actor = _required("GITHUB_ACTOR")
    run = api.run(repository, run_id)
    workflow_id = _required(authority["workflow_id_variable"])
    if {
        "id": str(run.get("id")),
        "attempt": str(run.get("run_attempt")),
        "event": str(run.get("event")),
        "sha": str(run.get("head_sha")),
        "branch": str(run.get("head_branch")),
        "workflow_id": str(run.get("workflow_id")),
        "path": str(run.get("path")),
        "actor": str(run.get("actor", {}).get("login")),
    } != {
        "id": run_id,
        "attempt": attempt,
        "event": "workflow_dispatch",
        "sha": main.checkout_sha,
        "branch": main.default_branch,
        "workflow_id": workflow_id,
        "path": authority["workflow_path"],
        "actor": actor,
    }:
        raise GitHubControllerError("recovery workflow/run/actor identity is not exact")
    permission = api.collaborator_permission(repository, actor)
    if permission.get("permission") != authority["required_actor_permission"]:
        raise GitHubControllerError("recovery actor is not a repository administrator")
    active = [
        value
        for value in api.workflow_runs(
            repository, workflow_id, head_sha=main.checkout_sha, event="workflow_dispatch"
        )
        if value.get("status") in {"queued", "in_progress"}
    ]
    if len(active) != 1 or str(active[0].get("id")) != run_id:
        raise GitHubControllerError("recovery operation is not singleton")
    existing = {
        kind: api.repository_artifacts(
            repository, name=_artifact_name(policy, kind, operation_id)
        )
        for kind in ("build", "install", "receipt")
    }
    if stage == "build" and any(existing.values()):
        raise GitHubControllerError("recovery operation ID is replayed")
    if stage == "install" and (
        len(existing["build"]) != 1 or existing["install"] or existing["receipt"]
    ):
        raise GitHubControllerError("recovery install stage is duplicated or out of order")
    if stage == "probe" and (
        len(existing["build"]) != 1
        or len(existing["install"]) != 1
        or existing["receipt"]
    ):
        raise GitHubControllerError("recovery probe stage is duplicated or out of order")
    return policy, main, {
        "login": actor,
        "id": str(run.get("actor", {}).get("id")),
        "permission": permission["permission"],
        "app_id": expected_app,
        "installation_id": expected_installation,
        "workflow_id": workflow_id,
        "run_id": run_id,
        "run_attempt": attempt,
    }


def _one_artifact(
    api: GitHubAPI, repository: str, policy: dict[str, Any], kind: str, operation_id: str
) -> dict[str, Any]:
    name = _artifact_name(policy, kind, operation_id)
    values = [
        value for value in api.repository_artifacts(repository, name=name)
        if value.get("name") == name and value.get("expired") is False
    ]
    if len(values) != 1:
        raise GitHubControllerError(f"recovery {kind} artifact is not unique and unexpired")
    artifact = values[0]
    if str(artifact.get("id")) in policy["operation"]["forensic_artifact_ids"]:
        raise GitHubControllerError("forensic artifact is forbidden for recovery")
    digest = str(artifact.get("digest"))
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise GitHubControllerError("recovery artifact provider digest is not exact")
    return artifact


def _safe_archive(raw: bytes, output: Path) -> None:
    try:
        with zipfile.ZipFile(__import__("io").BytesIO(raw)) as archive:
            if sum(member.file_size for member in archive.infolist()) > 209_715_200:
                raise GitHubControllerError("recovery archive expands beyond the size limit")
            names: set[str] = set()
            for member in archive.infolist():
                path = Path(member.filename)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or "\\" in member.filename
                    or ":" in member.filename
                    or member.filename in names
                    or member.flag_bits & 0x1
                ):
                    raise GitHubControllerError("recovery archive path is unsafe")
                names.add(member.filename)
                mode = (member.external_attr >> 16) & 0o170000
                if mode not in {0, 0o040000, 0o100000}:
                    raise GitHubControllerError("recovery archive contains a special file")
            archive.extractall(output)
    except zipfile.BadZipFile as exc:
        raise GitHubControllerError("recovery artifact archive is invalid") from exc


def _build_bundle(
    api: GitHubAPI, repository: str, policy: dict[str, Any], operation_id: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    artifact = _one_artifact(api, repository, policy, "build", operation_id)
    run_id = str(artifact.get("workflow_run", {}).get("id"))
    run = api.run(repository, run_id)
    if {
        "conclusion": str(run.get("conclusion")),
        "event": str(run.get("event")),
        "head_sha": str(run.get("head_sha")),
        "head_branch": str(run.get("head_branch")),
        "workflow_id": str(run.get("workflow_id")),
        "path": str(run.get("path")),
        "repository_id": str(run.get("repository", {}).get("id")),
        "head_repository_id": str(run.get("head_repository", {}).get("id")),
    } != {
        "conclusion": "success",
        "event": "workflow_dispatch",
        "head_sha": _required("GITHUB_SHA"),
        "head_branch": policy["repository"]["default_branch"],
        "workflow_id": _required(policy["authority"]["workflow_id_variable"]),
        "path": policy["authority"]["workflow_path"],
        "repository_id": policy["repository"]["repository_id"],
        "head_repository_id": policy["repository"]["repository_id"],
    }:
        raise GitHubControllerError("recovery builder run identity is not exact")
    jobs = api.jobs(repository, run_id, attempt=int(run["run_attempt"]))
    selected = [job for job in jobs if job.get("name") == policy["builder"]["job_name"]]
    if (
        len(selected) != 1
        or selected[0].get("status") != "completed"
        or selected[0].get("conclusion") != "success"
    ):
        raise GitHubControllerError("recovery builder job is not exactly successful")
    return artifact, run, selected[0]


def _install_run(
    api: GitHubAPI, repository: str, policy: dict[str, Any], operation_id: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    artifact = _one_artifact(api, repository, policy, "install", operation_id)
    run = api.run(repository, artifact["workflow_run"]["id"])
    if {
        "conclusion": str(run.get("conclusion")),
        "event": str(run.get("event")),
        "head_sha": str(run.get("head_sha")),
        "head_branch": str(run.get("head_branch")),
        "workflow_id": str(run.get("workflow_id")),
        "path": str(run.get("path")),
        "repository_id": str(run.get("repository", {}).get("id")),
        "head_repository_id": str(run.get("head_repository", {}).get("id")),
    } != {
        "conclusion": "success",
        "event": "workflow_dispatch",
        "head_sha": _required("GITHUB_SHA"),
        "head_branch": policy["repository"]["default_branch"],
        "workflow_id": _required(policy["authority"]["workflow_id_variable"]),
        "path": policy["authority"]["workflow_path"],
        "repository_id": policy["repository"]["repository_id"],
        "head_repository_id": policy["repository"]["repository_id"],
    }:
        raise GitHubControllerError("recovery install run identity is not exact")
    jobs = api.jobs(repository, run["id"], attempt=int(run["run_attempt"]))
    expected = {
        f"Install recovered controller / {value['slot']}": value
        for value in policy["runners"]
    }
    observed = {str(job.get("name")): job for job in jobs if str(job.get("name")) in expected}
    if set(observed) != set(expected) or any(
        job.get("status") != "completed"
        or job.get("conclusion") != "success"
        or str(job.get("runner_name")) != expected[name]["runner_name"]
        or expected[name]["slot"] not in job.get("labels", [])
        for name, job in observed.items()
    ):
        raise GitHubControllerError("recovery install inventory is not exactly green")
    return artifact, run, observed


def _authenticated_build(
    api: GitHubAPI,
    *,
    repository: str,
    policy: dict[str, Any],
    operation_id: str,
    main: Any,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    artifact, run, job = _build_bundle(api, repository, policy, operation_id)
    raw = api.artifact_bytes(repository, artifact["id"])
    if f"sha256:{hashlib.sha256(raw).hexdigest()}" != artifact["digest"]:
        raise GitHubControllerError("recovery artifact bytes do not match provider digest")
    with tempfile.TemporaryDirectory(prefix="bcf-break-glass-build-") as name:
        root = Path(name)
        _safe_archive(raw, root)
        try:
            build = json.loads((root / "RECOVERY-BUILD.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise GitHubControllerError("recovery build receipt is invalid") from exc
        bundle = root / "controller"
        wheel, declared = verify_controller_inventory(bundle)
        verify_controller_subject_metadata(
            bundle / "CONTROL-METADATA.json",
            commit_sha=main.checkout_sha,
            tree_sha=main.tree_sha,
            run_id=str(run["id"]),
            run_attempt=str(run["run_attempt"]),
        )
        wheel_sha256 = hashlib.sha256(wheel.read_bytes()).hexdigest()
        expected_subject = {"commit": main.checkout_sha, "tree": main.tree_sha}
        if (
            build.get("operation_id") != operation_id
            or build.get("reason_code") != "ordinary_control_plane_bootstrap_deadlock"
            or build.get("subject") != expected_subject
            or build.get("wheel_sha256") != wheel_sha256
            or build.get("checksum_inventory") != declared
            or build.get("actor", {}).get("run_id") != str(run["id"])
            or build.get("actor", {}).get("run_attempt") != str(run["run_attempt"])
            or build.get("actor", {}).get("login")
            != str(run.get("actor", {}).get("login"))
        ):
            raise GitHubControllerError("recovery build receipt does not bind exact bytes")
        custody = {
            "wheel_sha256": wheel_sha256,
            "checksum_inventory": declared,
            "checksum_inventory_sha256": hashlib.sha256(
                (bundle / "SHA256SUMS").read_bytes()
            ).hexdigest(),
            "control_metadata": controller_metadata(bundle / "CONTROL-METADATA.json"),
        }
    return artifact, run, job, custody


def authorize_build(api: GitHubAPI, **kwargs: Any) -> dict[str, Any]:
    policy, main, actor = _authorize(api, stage="build", **kwargs)
    value = {
        "schema_version": "1.0",
        "operation_id": kwargs["operation_id"],
        "reason_code": kwargs["reason_code"],
        "repository": {"id": main.repository_id, "name": kwargs["repository"], "branch": main.default_branch},
        "subject": {"commit": main.checkout_sha, "tree": main.tree_sha},
        "actor": actor,
    }
    _write_json(kwargs["output"], value)
    return {"status": "recovery_build_authorized", **value}


def bind_build(root: Path, bundle: Path, authorization: Path) -> dict[str, Any]:
    auth = json.loads(authorization.read_text(encoding="utf-8"))
    wheel, declared = verify_controller_inventory(bundle)
    verify_controller_subject_metadata(
        bundle / "CONTROL-METADATA.json",
        commit_sha=auth["subject"]["commit"], tree_sha=auth["subject"]["tree"],
        run_id=auth["actor"]["run_id"], run_attempt=auth["actor"]["run_attempt"],
    )
    value = {**auth, "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(), "checksum_inventory": declared}
    _write_json(root / "RECOVERY-BUILD.json", value)
    return value


def resolve_build(api: GitHubAPI, **kwargs: Any) -> dict[str, Any]:
    policy, main, _ = _authorize(api, stage=kwargs["stage"], **kwargs)
    artifact, run, _ = _build_bundle(api, kwargs["repository"], policy, kwargs["operation_id"])
    if str(run.get("head_sha")) != main.checkout_sha:
        raise GitHubControllerError("recovery build is not bound to current main")
    result = {"artifact_id": artifact["id"], "artifact_name": artifact["name"], "artifact_digest": artifact["digest"], "build_run_id": run["id"], "build_run_attempt": run["run_attempt"]}
    _output(**result)
    return result


def install(api: GitHubAPI, *, artifact_root: Path, slot: str, **kwargs: Any) -> dict[str, Any]:
    policy, main, actor = _authorize(api, stage="install", **kwargs)
    runners = {value["slot"]: value for value in policy["runners"]}
    if slot not in runners or _required("RUNNER_NAME") != runners[slot]["runner_name"]:
        raise GitHubControllerError("recovery install runner identity is not exact")
    artifact, run, _ = _build_bundle(api, kwargs["repository"], policy, kwargs["operation_id"])
    bundle = artifact_root / "controller"
    build = json.loads((artifact_root / "RECOVERY-BUILD.json").read_text(encoding="utf-8"))
    wheel, _ = verify_controller_inventory(bundle)
    wheel_digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if (
        build["subject"] != {"commit": main.checkout_sha, "tree": main.tree_sha}
        or build["wheel_sha256"] != wheel_digest
        or build.get("operation_id") != kwargs["operation_id"]
        or build.get("reason_code") != kwargs["reason_code"]
        or build.get("actor", {}).get("run_id") != str(run["id"])
        or build.get("actor", {}).get("run_attempt") != str(run["run_attempt"])
        or build.get("actor", {}).get("login")
        != str(run.get("actor", {}).get("login"))
    ):
        raise GitHubControllerError("recovery build receipt is not the exact current-main bundle")
    result = install_controller(
        api, repository=kwargs["repository"], artifact_dir=bundle,
        artifact_id=artifact["id"], artifact_name=artifact["name"], provider_digest=artifact["digest"],
        producer_run_id=run["id"], producer_run_attempt=run["run_attempt"], repository_id=main.repository_id,
        commit_sha=main.checkout_sha, tree_sha=main.tree_sha, wheel_sha256=wheel_digest,
        selected_python=Path(_required("BCF_PYTHON")), tool_cache=Path(_required("RUNNER_TOOL_CACHE")),
    )
    receipt = {"slot": slot, "runner_name": runners[slot]["runner_name"], "job_id": _required("GITHUB_JOB"), "run_id": actor["run_id"], "run_attempt": actor["run_attempt"], "target": main.checkout_sha, **result}
    _write_json(kwargs["output"], receipt)
    return receipt


def probe(api: GitHubAPI, *, slot: str, **kwargs: Any) -> dict[str, Any]:
    policy, main, actor = _authorize(api, stage="probe", **kwargs)
    runners = {value["slot"]: value for value in policy["runners"]}
    if slot not in runners or _required("RUNNER_NAME") != runners[slot]["runner_name"]:
        raise GitHubControllerError("recovery probe runner identity is not exact")
    artifact, build_run, _, custody = _authenticated_build(
        api,
        repository=kwargs["repository"],
        policy=policy,
        operation_id=kwargs["operation_id"],
        main=main,
    )
    _, install_run, _ = _install_run(
        api, kwargs["repository"], policy, kwargs["operation_id"]
    )
    if int(actor["run_id"]) <= int(install_run["id"]):
        raise GitHubControllerError("recovery probe did not follow installation")
    root = Path(_required("RUNNER_TOOL_CACHE")).resolve() / "bcf-governance" / main.checkout_sha
    executable = root / "bin/bcf"
    metadata = controller_metadata(root / "INSTALL-METADATA.json")
    expected_metadata = {
        "artifact_id": str(artifact["id"]),
        "artifact_digest": artifact["digest"],
        "artifact_run_id": str(build_run["id"]),
        "commit_sha": main.checkout_sha,
        "wheel_sha256": custody["wheel_sha256"],
    }
    if (
        root.is_symlink()
        or not executable.is_file()
        or executable.is_symlink()
        or metadata != expected_metadata
    ):
        raise GitHubControllerError("recovery probe target is not the exact installation")
    try:
        subprocess.run(
            [str(executable), "ci-github", "--help"], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GitHubControllerError("recovery probe executable failed") from exc
    receipt = {"slot": slot, "runner_name": runners[slot]["runner_name"], "job_id": _required("GITHUB_JOB"), "run_id": actor["run_id"], "run_attempt": actor["run_attempt"], "target": main.checkout_sha, "install_metadata": metadata}
    _write_json(kwargs["output"], receipt)
    return receipt


def finalize(api: GitHubAPI, **kwargs: Any) -> dict[str, Any]:
    policy, main, actor = _authorize(api, stage="probe", **kwargs)
    artifact, build_run, build_job, custody = _authenticated_build(
        api,
        repository=kwargs["repository"],
        policy=policy,
        operation_id=kwargs["operation_id"],
        main=main,
    )
    jobs = api.jobs(kwargs["repository"], actor["run_id"], attempt=int(actor["run_attempt"]))
    expected = {f"Probe recovered controller / {value['slot']}" for value in policy["runners"]}
    observed = {str(job.get("name")): job for job in jobs if str(job.get("name")) in expected}
    runner_by_job = {
        f"Probe recovered controller / {value['slot']}": value
        for value in policy["runners"]
    }
    if set(observed) != expected or any(
        job.get("status") != "completed"
        or job.get("conclusion") != "success"
        or str(job.get("runner_name")) != runner_by_job[name]["runner_name"]
        or runner_by_job[name]["slot"] not in job.get("labels", [])
        for name, job in observed.items()
    ):
        raise GitHubControllerError("recovery probe inventory is not exactly green")
    _, install_run, install_jobs = _install_run(
        api, kwargs["repository"], policy, kwargs["operation_id"]
    )
    if int(actor["run_id"]) <= int(install_run["id"]):
        raise GitHubControllerError("recovery probe did not follow installation")
    if (
        str(build_run.get("actor", {}).get("login")) != actor["login"]
        or str(install_run.get("actor", {}).get("login")) != actor["login"]
    ):
        raise GitHubControllerError("recovery stage actor identity changed")
    receipt = {
        "schema_version": "1.0", "operation_id": kwargs["operation_id"], "reason_code": kwargs["reason_code"],
        "repository": {"id": main.repository_id, "name": kwargs["repository"], "branch": main.default_branch}, "actor": actor,
        "pre_recovery_controller": _required("BCF_PRE_RECOVERY_CONTROLLER"),
        "subject": {"commit": main.checkout_sha, "tree": main.tree_sha},
        "builder": {"workflow": policy["authority"]["workflow_path"], "job": policy["builder"]["job_name"], "job_id": str(build_job["id"]), "run_id": str(build_run["id"]), "run_attempt": str(build_run["run_attempt"])},
        "artifact": {"id": str(artifact["id"]), "name": artifact["name"], "provider_digest": artifact["digest"], **custody},
        "install": {"run_id": str(install_run["id"]), "run_attempt": str(install_run["run_attempt"]), "jobs": {name: {"id": str(job["id"]), "runner_name": str(job["runner_name"])} for name, job in sorted(install_jobs.items())}},
        "probe": {"run_id": actor["run_id"], "run_attempt": actor["run_attempt"], "jobs": {name: {"id": str(job["id"]), "runner_name": str(job["runner_name"])} for name, job in sorted(observed.items())}},
        "controller_confirmation": {"schema_version": "1.0", "installed_commit_sha": main.checkout_sha, "subject_commit_sha": main.checkout_sha, "subject_tree_sha": main.tree_sha, "bootstrap_run_id": str(install_run["id"]), "bootstrap_run_attempt": str(install_run["run_attempt"]), "probe_run_id": actor["run_id"], "probe_run_attempt": actor["run_attempt"]},
        "resulting_installed_controller": main.checkout_sha, "recovery_only": True, "governance_certified": False,
        "provider_timestamps": {"builder_created_at": build_run["created_at"], "install_created_at": install_run["created_at"], "probe_created_at": api.run(kwargs["repository"], actor["run_id"])["created_at"]},
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    Draft202012Validator(json.loads((kwargs["root"] / RECEIPT_SCHEMA).read_text())).validate(receipt)
    _write_json(kwargs["output"], receipt)
    return receipt


def project_installation(*, root: Path, receipt_path: Path) -> dict[str, Any]:
    """Project only recovery-proven installed state for a protected follow-up PR."""

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    schema = json.loads((root / RECEIPT_SCHEMA).read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER).validate(receipt)
    subject = receipt["subject"]
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()
    if (
        {"commit": head, "tree": tree} != subject
        or receipt["resulting_installed_controller"] != head
        or receipt["controller_confirmation"]["installed_commit_sha"] != head
    ):
        raise GitHubControllerError("recovery receipt is not for exact local main")
    policy_path = root / "governance/self-governance-policy.yml"
    raw = policy_path.read_bytes()
    policy = yaml.safe_load(raw)
    runner = policy.get("runner_security", {})
    pin = runner.get("trusted_controller_artifact", {})
    current = runner.get("trusted_controller_installation", {})
    if current.get("installed_commit_sha") != pin.get("BCF_BOOTSTRAP_COMMIT_SHA"):
        raise GitHubControllerError("ordinary controller rotation is already pending")
    confirmation = yaml.safe_dump(
        receipt["controller_confirmation"], sort_keys=False,
        default_flow_style=True, width=1000,
    ).strip()
    pattern = re.compile(rb"(?m)^  trusted_controller_installation: \{[^\r\n]*\}$")
    if len(pattern.findall(raw)) != 1:
        raise GitHubControllerError("canonical installed-controller proof is not unique")
    projected = pattern.sub(
        f"  trusted_controller_installation: {confirmation}".encode(), raw
    )
    if projected == raw:
        raise GitHubControllerError("recovery installation is already projected")
    _write_atomic(policy_path, projected)
    lock = apply_ci_graph_locks(root)
    render = apply_ci_graph(root)
    return {
        "status": "recovery_installation_projected_for_protected_pr",
        "installed_commit_sha": head,
        "changed_paths": sorted(
            {"governance/self-governance-policy.yml", *lock.changed_inputs, *render.changed_paths}
        ),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["authorize-build", "bind-build", "resolve-build", "install", "probe", "finalize", "project-installation"])
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--repository")
    parser.add_argument("--operation-id")
    parser.add_argument("--reason-code")
    parser.add_argument("--stage", choices=["install", "probe"])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--authorization", type=Path)
    parser.add_argument("--slot")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args(argv)
    root = args.repo_root.resolve()
    if args.operation == "project-installation":
        result = project_installation(root=root, receipt_path=args.receipt)
    elif args.operation == "bind-build":
        result = bind_build(args.artifact_root, args.artifact_root / "controller", args.authorization)
    else:
        api = GitHubAPI(token=_required("BCF_BREAK_GLASS_APP_TOKEN"))
        common = {"root": root, "repository": args.repository, "operation_id": args.operation_id, "reason_code": args.reason_code, "output": args.output}
        if args.operation == "authorize-build": result = authorize_build(api, **common)
        elif args.operation == "resolve-build": result = resolve_build(api, stage=args.stage, **common)
        elif args.operation == "install": result = install(api, artifact_root=args.artifact_root, slot=args.slot, **common)
        elif args.operation == "probe": result = probe(api, slot=args.slot, **common)
        else: result = finalize(api, **common)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

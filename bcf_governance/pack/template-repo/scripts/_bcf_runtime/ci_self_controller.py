"""Mechanical BCF self-controller selection and workflow projection."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

import yaml

from .ci_authority_contracts import authority_role_workflow
from .ci_github_api import GitHubAPI
from .ci_github_artifacts import ProviderArtifact, resolve_role_artifact
from .ci_github_authority import authenticate_role_run, load_authority
from .ci_github_bootstrap import controller_metadata, verify_controller_inventory
from .ci_github_identity import GitHubControllerError, resolve_main
from .ci_github_membership import collect_same_run_producers, select_latest_admission


PIN_KEYS = (
    "BCF_BOOTSTRAP_ARTIFACT_ID",
    "BCF_BOOTSTRAP_ARTIFACT_NAME",
    "BCF_BOOTSTRAP_ARTIFACT_DIGEST",
    "BCF_BOOTSTRAP_RUN_ID",
    "BCF_BOOTSTRAP_RUN_ATTEMPT",
    "BCF_BOOTSTRAP_COMMIT_SHA",
    "BCF_BOOTSTRAP_TREE_SHA",
    "BCF_BOOTSTRAP_REPOSITORY_ID",
    "BCF_BOOTSTRAP_WHEEL_SHA256",
)
BOOTSTRAP_WORKFLOW = ".github/workflows/bcf-trusted-control-bootstrap.yml"
PROBE_WORKFLOW = ".github/workflows/bcf-trusted-control-probe.yml"
BOOTSTRAP_WORKFLOWS = (BOOTSTRAP_WORKFLOW, PROBE_WORKFLOW)
TOPOLOGY_PATH = "governance/github-ci-topology.yml"
INSTALLATION_KEYS = (
    "schema_version",
    "installed_commit_sha",
    "subject_commit_sha",
    "subject_tree_sha",
    "bootstrap_run_id",
    "bootstrap_run_attempt",
    "probe_run_id",
    "probe_run_attempt",
)


@dataclass(frozen=True)
class SelfControllerProjection:
    status: str
    changed_paths: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {"status": self.status, "changed_paths": list(self.changed_paths)}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pin(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != set(PIN_KEYS):
        raise GitHubControllerError("self-controller pin inventory is not exact")
    pin = {key: str(value[key]) for key in PIN_KEYS}
    numeric = (
        "BCF_BOOTSTRAP_ARTIFACT_ID", "BCF_BOOTSTRAP_RUN_ID",
        "BCF_BOOTSTRAP_RUN_ATTEMPT", "BCF_BOOTSTRAP_REPOSITORY_ID",
    )
    if any(not pin[key].isdigit() or int(pin[key]) < 1 for key in numeric):
        raise GitHubControllerError("self-controller provider identities must be positive")
    for key in ("BCF_BOOTSTRAP_COMMIT_SHA", "BCF_BOOTSTRAP_TREE_SHA"):
        if not re.fullmatch(r"[a-f0-9]{40}", pin[key]):
            raise GitHubControllerError("self-controller Git identity is not exact")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", pin["BCF_BOOTSTRAP_ARTIFACT_DIGEST"]):
        raise GitHubControllerError("self-controller provider digest is not exact")
    if not re.fullmatch(r"[a-f0-9]{64}", pin["BCF_BOOTSTRAP_WHEEL_SHA256"]):
        raise GitHubControllerError("self-controller wheel digest is not exact")
    expected_name = (
        f"bcf-trusted-control-{pin['BCF_BOOTSTRAP_COMMIT_SHA']}-"
        f"{pin['BCF_BOOTSTRAP_RUN_ATTEMPT']}"
    )
    if pin["BCF_BOOTSTRAP_ARTIFACT_NAME"] != expected_name:
        raise GitHubControllerError("self-controller artifact name is not derived")
    return pin


def _installation(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != set(INSTALLATION_KEYS):
        raise GitHubControllerError("installed-controller proof inventory is not exact")
    proof = {key: str(value[key]) for key in INSTALLATION_KEYS}
    if proof["schema_version"] != "1.0":
        raise GitHubControllerError("installed-controller proof version is unsupported")
    for key in ("installed_commit_sha", "subject_commit_sha", "subject_tree_sha"):
        if not re.fullmatch(r"[a-f0-9]{40}", proof[key]):
            raise GitHubControllerError("installed-controller Git identity is not exact")
    for key in (
        "bootstrap_run_id", "bootstrap_run_attempt", "probe_run_id",
        "probe_run_attempt",
    ):
        if not proof[key].isdigit() or int(proof[key]) < 1:
            raise GitHubControllerError("installed-controller run identity is not positive")
    if int(proof["probe_run_id"]) <= int(proof["bootstrap_run_id"]):
        raise GitHubControllerError("controller probe must follow its bootstrap run")
    return proof


def resolve_self_controller_artifact(
    api: GitHubAPI, *, repository: str
) -> tuple[dict[str, str], ProviderArtifact]:
    """Select the latest exact-main controller without a caller-supplied run or name."""

    main = resolve_main(api, repository)
    authority = load_authority(api, repository, main, required_version="1.1")
    run_id, attempt = select_latest_admission(
        api, repository=repository, main=main, authority=authority
    )
    producers = collect_same_run_producers(
        api,
        repository=repository,
        main=main,
        authority=authority,
        admission_run_id=run_id,
        admission_run_attempt=attempt,
    )
    package = [value for value in producers if value["producer_id"] == "governance-pack"]
    if len(package) != 1:
        raise GitHubControllerError("latest exact-main package producer is not unique")
    package_attempt = package[0]["attempts"][0]
    if package_attempt["status"] != "completed" or (
        package_attempt["conclusion"] != "success"
    ):
        raise GitHubControllerError("latest exact-main package producer is not successful")
    name = f"bcf-trusted-control-{main.checkout_sha}-{attempt}"
    artifact = resolve_role_artifact(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="admission",
        run_id=run_id,
        run_attempt=attempt,
        artifact_name=name,
        require_success=False,
    )
    return {
        "repository_id": main.repository_id,
        "commit_sha": main.checkout_sha,
        "tree_sha": main.tree_sha,
    }, artifact


def compile_self_controller_pin(
    api: GitHubAPI, *, repository: str, artifact_dir: Path
) -> dict[str, str]:
    """Compile one canonical pin from provider state and downloaded exact bytes."""

    subject, artifact = resolve_self_controller_artifact(api, repository=repository)
    root = artifact_dir.resolve()
    wheel, _ = verify_controller_inventory(root)
    expected_metadata = {
        "schema_version": "1.0",
        "commit_sha": subject["commit_sha"],
        "tree_sha": subject["tree_sha"],
        "workflow_run_id": artifact.run_id,
        "workflow_run_attempt": str(artifact.run_attempt),
    }
    if controller_metadata(root / "CONTROL-METADATA.json") != expected_metadata:
        raise GitHubControllerError("controller metadata is not the selected provider subject")
    return _pin(
        {
            "BCF_BOOTSTRAP_ARTIFACT_ID": artifact.artifact_id,
            "BCF_BOOTSTRAP_ARTIFACT_NAME": artifact.artifact_name,
            "BCF_BOOTSTRAP_ARTIFACT_DIGEST": artifact.provider_digest,
            "BCF_BOOTSTRAP_RUN_ID": artifact.run_id,
            "BCF_BOOTSTRAP_RUN_ATTEMPT": str(artifact.run_attempt),
            "BCF_BOOTSTRAP_COMMIT_SHA": subject["commit_sha"],
            "BCF_BOOTSTRAP_TREE_SHA": subject["tree_sha"],
            "BCF_BOOTSTRAP_REPOSITORY_ID": subject["repository_id"],
            "BCF_BOOTSTRAP_WHEEL_SHA256": _sha256(wheel),
        }
    )


def _successful_role_run(
    api: GitHubAPI,
    *,
    repository: str,
    main: Any,
    authority: dict[str, Any],
    role: str,
    job_id: str,
    instance_labels: tuple[str, ...],
) -> tuple[str, str]:
    workflow = authority_role_workflow(authority, role)
    runs = api.workflow_runs(
        repository,
        workflow["workflow_id"],
        head_sha=main.checkout_sha,
        event="workflow_dispatch",
    )
    exact = [
        run for run in runs
        if str(run.get("head_sha")) == main.checkout_sha
        and str(run.get("repository", {}).get("id")) == main.repository_id
        and str(run.get("event")) == "workflow_dispatch"
    ]
    if not exact:
        raise GitHubControllerError(f"no exact-main {role} proof run exists")
    selected = max(
        exact,
        key=lambda value: (int(str(value.get("id", 0))), int(str(value.get("run_attempt", 0)))),
    )
    identity = authenticate_role_run(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role=role,
        run_id=selected.get("id"),
        run_attempt=selected.get("run_attempt"),
        require_success=True,
    )
    trusted = api.content(
        repository, str(workflow["active_path"]), ref=main.checkout_sha
    )
    try:
        definition = yaml.safe_load(trusted.content.decode("utf-8"))
        job = definition["jobs"][job_id]
        template = str(job["name"])
        declared = tuple(str(value) for value in job["strategy"]["matrix"]["trusted_runner"])
    except (KeyError, TypeError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise GitHubControllerError(f"{role} proof workflow topology is invalid") from exc
    marker = "${{ matrix.trusted_runner }}"
    if declared != instance_labels or template.count(marker) != 1:
        raise GitHubControllerError(f"{role} proof runner topology is not canonical")
    expected = {template.replace(marker, label) for label in instance_labels}
    jobs = api.jobs(repository, identity.run_id, attempt=identity.run_attempt)
    observed = {str(job.get("name")): job for job in jobs}
    if set(observed) != expected or any(
        job.get("status") != "completed" or job.get("conclusion") != "success"
        for job in observed.values()
    ):
        raise GitHubControllerError(f"{role} proof job inventory is not exactly green")
    return identity.run_id, str(identity.run_attempt)


def compile_self_controller_confirmation(
    api: GitHubAPI, *, repository: str
) -> dict[str, str]:
    """Compile installed-controller state only from authenticated provider proofs."""

    main = resolve_main(api, repository)
    authority = load_authority(api, repository, main, required_version="1.1")
    content = api.content(
        repository, "governance/self-governance-policy.yml", ref=main.checkout_sha
    )
    try:
        policy = yaml.safe_load(content.content.decode("utf-8"))
        runner = policy["runner_security"]
        pin = _pin(runner["trusted_controller_artifact"])
        labels = tuple(str(value) for value in runner["trusted_instance_labels"])
    except (KeyError, TypeError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise GitHubControllerError("provider self-controller policy is invalid") from exc
    if len(labels) < 2 or len(labels) != len(set(labels)):
        raise GitHubControllerError("trusted controller proof requires distinct runners")
    bootstrap_run, bootstrap_attempt = _successful_role_run(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="bootstrap",
        job_id="bootstrap",
        instance_labels=labels,
    )
    probe_run, probe_attempt = _successful_role_run(
        api,
        repository=repository,
        main=main,
        authority=authority,
        role="probe",
        job_id="probe",
        instance_labels=labels,
    )
    return _installation(
        {
            "schema_version": "1.0",
            "installed_commit_sha": pin["BCF_BOOTSTRAP_COMMIT_SHA"],
            "subject_commit_sha": main.checkout_sha,
            "subject_tree_sha": main.tree_sha,
            "bootstrap_run_id": bootstrap_run,
            "bootstrap_run_attempt": bootstrap_attempt,
            "probe_run_id": probe_run,
            "probe_run_attempt": probe_attempt,
        }
    )


def _replace_env(raw: bytes, desired: dict[str, str]) -> bytes:
    text = raw.decode("utf-8")
    parsed = yaml.safe_load(text)
    current = parsed.get("env") if isinstance(parsed, dict) else None
    if not isinstance(current, dict):
        raise GitHubControllerError("self-controller workflow lacks an environment mapping")
    for key, value in desired.items():
        if key not in current:
            raise GitHubControllerError(f"self-controller workflow lacks {key}")
        line = re.compile(rf"(?m)^  {re.escape(key)}:.*$")
        if len(line.findall(text)) != 1:
            raise GitHubControllerError(f"self-controller workflow duplicates {key}")
        rendered = json.dumps(value) if value.isdigit() else value
        text = line.sub(f"  {key}: {rendered}", text)
    return text.encode("utf-8")


def _replace_topology_controller(raw: bytes, commit_sha: str) -> bytes:
    text = raw.decode("utf-8")
    parsed = yaml.safe_load(text)
    current = parsed.get("controller_commit") if isinstance(parsed, dict) else None
    if not isinstance(current, str) or not re.fullmatch(r"[a-f0-9]{40}", current):
        raise GitHubControllerError("GitHub topology controller commit is invalid")
    line = re.compile(r"(?m)^controller_commit: [a-f0-9]{40}$")
    if len(line.findall(text)) != 1:
        raise GitHubControllerError("GitHub topology controller commit is not unique")
    return line.sub(f"controller_commit: {commit_sha}", text).encode("utf-8")


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


def project_self_controller_pin(
    repo_root: Path,
    *,
    pin: dict[str, str],
    confirmation: dict[str, str] | None = None,
    apply: bool,
) -> SelfControllerProjection:
    """Project target and proven-installed controller state transactionally."""

    root = repo_root.resolve()
    exact = _pin(pin)
    policy_path = root / "governance/self-governance-policy.yml"
    policy_raw = policy_path.read_bytes()
    policy = yaml.safe_load(policy_raw)
    runner_security = policy.get("runner_security") if isinstance(policy, dict) else None
    if not isinstance(runner_security, dict):
        raise GitHubControllerError("self-governance runner policy is invalid")
    current_pin = _pin(runner_security.get("trusted_controller_artifact"))
    current_installation = _installation(
        runner_security.get("trusted_controller_installation")
    )
    if (
        exact != current_pin
        and current_installation["installed_commit_sha"]
        != current_pin["BCF_BOOTSTRAP_COMMIT_SHA"]
    ):
        raise GitHubControllerError(
            "a controller rotation is already pending independent confirmation"
        )
    installation = (
        current_installation if confirmation is None else _installation(confirmation)
    )
    if confirmation is not None and installation["installed_commit_sha"] != exact[
        "BCF_BOOTSTRAP_COMMIT_SHA"
    ]:
        raise GitHubControllerError("confirmation does not prove the target controller")
    new_flow = yaml.safe_dump(
        exact, sort_keys=False, default_flow_style=True, width=1000
    ).strip()
    pattern = re.compile(rb"(?m)^  trusted_controller_artifact: \{[^\r\n]*\}$")
    if len(pattern.findall(policy_raw)) != 1:
        raise GitHubControllerError("canonical self-controller pin is not unique")
    installation_flow = yaml.safe_dump(
        installation, sort_keys=False, default_flow_style=True, width=1000
    ).strip()
    installation_pattern = re.compile(
        rb"(?m)^  trusted_controller_installation: \{[^\r\n]*\}$"
    )
    if len(installation_pattern.findall(policy_raw)) != 1:
        raise GitHubControllerError("canonical installed-controller proof is not unique")
    projected_policy = pattern.sub(
        f"  trusted_controller_artifact: {new_flow}".encode(), policy_raw
    )
    projected_policy = installation_pattern.sub(
        f"  trusted_controller_installation: {installation_flow}".encode(),
        projected_policy,
    )
    active_commit = installation["installed_commit_sha"]
    desired: dict[Path, bytes] = {
        policy_path: projected_policy,
        root / TOPOLOGY_PATH: _replace_topology_controller(
            (root / TOPOLOGY_PATH).read_bytes(), active_commit
        ),
    }
    bootstrap = root / BOOTSTRAP_WORKFLOW
    desired[bootstrap] = _replace_env(
        bootstrap.read_bytes(),
        {**exact, "BCF_INSTALLED_CONTROLLER_COMMIT_SHA": active_commit},
    )
    probe = root / PROBE_WORKFLOW
    desired[probe] = _replace_env(probe.read_bytes(), exact)
    required = runner_security.get("trusted_controller_interpreter", {}).get(
        "required_workflows"
    )
    if not isinstance(required, list):
        raise GitHubControllerError("trusted controller workflow inventory is invalid")
    for relative in required:
        if relative in BOOTSTRAP_WORKFLOWS:
            continue
        path = root / str(relative)
        desired[path] = _replace_env(
            path.read_bytes(), {"BCF_CONTROL_COMMIT": active_commit}
        )
    changed = tuple(
        path.relative_to(root).as_posix()
        for path, raw in desired.items()
        if path.read_bytes() != raw
    )
    if apply:
        for path, raw in desired.items():
            if path.relative_to(root).as_posix() in changed:
                _write_atomic(path, raw)
    return SelfControllerProjection("changed" if changed else "clean", changed)


def verify_self_controller_projection(repo_root: Path) -> int:
    """Reject any self-controller copy that differs from its canonical pin."""

    root = repo_root.resolve()
    policy = yaml.safe_load(
        (root / "governance/self-governance-policy.yml").read_text(encoding="utf-8")
    )
    runner_security = policy.get("runner_security") if isinstance(policy, dict) else None
    pin = (
        runner_security.get("trusted_controller_artifact")
        if isinstance(runner_security, dict)
        else None
    )
    result = project_self_controller_pin(root, pin=pin, apply=False)
    if result.status != "clean":
        raise GitHubControllerError(
            "self-controller projection drifted: " + ", ".join(result.changed_paths)
        )
    required = runner_security.get("trusted_controller_interpreter", {}).get(
        "required_workflows"
    )
    if not isinstance(required, list):
        raise GitHubControllerError("trusted controller workflow inventory is invalid")
    return 1 + len(required)

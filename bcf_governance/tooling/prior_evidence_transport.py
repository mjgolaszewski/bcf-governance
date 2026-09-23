"""Authenticate and preserve one merged PR's exact provider evidence.

This module transports immutable source bytes only.  It deliberately makes no
claim-applicability, equivalence, qualification, or reuse decision.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any
import zipfile

from jsonschema import Draft202012Validator
import yaml

from .ci_authority_state import CandidateIdentity
from .ci_github_api import GitHubAPI
from .ci_github_authority import packaged_repo_root
from .ci_github_bundle import canonical_json, prepare_output, write_exclusive
from .ci_github_identity import (
    GitHubControllerError,
    MainIdentity,
    authenticate_trusted_run,
    exact_sha,
    positive_int,
    resolve_main,
)
from .github_protection import (
    PROTECTION_PATH,
    inspect_protection_declaration,
    load_protection_bytes,
)
from .protection_inspection_client import ProtectionInspectionClient
from .provider_job_inventory import candidate_governance_job_inventory


FINALIZER_WORKFLOW = ".github/workflows/bcf-pr-finalizer.yml"
POLICY_PATH = "governance/self-governance-policy.yml"
CHECK_CONTEXT = "bcf/pr-certification"
CHECK_APP_ID = 15368
MAX_ARCHIVE_BYTES = 104_857_600
MAX_EXPANDED_BYTES = 268_435_456


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _mapping(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise GitHubControllerError(f"{label} is not a valid mapping") from exc
    if not isinstance(value, dict):
        raise GitHubControllerError(f"{label} must be a mapping")
    return value


def _object(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubControllerError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise GitHubControllerError(f"{label} must be an object")
    return value


def _archive_files(raw: bytes) -> dict[str, bytes]:
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise GitHubControllerError("prior-evidence artifact exceeds its size limit")
    files: dict[str, bytes] = {}
    expanded = 0
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            members = archive.infolist()
            if len(members) > 10_000:
                raise GitHubControllerError("prior-evidence artifact inventory is oversized")
            for member in members:
                path = PurePosixPath(member.filename)
                if member.is_dir():
                    continue
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or member.flag_bits & 0x1
                    or (member.external_attr >> 16) & 0o170000 == 0o120000
                ):
                    raise GitHubControllerError("prior-evidence artifact has an unsafe member")
                name = path.as_posix()
                if not name or name in files:
                    raise GitHubControllerError("prior-evidence artifact members are ambiguous")
                expanded += member.file_size
                if expanded > MAX_EXPANDED_BYTES:
                    raise GitHubControllerError("prior-evidence artifact expansion is oversized")
                files[name] = archive.read(member)
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        raise GitHubControllerError("prior-evidence artifact is not a valid ZIP") from exc
    if not files:
        raise GitHubControllerError("prior-evidence artifact is empty")
    return files


def _artifact_identity(
    artifact: dict[str, Any], *, repository_id: str, run_id: str,
    head_sha: str, head_branch: str,
) -> tuple[str, str]:
    artifact_id = str(positive_int(artifact.get("id"), field="artifact ID"))
    digest = str(artifact.get("digest", ""))
    expected_run = {
        "id": int(run_id),
        "repository_id": int(repository_id),
        "head_repository_id": int(repository_id),
        "head_branch": head_branch,
        "head_sha": head_sha,
    }
    if artifact.get("expired") is not False or artifact.get("workflow_run") != expected_run:
        raise GitHubControllerError("prior-evidence artifact provider identity is not exact")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise GitHubControllerError("prior-evidence artifact provider digest is invalid")
    return artifact_id, digest


def _main_at(api: GitHubAPI, repository: str, *, sha: str, branch: str,
             repository_id: str) -> MainIdentity:
    commit = api.commit(repository, sha)
    tree = commit.get("tree")
    if not isinstance(tree, dict):
        raise GitHubControllerError("source base commit tree is missing")
    return MainIdentity(
        repository_id=repository_id,
        default_branch=branch,
        checkout_sha=exact_sha(sha, field="source base SHA"),
        tree_sha=exact_sha(tree.get("sha"), field="source base tree SHA"),
    )


def _merged_pull(
    api: GitHubAPI, repository: str, *, main: MainIdentity
) -> tuple[dict[str, Any], CandidateIdentity, MainIdentity, str]:
    associated = api.commit_pull_requests(repository, sha=main.checkout_sha)
    exact = [
        value for value in associated
        if value.get("state") == "closed"
        and value.get("merged_at")
        and value.get("merge_commit_sha") == main.checkout_sha
    ]
    if len(exact) != 1:
        raise GitHubControllerError("current main must identify exactly one merged pull request")
    number = positive_int(exact[0].get("number"), field="pull request number")
    pull = api.pull_request(repository, number)
    if any(
        pull.get(field) != exact[0].get(field)
        for field in ("number", "state", "merged_at", "merge_commit_sha")
    ):
        raise GitHubControllerError("merged pull request provider views are inconsistent")
    head, base = pull.get("head"), pull.get("base")
    if not isinstance(head, dict) or not isinstance(base, dict):
        raise GitHubControllerError("merged pull request identity is incomplete")
    for label, value in (("head", head), ("base", base)):
        repo = value.get("repo")
        if not isinstance(repo, dict) or str(repo.get("id")) != main.repository_id:
            raise GitHubControllerError(f"merged pull request {label} repository is not exact")
    if str(base.get("ref")) != main.default_branch:
        raise GitHubControllerError("merged pull request base branch is not default main")
    candidate_sha = exact_sha(head.get("sha"), field="pull request head SHA")
    candidate_commit = api.commit(repository, candidate_sha)
    candidate_tree = candidate_commit.get("tree")
    if not isinstance(candidate_tree, dict):
        raise GitHubControllerError("pull request head tree is missing")
    candidate = CandidateIdentity(
        checkout_sha=candidate_sha,
        tree_sha=exact_sha(candidate_tree.get("sha"), field="pull request head tree SHA"),
    )
    source_main = _main_at(
        api, repository, sha=exact_sha(base.get("sha"), field="pull request base SHA"),
        branch=main.default_branch, repository_id=main.repository_id,
    )
    branch = str(head.get("ref", ""))
    if not branch:
        raise GitHubControllerError("pull request head branch is missing")
    return pull, candidate, source_main, branch


def _successful_check(
    api: GitHubAPI, repository: str, *, candidate_sha: str, merged_at: str
) -> tuple[dict[str, Any], str, int]:
    matches = [
        value for value in api.check_runs(repository, sha=candidate_sha)
        if value.get("name") == CHECK_CONTEXT
        and isinstance(value.get("app"), dict)
        and value["app"].get("id") == CHECK_APP_ID
    ]
    if not matches:
        raise GitHubControllerError("merged pull request has no trusted certification check")
    latest = max(matches, key=lambda value: positive_int(value.get("id"), field="check run ID"))
    if (
        latest.get("head_sha") != candidate_sha
        or latest.get("status") != "completed"
        or latest.get("conclusion") != "success"
        or not isinstance(latest.get("completed_at"), str)
        or latest["completed_at"] > merged_at
    ):
        raise GitHubControllerError("latest trusted certification did not authorize this merge")
    external = str(latest.get("external_id", ""))
    match = re.fullmatch(r"bcf-pr-certification:([1-9][0-9]*):([1-9][0-9]*)", external)
    if match is None:
        raise GitHubControllerError("trusted certification lacks exact finalizer identity")
    return latest, match.group(1), int(match.group(2))


def _one_artifact(
    api: GitHubAPI, repository: str, *, run_id: str, expected_name: str,
    repository_id: str, head_sha: str, head_branch: str,
) -> tuple[dict[str, Any], str, str, bytes, dict[str, bytes]]:
    matches = [
        value for value in api.artifacts(repository, run_id)
        if value.get("name") == expected_name
    ]
    if len(matches) != 1:
        raise GitHubControllerError(f"artifact identity is not exact: {expected_name}")
    artifact_id, provider_digest = _artifact_identity(
        matches[0], repository_id=repository_id, run_id=run_id,
        head_sha=head_sha, head_branch=head_branch,
    )
    raw = api.artifact_bytes(repository, artifact_id, maximum_bytes=MAX_ARCHIVE_BYTES)
    if f"sha256:{_sha256(raw)}" != provider_digest:
        raise GitHubControllerError("artifact bytes do not match provider digest")
    return matches[0], artifact_id, provider_digest, raw, _archive_files(raw)


def _verify_receipts(
    api: GitHubAPI, archives: dict[str, dict[str, bytes]], *,
    candidate: CandidateIdentity, repository: str, run_id: str, run_attempt: int,
) -> list[dict[str, Any]]:
    schema = json.loads(
        (packaged_repo_root() / "schemas/evidence-receipt.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(schema)
    receipts: list[dict[str, Any]] = []
    evidence_ids: set[str] = set()
    for artifact_name, files in sorted(archives.items()):
        for path, raw in sorted(files.items()):
            if not path.endswith(".evidence.json"):
                continue
            value = _object(raw, label=f"source receipt {path}")
            errors = sorted(validator.iter_errors(value), key=lambda item: list(item.absolute_path))
            if errors:
                raise GitHubControllerError(f"source receipt schema rejected {path}")
            subject = value.get("subject")
            invocation = value.get("invocation")
            workflow = invocation.get("workflow") if isinstance(invocation, dict) else None
            execution_commit = exact_sha(
                subject.get("commit_sha") if isinstance(subject, dict) else None,
                field="receipt execution commit",
            )
            execution = api.commit(repository, execution_commit)
            execution_tree = execution.get("tree")
            if (
                not isinstance(subject, dict)
                or subject.get("tree_sha") != candidate.tree_sha
                or subject.get("execution_tree_sha") != candidate.tree_sha
                or not isinstance(execution_tree, dict)
                or execution_tree.get("sha") != candidate.tree_sha
                or not isinstance(workflow, dict)
                or str(workflow.get("run_id")) != run_id
                or positive_int(workflow.get("run_attempt"), field="receipt run attempt")
                != run_attempt
            ):
                raise GitHubControllerError("source receipt subject or invocation is not exact")
            receipt_parent = PurePosixPath(path).parent
            artifacts = value.get("artifacts")
            if not isinstance(artifacts, list):
                raise GitHubControllerError("source receipt artifact inventory is missing")
            for artifact in artifacts:
                relative = artifact.get("path") if isinstance(artifact, dict) else None
                digest = artifact.get("sha256") if isinstance(artifact, dict) else None
                source_path = (receipt_parent / str(relative)).as_posix()
                if (
                    not isinstance(relative, str)
                    or PurePosixPath(relative).is_absolute()
                    or ".." in PurePosixPath(relative).parts
                    or source_path not in files
                    or digest != _sha256(files[source_path])
                ):
                    raise GitHubControllerError("source receipt raw artifact is not hash-bound")
            evidence_id = str(value.get("evidence_id", ""))
            if not evidence_id or evidence_id in evidence_ids:
                raise GitHubControllerError("source receipt identities are missing or duplicated")
            evidence_ids.add(evidence_id)
            receipts.append({
                "evidence_id": evidence_id,
                "artifact_name": artifact_name,
                "path": path,
                "receipt_sha256": _sha256(raw),
            })
    if not receipts:
        raise GitHubControllerError("source evidence contains no receipts")
    return receipts


def _verify_session_and_truth(
    api: GitHubAPI, *, repository: str, candidate: CandidateIdentity,
    run_id: str, run_attempt: int, expected_artifacts: dict[str, str],
    archives: dict[str, dict[str, bytes]],
) -> None:
    session_name = f"bcf-session-{run_id}-{run_attempt}"
    truth_name = f"bcf-governance-truth-{run_id}-{run_attempt}"
    session_files = archives.get(session_name)
    truth_files = archives.get(truth_name)
    if not isinstance(session_files, dict) or len(session_files) != 1:
        raise GitHubControllerError("source evidence session inventory is not exact")
    session_path, session_raw = next(iter(session_files.items()))
    if not session_path.endswith("/evidence-session.json"):
        raise GitHubControllerError("source evidence session path is not canonical")
    session = _object(session_raw, label="source evidence session")
    producer = session.get("producer")
    subject = session.get("subject")
    execution_commit = exact_sha(
        subject.get("commit_sha") if isinstance(subject, dict) else None,
        field="session execution commit",
    )
    execution = api.commit(repository, execution_commit)
    tree = execution.get("tree")
    if (
        not isinstance(producer, dict)
        or producer.get("provider") != "github-actions"
        or producer.get("repository") != repository
        or str(producer.get("run_id")) != run_id
        or positive_int(producer.get("run_attempt"), field="session run attempt")
        != run_attempt
        or not isinstance(subject, dict)
        or subject.get("tree_sha") != candidate.tree_sha
        or not isinstance(tree, dict)
        or tree.get("sha") != candidate.tree_sha
    ):
        raise GitHubControllerError("source evidence session identity is not exact")
    for name, role in expected_artifacts.items():
        if role != "evidence":
            continue
        files = archives.get(name, {})
        copies = [raw for path, raw in files.items() if path.endswith("/evidence-session.json")]
        if not copies or any(raw != session_raw for raw in copies):
            raise GitHubControllerError("evidence shard session binding is incomplete")
    if not isinstance(truth_files, dict) or set(truth_files) != {"truth-report.json"}:
        raise GitHubControllerError("source truth artifact inventory is not exact")
    truth = _object(truth_files["truth-report.json"], label="source truth report")
    proposition = truth.get("certified_proposition")
    truth_subject = truth.get("subject")
    if (
        truth.get("status") != "pass"
        or not isinstance(truth_subject, dict)
        or truth_subject.get("commit_sha") != execution_commit
        or truth_subject.get("tree_sha") != candidate.tree_sha
        or not isinstance(proposition, dict)
        or proposition.get("conclusion") != "success"
        or proposition.get("subject") != {
            "commit_sha": execution_commit, "tree_sha": candidate.tree_sha
        }
    ):
        raise GitHubControllerError("source truth is not exact and successful")


def _controller_authority(
    api: GitHubAPI, repository: str, *, main: MainIdentity
) -> dict[str, str]:
    policy = _mapping(
        api.content(repository, POLICY_PATH, ref=main.checkout_sha).content,
        label="self-governance policy",
    )
    runner = policy.get("runner_security")
    pin = runner.get("trusted_controller_artifact") if isinstance(runner, dict) else None
    installed = runner.get("trusted_controller_installation") if isinstance(runner, dict) else None
    if not isinstance(pin, dict) or not isinstance(installed, dict):
        raise GitHubControllerError("trusted controller custody is incomplete")
    target = exact_sha(pin.get("BCF_BOOTSTRAP_COMMIT_SHA"), field="controller target")
    current = exact_sha(installed.get("installed_commit_sha"), field="installed controller")
    wheel = str(pin.get("BCF_BOOTSTRAP_WHEEL_SHA256", ""))
    if target != current or not re.fullmatch(r"[a-f0-9]{64}", wheel):
        raise GitHubControllerError("prior evidence requires ordinary-current controller custody")
    if "trusted_controller_recovery_reentry" in runner:
        raise GitHubControllerError("prior evidence cannot use recovery-reentry custody")
    return {"controller_commit_sha": current, "controller_bundle_sha256": wheel}


def _write_materialized(
    root: Path, archives: list[tuple[str, str, str, str, bytes, dict[str, bytes]]]
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    inventory: list[dict[str, Any]] = []
    payload_files: dict[str, str] = {}
    for artifact_id, name, role, provider_digest, raw, files in archives:
        archive_path = root / "archives" / f"{artifact_id}.zip"
        archive_path.parent.mkdir(mode=0o700, exist_ok=True)
        archive_path.write_bytes(raw)
        payload_files[archive_path.relative_to(root).as_posix()] = _sha256(raw)
        expanded_inventory: list[dict[str, Any]] = []
        for source_path, content in sorted(files.items()):
            target = root / "expanded" / artifact_id / source_path
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(content)
            relative = target.relative_to(root).as_posix()
            digest = _sha256(content)
            payload_files[relative] = digest
            expanded_inventory.append(
                {"path": source_path, "sha256": digest, "size": len(content)}
            )
        inventory.append({
            "artifact_id": artifact_id, "name": name, "role": role,
            "provider_digest": provider_digest, "archive_sha256": _sha256(raw),
            "files": expanded_inventory,
        })
    return inventory, payload_files


def transport_prior_evidence(
    api: GitHubAPI, *, repository: str, expected_main_sha: str, output_root: Path,
    protection_credential: tuple[str, str, str, str] | None = None,
) -> dict[str, Any]:
    """Authenticate current main's merged-PR evidence and preserve exact bytes."""

    main = resolve_main(api, repository)
    if main.checkout_sha != exact_sha(expected_main_sha, field="expected main SHA"):
        raise GitHubControllerError("provider main moved from the requested transport subject")
    pull, candidate, source_main, head_branch = _merged_pull(
        api, repository, main=main
    )
    merged_at = str(pull.get("merged_at", ""))
    check, finalizer_run, finalizer_attempt = _successful_check(
        api, repository, candidate_sha=candidate.checkout_sha, merged_at=merged_at
    )
    finalizer = authenticate_trusted_run(
        api, repository=repository, main=source_main, run_id=finalizer_run,
        run_attempt=finalizer_attempt, workflow_path=FINALIZER_WORKFLOW,
        expected_event="workflow_run", require_success=True,
    )
    finalizer_name = f"bcf-pr-finalization-{finalizer_run}-{finalizer_attempt}"
    _, finalizer_id, finalizer_digest, finalizer_raw, finalizer_files = _one_artifact(
        api, repository, run_id=finalizer_run, expected_name=finalizer_name,
        repository_id=main.repository_id, head_sha=source_main.checkout_sha,
        head_branch=main.default_branch,
    )
    if set(finalizer_files) != {"bundle-manifest.json", "pr-observation.json"}:
        raise GitHubControllerError("PR finalization bundle inventory is not exact")
    bundle_manifest = _object(
        finalizer_files["bundle-manifest.json"], label="PR finalization manifest"
    )
    observation = _object(
        finalizer_files["pr-observation.json"], label="PR finalization observation"
    )
    if (
        bundle_manifest.get("files") != {
            "pr-observation.json": _sha256(finalizer_files["pr-observation.json"])
        }
        or observation.get("computed_state") != "successful"
        or observation.get("pull_request") != pull.get("number")
        or observation.get("repository") != {
            "full_name": repository, "numeric_id": int(main.repository_id)
        }
        or observation.get("subject") != {
            "commit_sha": candidate.checkout_sha,
            "tree_sha": candidate.tree_sha,
            "branch": head_branch,
        }
        or observation.get("finalizer") != {
            "run_id": finalizer.run_id,
            "run_attempt": finalizer.run_attempt,
            "workflow": asdict(finalizer.workflow),
        }
    ):
        raise GitHubControllerError("PR finalization observation is not exact")
    producers = observation.get("producers")
    successful = [
        value for value in producers if isinstance(value, dict)
        and value.get("id") == "governance"
        and value.get("state") == "successful"
    ] if isinstance(producers, list) else []
    if len(successful) != 1 or len(producers) != 1:
        raise GitHubControllerError("PR finalization producer inventory is not exact")
    producer = successful[0]
    producer_run = str(positive_int(producer.get("run_id"), field="producer run ID"))
    producer_attempt = positive_int(producer.get("run_attempt"), field="producer run attempt")
    producer_identity = authenticate_trusted_run(
        api, repository=repository, main=source_main, run_id=producer_run,
        run_attempt=producer_attempt, workflow_path=".github/workflows/governance.yml",
        expected_event="pull_request", require_success=True, expected_candidate=candidate,
    )
    if producer.get("workflow") != asdict(producer_identity.workflow):
        raise GitHubControllerError("PR producer workflow identity is not exact")
    protection_raw = api.content(
        repository, PROTECTION_PATH.as_posix(), ref=source_main.checkout_sha
    ).content
    declaration = load_protection_bytes(
        protection_raw,
        schema_path=packaged_repo_root() / "schemas/github-protection.schema.json",
    )
    protection_inspector = None
    if protection_credential is not None:
        token, installation_id, observed_installation_id, api_url = protection_credential
        protection_inspector = ProtectionInspectionClient(
            token=token, repository=repository,
            repository_id=declaration["repository"]["numeric_id"],
            installation_id=installation_id,
            observed_installation_id=observed_installation_id,
            api_url=api_url,
        )
    inventory_subject_sha = candidate.checkout_sha
    expected_jobs = set(candidate_governance_job_inventory(
        api, repository=repository, candidate_sha=inventory_subject_sha,
    ))
    jobs = api.jobs(repository, producer_run, attempt=producer_attempt)
    check_id = positive_int(check.get("id"), field="check run ID")
    check_jobs = [value for value in jobs if value.get("id") == check_id]
    if len(check_jobs) > 1 or any(
        value.get("name") != CHECK_CONTEXT
        or value.get("status") != "completed"
        or value.get("conclusion") != "success"
        or str(value.get("run_id")) != producer_run
        or positive_int(value.get("run_attempt"), field="check job run attempt")
        != producer_attempt
        or value.get("head_sha") != candidate.checkout_sha
        or value.get("head_branch") != head_branch
        or value.get("runner_id") is not None
        or value.get("runner_name") is not None
        or value.get("labels") != []
        or value.get("steps") != []
        for value in check_jobs
    ):
        raise GitHubControllerError("protected App check job projection is not exact")
    workflow_jobs = tuple(value for value in jobs if value.get("id") != check_id)
    if (
        len(workflow_jobs) != len(expected_jobs)
        or {str(value.get("name")) for value in workflow_jobs} != expected_jobs
        or any(
            value.get("status") != "completed" or value.get("conclusion") != "success"
            for value in workflow_jobs
        )
    ):
        raise GitHubControllerError("PR producer job inventory is not exact and green")
    shard_count = sum(value.startswith("Evidence / ") for value in expected_jobs)
    expected_artifacts = {
        f"bcf-session-{producer_run}-{producer_attempt}": "session",
        f"bcf-governance-truth-{producer_run}-{producer_attempt}": "truth",
        **{
            f"bcf-evidence-{producer_run}-{producer_attempt}-shard-{index}": "evidence"
            for index in range(shard_count)
        },
    }
    provider_artifacts = api.artifacts(repository, producer_run)
    by_name = {str(value.get("name")): value for value in provider_artifacts}
    if len(by_name) != len(provider_artifacts) or set(by_name) != set(expected_artifacts):
        raise GitHubControllerError("PR producer artifact inventory is not exact")
    archives: list[tuple[str, str, str, str, bytes, dict[str, bytes]]] = [
        (finalizer_id, finalizer_name, "certification", finalizer_digest,
         finalizer_raw, finalizer_files)
    ]
    evidence_archives: dict[str, dict[str, bytes]] = {}
    producer_archives: dict[str, dict[str, bytes]] = {}
    for name, role in sorted(expected_artifacts.items()):
        _, artifact_id, digest, raw, files = _one_artifact(
            api, repository, run_id=producer_run, expected_name=name,
            repository_id=main.repository_id, head_sha=candidate.checkout_sha,
            head_branch=head_branch,
        )
        archives.append((artifact_id, name, role, digest, raw, files))
        producer_archives[name] = files
        if role == "evidence":
            evidence_archives[name] = files
    _verify_session_and_truth(
        api, repository=repository, candidate=candidate, run_id=producer_run,
        run_attempt=producer_attempt, expected_artifacts=expected_artifacts,
        archives=producer_archives,
    )
    receipts = _verify_receipts(
        api, evidence_archives, candidate=candidate, repository=repository,
        run_id=producer_run, run_attempt=producer_attempt,
    )
    if protection_inspector is not None:
        protection_inspector.verify_installation()
    protection = inspect_protection_declaration(
        protection_inspector if protection_inspector is not None else api,
        repository=repository, declaration=declaration,
    )
    if protection.status != "clean" or protection.ruleset_id is None:
        raise GitHubControllerError("provider protection does not match source authority")
    root = prepare_output(output_root)
    artifact_inventory, payload_files = _write_materialized(root, archives)
    artifact_ids = {value[1]: value[0] for value in archives}
    receipt_inventory = []
    for value in receipts:
        artifact_name = str(value["artifact_name"])
        receipt_inventory.append({
            **value,
            "artifact_id": artifact_ids[artifact_name],
            "immutable_reference": (
                f"github-actions://{repository}/runs/{producer_run}/attempts/"
                f"{producer_attempt}/artifacts/{artifact_ids[artifact_name]}/{value['path']}"
            ),
        })
    payload_digest = _sha256(canonical_json(dict(sorted(payload_files.items()))))
    manifest = {
        "schema_version": "1.0",
        "kind": "prior_evidence_transport",
        "repository": {
            "provider": "github", "full_name": repository,
            "repository_id": main.repository_id,
        },
        "pull_request": positive_int(pull.get("number"), field="pull request number"),
        "candidate": {
            "commit_sha": candidate.checkout_sha, "tree_sha": candidate.tree_sha,
        },
        "main": {"commit_sha": main.checkout_sha, "tree_sha": main.tree_sha},
        "merge": {
            "commit_sha": main.checkout_sha, "base_branch": main.default_branch,
            "merged_at": merged_at,
            "merged_by": (
                pull.get("merged_by", {}).get("login")
                if isinstance(pull.get("merged_by"), dict) else None
            ),
            "candidate_tree_equals_main_tree": candidate.tree_sha == main.tree_sha,
        },
        "producer": {
            "run_id": producer_identity.run_id,
            "run_attempt": producer_identity.run_attempt,
            "workflow": {
                "path": producer_identity.workflow.active_path,
                "workflow_id": producer_identity.workflow.workflow_id,
                "definition_commit": producer_identity.workflow.trusted_workflow_definition_commit,
                "definition_sha256": producer_identity.workflow.trusted_workflow_sha256,
            },
        },
        "certification": {
            "context": CHECK_CONTEXT, "app_id": CHECK_APP_ID,
            "check_run_id": str(positive_int(check.get("id"), field="check run ID")),
            "finalizer_run_id": finalizer_run,
            "finalizer_run_attempt": finalizer_attempt,
            "completed_at": check["completed_at"],
        },
        "authority": _controller_authority(api, repository, main=main),
        "protection": {
            "declaration_sha256": _sha256(protection_raw),
            "ruleset_id": protection.ruleset_id, "provider_state": "clean",
            "required_context": CHECK_CONTEXT, "publisher_app_id": CHECK_APP_ID,
            "bypass_actors": [],
        },
        "artifacts": artifact_inventory,
        "receipts": receipt_inventory,
        "bundle_sha256": payload_digest,
        "authenticated_at": check["completed_at"],
    }
    write_exclusive(root / "prior-evidence-transport.json", manifest)
    return manifest

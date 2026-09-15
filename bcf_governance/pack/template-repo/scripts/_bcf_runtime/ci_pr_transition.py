"""One-shot authenticated equivalence for the BCF 2.0 PR topology transition."""

from __future__ import annotations

import hashlib
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any
from xml.etree import ElementTree
import zipfile

from jsonschema import Draft202012Validator
import yaml

from .ci_github_api import GitHubAPI, GitHubAPIError
from .ci_github_identity import GitHubControllerError, MainIdentity, positive_int
from .github_protection import load_protection_bytes


TRANSITION_PATH = "governance/pr-transition.yml"
TRANSITION_SCHEMA = Path("schemas/pr-transition.schema.json")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_MAX_ARCHIVE_BYTES = 104_857_600
_MAX_EXPANDED_BYTES = 268_435_456
_EXPECTED_MAPPING = (
    ("governed-yaml-front-door-validity", "successor_claim", "governance-contracts-valid", "preflight_satisfied_claims"),
    ("canonical-package-projection-and-schema-parity", "successor_test", "test", "tests.test_pack_sync::test_complete_pack_manifest_check"),
    ("python-syntax-across-governed-roots", "successor_claim", "source-syntax-format", "preflight_satisfied_claims"),
    ("exact-main-controller-bundle-construction", "trusted_main_rotation", None, "governance-pack exact-main build_controller path"),
)


class TransitionRejected(GitHubControllerError):
    """Raised when an eligible successor fails trusted equivalence reconstruction."""


def load_transition_bytes(content: bytes, *, schema_path: Path) -> dict[str, Any]:
    """Decode the closed transition contract using trusted packaged schema bytes."""

    try:
        value = yaml.safe_load(content.decode("utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError, OSError, json.JSONDecodeError) as exc:
        raise GitHubControllerError(f"cannot load PR transition contract: {exc}") from exc
    if not isinstance(value, dict):
        raise GitHubControllerError("PR transition contract must be a mapping")
    errors = sorted(
        Draft202012Validator(schema).iter_errors(value),
        key=lambda item: list(item.absolute_path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(item) for item in error.absolute_path) or "<root>"
        raise GitHubControllerError(
            f"PR transition schema violation at {location}: {error.message}"
        )
    mapping = tuple(
        (item["old_fact"], item["disposition"], item["claim"], item["evidence"])
        for item in value["assurance_mapping"]
    )
    if mapping != _EXPECTED_MAPPING:
        raise GitHubControllerError("PR transition assurance mapping is not exact and complete")
    return value


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _matches_files(
    api: GitHubAPI,
    *,
    repository: str,
    ref: str,
    files: dict[str, Any],
    missing_is_mismatch: bool,
) -> bool:
    for expected in files.values():
        try:
            content = api.content(repository, expected["path"], ref=ref).content
        except GitHubAPIError:
            if missing_is_mismatch:
                return False
            raise
        if _sha256(content) != expected["sha256"]:
            return False
    return True


def _producer_contracts(protection: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    return tuple(protection["pr_certification"]["producer_workflows"])


def transition_is_applicable(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    protection: dict[str, Any],
    head_sha: str,
    head_branch: str,
    package_state: dict[str, Any],
    schema_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Return the trusted contract and successor protection only for its one target."""

    if package_state != {"id": "package", "state": "pending", "reason": "not_started"}:
        return None
    contract_content = api.content(repository, TRANSITION_PATH, ref=main.checkout_sha)
    contract = load_transition_bytes(
        contract_content.content, schema_path=schema_root / TRANSITION_SCHEMA
    )
    repository_contract = contract["repository"]
    if repository_contract != {
        "full_name": repository,
        "numeric_id": int(main.repository_id),
        "base_branch": main.default_branch,
    }:
        raise GitHubControllerError("PR transition repository identity is not exact")
    activation = contract["activation"]
    if head_branch != activation["successor_head_branch"]:
        return None
    if not _matches_files(
        api,
        repository=repository,
        ref=main.checkout_sha,
        files=activation["current_topology"],
        missing_is_mismatch=False,
    ):
        raise GitHubControllerError("current PR topology does not match transition authority")
    if _producer_contracts(protection) != (
        {"id": "governance", "path": activation["successor_producer"]["path"], "required_job_names": ["Verify exact-tree governance evidence"]},
        activation["retired_producer"],
    ):
        raise GitHubControllerError("current producer topology does not match transition authority")
    if not _matches_files(
        api,
        repository=repository,
        ref=head_sha,
        files=activation["successor_topology"],
        missing_is_mismatch=True,
    ):
        return None
    successor_protection_content = api.content(
        repository, activation["successor_topology"]["protection"]["path"], ref=head_sha
    )
    successor_protection = load_protection_bytes(
        successor_protection_content.content,
        schema_path=schema_root / "schemas/github-protection.schema.json",
    )
    if _producer_contracts(successor_protection) != (
        {
            "id": activation["successor_producer"]["id"],
            "path": activation["successor_producer"]["path"],
            "required_job_names": ["Verify exact-tree governance evidence"],
        },
    ):
        return None
    return contract, successor_protection


def _artifact_metadata(
    artifact: dict[str, Any],
    *,
    run_id: str,
    run_attempt: int,
    repository_id: str,
    head_sha: str,
    head_branch: str,
) -> tuple[str, str]:
    artifact_id = str(positive_int(artifact.get("id"), field="transition artifact ID"))
    digest = str(artifact.get("digest", ""))
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise TransitionRejected("transition artifact provider digest is invalid")
    workflow_run = artifact.get("workflow_run")
    if not isinstance(workflow_run, dict) or workflow_run != {
        "id": int(run_id),
        "repository_id": int(repository_id),
        "head_repository_id": int(repository_id),
        "head_branch": head_branch,
        "head_sha": head_sha,
    }:
        raise TransitionRejected("transition artifact provider subject is not exact")
    if artifact.get("expired") is not False:
        raise TransitionRejected("transition artifact is expired")
    return artifact_id, digest


def _archive_files(raw: bytes) -> dict[str, bytes]:
    if len(raw) > _MAX_ARCHIVE_BYTES:
        raise TransitionRejected("transition artifact exceeds its closed size limit")
    files: dict[str, bytes] = {}
    expanded = 0
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            members = archive.infolist()
            if len(members) > 10_000:
                raise TransitionRejected("transition artifact inventory is oversized")
            for member in members:
                path = PurePosixPath(member.filename)
                if member.is_dir():
                    continue
                if path.is_absolute() or ".." in path.parts or member.flag_bits & 0x1:
                    raise TransitionRejected("transition artifact contains an unsafe member")
                if (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise TransitionRejected("transition artifact contains a symlink")
                name = path.as_posix()
                if name in files:
                    raise TransitionRejected("transition artifact contains duplicate members")
                expanded += member.file_size
                if expanded > _MAX_EXPANDED_BYTES:
                    raise TransitionRejected("transition artifact expansion is oversized")
                files[name] = archive.read(member)
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        raise TransitionRejected("transition artifact is not a valid closed ZIP") from exc
    return files


def _one_suffix(files: dict[str, bytes], suffix: str) -> tuple[str, bytes]:
    matches = [(name, raw) for name, raw in files.items() if name.endswith(suffix)]
    if len(matches) != 1:
        raise TransitionRejected(f"transition evidence inventory is not exact for {suffix}")
    return matches[0]


def _json(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TransitionRejected(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise TransitionRejected(f"{label} must be an object")
    return value


def _verify_session(
    session: dict[str, Any],
    *,
    successor: dict[str, Any],
    repository: str,
    repository_id: str,
    run_id: str,
    run_attempt: int,
    evidence_commit: str,
    head_tree: str,
) -> str:
    producer = session.get("producer")
    if session.get("schema_version") != successor["session_schema_version"]:
        raise TransitionRejected("legacy transition evidence is not admitted")
    if session.get("profile") != successor["profile"] or session.get(
        "profile_contract_version"
    ) != successor["profile_contract_version"]:
        raise TransitionRejected("transition evidence profile identity is not exact")
    if session.get("subject") != {"commit_sha": evidence_commit, "tree_sha": head_tree}:
        raise TransitionRejected("transition evidence session subject is not exact")
    if session.get("expected_gate_inventory") != successor["required_gate_inventory"] or session.get(
        "expected_producer_inventory"
    ) != ["evidence"]:
        raise TransitionRejected("transition evidence gate inventory is not exact")
    if producer != {
        "kind": "workflow",
        "producer_id": "preflight",
        "provider": "github-actions",
        "repository": repository,
        "repository_id": repository_id,
        "run_attempt": str(run_attempt),
        "run_id": run_id,
    }:
        raise TransitionRejected("transition evidence session producer is not exact")
    required = {"governance-contracts-valid", "source-syntax-format"}
    if not isinstance(session.get("preflight_satisfied_claims"), list) or not required.issubset(
        set(session["preflight_satisfied_claims"])
    ):
        raise TransitionRejected("transition preflight claim mapping is incomplete")
    session_id = str(session.get("session_id", ""))
    if not re.fullmatch(r"[a-f0-9]{32,}", session_id):
        raise TransitionRejected("transition evidence session identity is invalid")
    return session_id


def _verify_truth(
    report: dict[str, Any],
    *,
    successor: dict[str, Any],
    repository: str,
    run_id: str,
    run_attempt: int,
    evidence_commit: str,
    head_tree: str,
) -> None:
    expected_ref = f"github-actions://{repository}/runs/{run_id}/attempts/{run_attempt}/bcf-governance-truth"
    if (
        report.get("schema_version") != successor["truth_schema_version"]
        or report.get("subject")
        != {"commit_sha": evidence_commit, "tracked_clean": True, "tree_sha": head_tree, "untracked_clean": True}
        or report.get("evaluation_mode") != "pr"
        or report.get("status") != "pass"
        or report.get("merge_eligibility") != "eligible"
        or report.get("durable_ref") != expected_ref
        or report.get("issues") != []
    ):
        raise TransitionRejected("transition truth report is not exact and successful")
    claims = report.get("claims")
    if not isinstance(claims, dict):
        raise TransitionRejected("transition truth claims are missing")
    expected = {
        "security_review_complete": "governance-contracts-valid",
        "required_suites_green": "source-syntax-format",
    }
    for claim_id, evidence_id in expected.items():
        claim = claims.get(claim_id)
        refs = claim.get("evidence_refs") if isinstance(claim, dict) else None
        if claim is None or claim.get("effective_state") != "verified" or not isinstance(refs, list):
            raise TransitionRejected("transition truth claim mapping failed")
        if not any(
            isinstance(ref, dict)
            and ref.get("evidence_id") == f"preflight:{evidence_id}"
            and ref.get("result") == "verified"
            and ref.get("source") == "evidence-session-v2"
            for ref in refs
        ):
            raise TransitionRejected("transition truth omitted a mapped preflight claim")


def _verify_test_receipt(
    receipt: dict[str, Any],
    *,
    session_raw: bytes,
    junit_raw: bytes,
    repository: str,
    pr_number: int,
    run_id: str,
    run_attempt: int,
    evidence_commit: str,
    head_tree: str,
    required_node: str,
) -> None:
    subject = receipt.get("subject")
    invocation = receipt.get("invocation")
    workflow = invocation.get("workflow") if isinstance(invocation, dict) else None
    if (
        receipt.get("schema_version") != "3.0"
        or receipt.get("gate_id") != "test"
        or receipt.get("result") != "passed"
        or not isinstance(receipt.get("claims"), list)
        or "test" not in receipt["claims"]
        or receipt.get("producer") != {"id": repository.split("/", 1)[0], "kind": "workflow"}
        or subject
        != {
            "binding": "exact_tree",
            "commit_sha": evidence_commit,
            "execution_tree_sha": head_tree,
            "status_porcelain_sha256": _EMPTY_SHA256,
            "tracked_clean": True,
            "tree_sha": head_tree,
            "untracked_clean": True,
        }
        or workflow
        != {
            "job": "evidence",
            "matrix": {"gate": "test"},
            "path": f"{repository}/.github/workflows/governance.yml@refs/pull/{pr_number}/merge",
            "provider": "github-actions",
            "run_attempt": str(run_attempt),
            "run_id": run_id,
        }
    ):
        raise TransitionRejected("transition test receipt identity or result is not exact")
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, list):
        raise TransitionRejected("transition test receipt artifact inventory is missing")
    expected_digests = {
        ("evidence-session.json", "application/vnd.bcf.evidence-session+json"): _sha256(session_raw),
        ("test.junit.xml", "application/junit+xml"): _sha256(junit_raw),
    }
    for (path, media_type), digest in expected_digests.items():
        matches = [
            item
            for item in artifacts
            if isinstance(item, dict)
            and item.get("path") == path
            and item.get("media_type") == media_type
            and item.get("sha256") == digest
        ]
        if len(matches) != 1:
            raise TransitionRejected("transition test receipt does not hash-bind required evidence")
    try:
        root = ElementTree.fromstring(junit_raw)
    except ElementTree.ParseError as exc:
        raise TransitionRejected("transition JUnit evidence is invalid") from exc
    classname, name = required_node.split("::", 1)
    nodes = [
        item
        for item in root.iter("testcase")
        if item.get("classname") == classname and item.get("name") == name
    ]
    if len(nodes) != 1 or any(
        nodes[0].find(kind) is not None for kind in ("failure", "error", "skipped")
    ):
        raise TransitionRejected("complete pack-manifest test evidence is absent or failed")


def verify_transition_equivalence(
    api: GitHubAPI,
    *,
    repository: str,
    main: MainIdentity,
    contract: dict[str, Any],
    pr_number: int,
    head_sha: str,
    head_tree: str,
    head_branch: str,
    governance_state: dict[str, Any],
) -> dict[str, Any]:
    """Reconstruct one non-replayable package equivalence from provider evidence."""

    successor = contract["activation"]["successor_producer"]
    if governance_state.get("state") != "successful":
        raise TransitionRejected("successor governance producer is not successful")
    run_id = str(governance_state.get("run_id", ""))
    run_attempt = positive_int(
        governance_state.get("run_attempt"), field="transition governance run attempt"
    )
    run = api.run(repository, run_id)
    if (
        str(run.get("head_sha")) != head_sha
        or run.get("event") != "pull_request"
        or _pr_number(run) != pr_number
        or positive_int(run.get("run_attempt"), field="transition run attempt") != run_attempt
    ):
        raise TransitionRejected("transition governance run cannot be replayed across subjects")
    jobs = api.jobs(repository, run_id, attempt=run_attempt)
    expected_jobs = set(successor["required_job_names"])
    if (
        len(jobs) != len(expected_jobs)
        or {str(job.get("name")) for job in jobs} != expected_jobs
        or any(job.get("status") != "completed" or job.get("conclusion") != "success" for job in jobs)
    ):
        raise TransitionRejected("successor governance job inventory is not exact and green")
    expected_names = {
        f"bcf-session-{run_id}-{run_attempt}",
        f"bcf-governance-truth-{run_id}-{run_attempt}",
        *(f"bcf-evidence-{run_id}-{run_attempt}-shard-{index}" for index in range(successor["artifact_shards"])),
    }
    artifacts = api.artifacts(repository, run_id)
    by_name = {str(item.get("name")): item for item in artifacts}
    if len(artifacts) != len(expected_names) or set(by_name) != expected_names:
        raise TransitionRejected("successor governance artifact inventory is not exact")
    archives: dict[str, dict[str, bytes]] = {}
    identities: list[dict[str, Any]] = []
    for name in sorted(expected_names):
        artifact = by_name[name]
        artifact_id, provider_digest = _artifact_metadata(
            artifact,
            run_id=run_id,
            run_attempt=run_attempt,
            repository_id=main.repository_id,
            head_sha=head_sha,
            head_branch=head_branch,
        )
        raw = api.artifact_bytes(repository, artifact_id, maximum_bytes=_MAX_ARCHIVE_BYTES)
        if f"sha256:{_sha256(raw)}" != provider_digest:
            raise TransitionRejected("transition artifact bytes do not match provider digest")
        archives[name] = _archive_files(raw)
        identities.append({"id": artifact_id, "name": name, "provider_digest": provider_digest})
    session_name = f"bcf-session-{run_id}-{run_attempt}"
    _, session_raw = _one_suffix(archives[session_name], "/evidence-session.json")
    session = _json(session_raw, label="transition evidence session")
    evidence_commit = str(session.get("subject", {}).get("commit_sha", ""))
    evidence_commit_record = api.commit(repository, evidence_commit)
    evidence_tree = evidence_commit_record.get("tree")
    if not isinstance(evidence_tree, dict) or evidence_tree.get("sha") != head_tree:
        raise TransitionRejected("transition execution commit is not tree-equivalent to candidate")
    session_id = _verify_session(
        session,
        successor=successor,
        repository=repository,
        repository_id=main.repository_id,
        run_id=run_id,
        run_attempt=run_attempt,
        evidence_commit=evidence_commit,
        head_tree=head_tree,
    )
    truth_name = f"bcf-governance-truth-{run_id}-{run_attempt}"
    truth_files = archives[truth_name]
    if set(truth_files) != {"truth-report.json"}:
        raise TransitionRejected("transition truth artifact inventory is not exact")
    _verify_truth(
        _json(truth_files["truth-report.json"], label="transition truth report"),
        successor=successor,
        repository=repository,
        run_id=run_id,
        run_attempt=run_attempt,
        evidence_commit=evidence_commit,
        head_tree=head_tree,
    )
    shard_files: dict[str, bytes] = {}
    for index in range(successor["artifact_shards"]):
        for path, raw in archives[f"bcf-evidence-{run_id}-{run_attempt}-shard-{index}"].items():
            if path in shard_files:
                if path.endswith("/evidence-session.json") and shard_files[path] == raw:
                    continue
                raise TransitionRejected("transition evidence shards contain duplicate members")
            shard_files[path] = raw
    _, receipt_raw = _one_suffix(shard_files, f"{session_id}/test/test.evidence.json")
    _, junit_raw = _one_suffix(shard_files, f"{session_id}/test/test.junit.xml")
    required_node = contract["assurance_mapping"][1]["evidence"]
    _verify_test_receipt(
        _json(receipt_raw, label="transition test receipt"),
        session_raw=session_raw,
        junit_raw=junit_raw,
        repository=repository,
        pr_number=pr_number,
        run_id=run_id,
        run_attempt=run_attempt,
        evidence_commit=evidence_commit,
        head_tree=head_tree,
        required_node=required_node,
    )
    return {
        "id": "package",
        "state": "successful",
        "reason": "authenticated_bcf2_transition_equivalence",
        "run_id": run_id,
        "run_attempt": run_attempt,
        "transition": {
            "contract_definition_commit": main.checkout_sha,
            "pull_request": pr_number,
            "subject": {"commit_sha": head_sha, "tree_sha": head_tree, "branch": head_branch},
            "session_id": session_id,
            "artifacts": identities,
            "retired_producer": contract["activation"]["retired_producer"],
        },
    }


def _pr_number(run: dict[str, Any]) -> int:
    values = run.get("pull_requests")
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise TransitionRejected("transition run must identify exactly one pull request")
    return positive_int(values[0].get("number"), field="transition pull request number")

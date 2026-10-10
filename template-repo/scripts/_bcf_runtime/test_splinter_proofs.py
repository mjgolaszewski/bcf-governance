"""Exact, acceleration-only proof custody for deterministic test splinters."""

from __future__ import annotations

import hashlib
from io import BytesIO
from importlib import metadata
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any, Mapping
import zipfile

from .evidence_scheduling import validate_test_splinter_plan


KIND = "bcf.test-splinter-proof.v1"
_SHA256 = re.compile(r"[a-f0-9]{64}")
_PROOF_MEMBER = re.compile(r"(?:^|/)(splinter-[0-9]+)\.(proof\.json|junit\.xml)$")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repository_proof_members(
    repo_root: Path, proof_root: Path, splinter_id: str
) -> dict[str, str]:
    """Project proof members as exact repository-relative paths."""

    try:
        relative_root = proof_root.resolve().relative_to(repo_root.resolve())
    except ValueError as exc:
        raise ValueError("test splinter proof root escapes the repository") from exc
    if not re.fullmatch(r"splinter-[0-9]+", splinter_id):
        raise ValueError("test splinter proof member identity is invalid")
    return {
        "manifest": (relative_root / f"{splinter_id}.proof.json").as_posix(),
        "junit": (relative_root / f"{splinter_id}.junit.xml").as_posix(),
    }


def toolchain_sha256(repo_root: Path, python_executable: Path) -> str:
    """Bind the interpreter and locked test dependencies without storing their bytes."""

    inputs = {
        "python_executable_sha256": _file_sha256(python_executable.resolve()),
        "python_version": os.sys.version,
        "pytest_version": metadata.version("pytest"),
        "requirements_governance_sha256": _file_sha256(
            repo_root / "requirements-governance.txt"
        ),
    }
    return hashlib.sha256(_canonical(inputs)).hexdigest()


def applicability_identity(
    plan: Mapping[str, Any], splinter: Mapping[str, Any], *, toolchain_sha256: str
) -> dict[str, Any]:
    """Project the exact reusable proposition, excluding only attempt-local session ID."""

    validate_test_splinter_plan(plan)
    identity = plan["identity"]
    if not isinstance(identity, Mapping) or not _SHA256.fullmatch(toolchain_sha256):
        raise ValueError("test splinter applicability identity is invalid")
    if splinter not in plan["splinters"]:
        raise ValueError("test splinter is not owned by the partition plan")
    stable_plan = {
        key: value
        for key, value in plan.items()
        if key != "partition_sha256"
    }
    stable_plan["identity"] = {
        key: value for key, value in identity.items() if key != "session"
    }
    return {
        "partition_sha256": hashlib.sha256(_canonical(stable_plan)).hexdigest(),
        "splinter_id": splinter["id"],
        "nodes": list(splinter["nodes"]),
        "selectors": list(splinter["selectors"]),
        "toolchain_sha256": toolchain_sha256,
    }


def load_test_splinter_proof(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("test splinter proof is unreadable") from exc
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "kind", "applicability", "source", "result", "proof_sha256"
    }:
        raise ValueError("test splinter proof contract is not closed")
    unsigned = {key: value[key] for key in value if key != "proof_sha256"}
    if (
        value["schema_version"] != "1.0"
        or value["kind"] != KIND
        or value["proof_sha256"] != hashlib.sha256(_canonical(unsigned)).hexdigest()
    ):
        raise ValueError("test splinter proof digest is invalid")
    applicability = value["applicability"]
    source = value["source"]
    result = value["result"]
    if (
        not isinstance(applicability, dict)
        or set(applicability) != {
            "partition_sha256", "splinter_id", "nodes", "selectors", "toolchain_sha256"
        }
        or not isinstance(source, dict)
        or set(source) != {
            "repository", "repository_id", "run_id", "run_attempt", "job", "shard",
            "session",
        }
        or not isinstance(result, dict)
        or set(result) != {
            "returncode", "junit_file", "junit_sha256", "node_ids",
            "execution_state", "worktree_removed",
        }
        or any(
            not _SHA256.fullmatch(str(applicability.get(key, "")))
            for key in ("partition_sha256", "toolchain_sha256")
        )
        or result.get("returncode") != 0
        or result.get("worktree_removed") is not True
        or not isinstance(result.get("node_ids"), list)
        or not _SHA256.fullmatch(str(result.get("junit_sha256", "")))
        or not isinstance(result.get("junit_file"), str)
        or Path(result["junit_file"]).name != result["junit_file"]
    ):
        raise ValueError("test splinter proof fields are invalid")
    state = result.get("execution_state")
    if state is not None and (
        not isinstance(state, dict)
        or state.get("retired") is not True
        or state.get("removal_verified") is not True
    ):
        raise ValueError("test splinter proof state was not retired")
    return value


def write_successful_proof(
    destination: Path,
    *,
    plan: Mapping[str, Any],
    splinter: Mapping[str, Any],
    toolchain_sha256: str,
    junit: Path,
    observed_nodes: list[str],
    execution_state: dict[str, Any] | None,
    worktree_removed: bool,
    source: Mapping[str, str],
) -> tuple[Path, Path]:
    """Persist one successful result before aggregate fan-in."""

    expected_source = {
        "repository", "repository_id", "run_id", "run_attempt", "job", "shard",
        "session",
    }
    if (
        set(source) != expected_source
        or any(not isinstance(source[key], str) or not source[key] for key in expected_source)
        or sorted(observed_nodes) != sorted(str(value) for value in splinter["nodes"])
        or not junit.is_file()
        or not worktree_removed
    ):
        raise ValueError("successful test splinter proof inputs are incomplete")
    destination.mkdir(parents=True, exist_ok=True)
    splinter_id = str(splinter["id"])
    junit_target = destination / f"{splinter_id}.junit.xml"
    shutil.copyfile(junit, junit_target)
    unsigned = {
        "schema_version": "1.0",
        "kind": KIND,
        "applicability": applicability_identity(
            plan, splinter, toolchain_sha256=toolchain_sha256
        ),
        "source": dict(source),
        "result": {
            "returncode": 0,
            "junit_file": junit_target.name,
            "junit_sha256": _file_sha256(junit_target),
            "node_ids": sorted(observed_nodes),
            "execution_state": execution_state,
            "worktree_removed": True,
        },
    }
    proof = {**unsigned, "proof_sha256": hashlib.sha256(_canonical(unsigned)).hexdigest()}
    manifest = destination / f"{splinter_id}.proof.json"
    manifest.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    load_test_splinter_proof(manifest)
    return manifest, junit_target


def select_applicable_proof(
    roots: list[Path],
    *,
    plan: Mapping[str, Any],
    splinter: Mapping[str, Any],
    toolchain_sha256: str,
    current: Mapping[str, str],
) -> tuple[dict[str, Any] | None, Path | None, str]:
    """Select the newest unique exact prior-attempt proof or require execution."""

    expected = applicability_identity(plan, splinter, toolchain_sha256=toolchain_sha256)
    candidates: list[tuple[int, dict[str, Any], Path]] = []
    malformed = False
    observed = False
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob(f"{splinter['id']}.proof.json")):
            observed = True
            try:
                proof = load_test_splinter_proof(path)
                source = proof["source"]
                attempt = int(source["run_attempt"])
                junit = path.with_name(str(proof["result"]["junit_file"]))
                if (
                    proof["applicability"] == expected
                    and source["repository"] == current["repository"]
                    and source["repository_id"] == current["repository_id"]
                    and source["run_id"] == current["run_id"]
                    and source["job"] == current["job"]
                    and source["shard"] == current["shard"]
                    and 0 < attempt < int(current["run_attempt"])
                    and junit.is_file()
                    and _file_sha256(junit) == proof["result"]["junit_sha256"]
                ):
                    candidates.append((attempt, proof, junit))
            except (OSError, TypeError, ValueError):
                malformed = True
    if not candidates:
        return None, None, (
            "prior_proof_malformed" if malformed
            else "prior_proof_inapplicable" if observed
            else "prior_proof_absent"
        )
    newest = max(value[0] for value in candidates)
    selected = [value for value in candidates if value[0] == newest]
    identities = {value[1]["proof_sha256"] for value in selected}
    if len(selected) != 1 or len(identities) != 1:
        return None, None, "prior_proof_ambiguous"
    return selected[0][1], selected[0][2], "exact_prior_proof"


def materialize_prior_provider_proofs(
    api: Any,
    destination: Path,
    *,
    repository: str,
    repository_id: str,
    head_sha: str,
    run_id: str,
    current_attempt: int,
    job: str,
    shard: int,
) -> dict[str, Any]:
    """Cold-resolve exact earlier-attempt proof members from the same workflow run."""

    if current_attempt < 2:
        return {"status": "first_attempt", "artifacts": []}
    prefix = f"bcf-evidence-{run_id}-"
    suffix = f"-shard-{shard}"
    selected: dict[int, dict[str, Any]] = {}
    for artifact in api.artifacts(repository, run_id):
        name = artifact.get("name")
        if not isinstance(name, str) or not name.startswith(prefix) or not name.endswith(suffix):
            continue
        attempt_text = name[len(prefix) : -len(suffix)]
        if not attempt_text.isdigit():
            continue
        attempt = int(attempt_text)
        workflow = artifact.get("workflow_run")
        if (
            not 0 < attempt < current_attempt
            or artifact.get("expired") is not False
            or not isinstance(workflow, dict)
            or workflow.get("id") != int(run_id)
            or str(workflow.get("repository_id")) != repository_id
            or str(workflow.get("head_repository_id")) != repository_id
            or workflow.get("head_sha") != head_sha
        ):
            continue
        if attempt in selected:
            raise ValueError("prior test splinter artifact identity is ambiguous")
        selected[attempt] = artifact
    observations: list[dict[str, Any]] = []
    for attempt, artifact in sorted(selected.items()):
        jobs = [
            value for value in api.jobs(repository, run_id, attempt=attempt)
            if value.get("name") == f"Evidence / Evidence shard {shard}"
        ]
        if (
            len(jobs) != 1
            or jobs[0].get("status") != "completed"
            or jobs[0].get("conclusion") not in {"success", "failure"}
            or jobs[0].get("head_sha") != head_sha
        ):
            raise ValueError("prior test splinter producer job is not exact and terminal")
        raw = api.artifact_bytes(repository, artifact["id"], maximum_bytes=104_857_600)
        expected_digest = artifact.get("digest")
        if expected_digest != f"sha256:{hashlib.sha256(raw).hexdigest()}":
            raise ValueError("prior test splinter artifact digest differs")
        target = destination / f"attempt-{attempt}"
        target.mkdir(parents=True, exist_ok=True)
        extracted: set[str] = set()
        try:
            with zipfile.ZipFile(BytesIO(raw)) as archive:
                for member in archive.infolist():
                    match = _PROOF_MEMBER.search(member.filename)
                    if (
                        member.is_dir()
                        or match is None
                        or member.file_size > 20_000_000
                        or member.compress_size > 20_000_000
                    ):
                        continue
                    name = f"{match.group(1)}.{match.group(2)}"
                    if name in extracted:
                        raise ValueError("prior test splinter artifact members are ambiguous")
                    (target / name).write_bytes(archive.read(member))
                    extracted.add(name)
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise ValueError("prior test splinter artifact is unreadable") from exc
        for manifest in target.glob("splinter-*.proof.json"):
            proof = load_test_splinter_proof(manifest)
            source = proof["source"]
            if (
                source["repository"] != repository
                or source["repository_id"] != repository_id
                or source["run_id"] != run_id
                or source["run_attempt"] != str(attempt)
                or source["job"] != job
                or source["shard"] != str(shard)
            ):
                raise ValueError("prior test splinter proof provider identity differs")
        observations.append(
            {
                "artifact_id": str(artifact["id"]),
                "attempt": attempt,
                "job_id": str(jobs[0].get("id")),
                "provider_digest": expected_digest,
                "proof_members": sorted(extracted),
            }
        )
    return {
        "status": "materialized" if observations else "prior_artifact_absent",
        "artifacts": observations,
    }

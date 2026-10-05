"""Content-addressed, acceleration-only local prospective proof bundles."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from .ci_graph_execution import resolve_local_job_environment
from .evidence_scheduling import receipt_duration_ms
from .governance_evidence import capture_gate


MANIFEST_NAME = "proof-bundle.json"
PAYLOAD_ROOT = "evidence"


class LocalProofBundleError(ValueError):
    """Raised when local proof custody is unsafe or internally inconsistent."""


def capture_producers(
    repo_root: Path,
    *,
    python_executable: Path,
    session_manifest: Path,
    session_root: Path,
    producers: tuple[str, ...],
    producer_environments: dict[str, dict[str, str]],
) -> list[dict[str, Any]]:
    """Execute the exact planned producer inventory and close each receipt."""

    observations: list[dict[str, Any]] = []
    for producer in producers:
        environment = resolve_local_job_environment(
            producer_environments[producer], repo_root
        )
        receipt = capture_gate(
            repo_root,
            producer,
            session_root / producer,
            python_executable=python_executable,
            session_manifest=session_manifest,
            job_environment=environment,
        )
        if not receipt.is_file():
            raise LocalProofBundleError(
                f"local evidence producer {producer} emitted no receipt"
            )
        payload = json.loads(receipt.read_text(encoding="utf-8"))
        if payload.get("result") != "passed":
            producer_observations = payload.get("observations")
            exit_code = (
                producer_observations.get("exit_code")
                if isinstance(producer_observations, dict)
                else "unknown"
            )
            diagnostics: list[str] = []
            for suffix in ("stderr", "stdout"):
                path = receipt.parent / f"{producer}.{suffix}.txt"
                if path.is_file():
                    value = path.read_text(encoding="utf-8", errors="replace").strip()
                    if value:
                        diagnostics.append(f"{suffix}: {value[-20000:]}")
            for probe in payload.get("behavioral_probes") or ():
                if not isinstance(probe, dict):
                    continue
                observation = probe.get("oracle_observation")
                if isinstance(observation, dict) and observation.get("satisfied") is True:
                    continue
                control_id = str(probe.get("id", "unknown"))
                reason = (
                    str(observation.get("reason", "oracle_not_satisfied"))
                    if isinstance(observation, dict)
                    else "oracle_observation_missing"
                )
                diagnostics.append(f"behavioral_probe {control_id}: {reason}")
                raw_artifacts = probe.get("raw_artifacts")
                if not isinstance(raw_artifacts, dict):
                    continue
                for stream in ("stderr", "stdout"):
                    relative = raw_artifacts.get(stream)
                    path = Path(str(relative)) if isinstance(relative, str) else None
                    if (
                        path is None
                        or path.is_absolute()
                        or ".." in path.parts
                        or not (receipt.parent / path).is_file()
                    ):
                        continue
                    value = (receipt.parent / path).read_text(
                        encoding="utf-8", errors="replace"
                    ).strip()
                    if value:
                        diagnostics.append(
                            f"behavioral_probe {control_id} {stream}: {value[-20000:]}"
                        )
            raise LocalProofBundleError(
                f"local evidence producer {producer} failed with exit {exit_code}"
                + (": " + " | ".join(diagnostics) if diagnostics else "")
            )
        duration = receipt_duration_ms(payload)
        if duration is None:
            raise LocalProofBundleError(
                f"local evidence producer {producer} emitted no valid duration"
            )
        observations.append(
            {
                "producer": producer,
                "duration_ms": duration,
                "claim_count": len(payload.get("claims") or ()),
                "control_count": len(payload.get("behavioral_probes") or ()),
            }
        )
    return observations


def cached_producer_observations(
    session_root: Path, producers: tuple[str, ...]
) -> list[dict[str, Any]]:
    """Recover telemetry only after the exact cached receipt inventory is closed."""

    observations: list[dict[str, Any]] = []
    for producer in producers:
        receipt = session_root / producer / f"{producer}.evidence.json"
        try:
            payload = json.loads(receipt.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LocalProofBundleError(
                f"cached local evidence producer {producer} is unreadable"
            ) from exc
        duration = receipt_duration_ms(payload)
        if payload.get("result") != "passed" or duration is None:
            raise LocalProofBundleError(
                f"cached local evidence producer {producer} is not a passed exact proof"
            )
        observations.append(
            {
                "producer": producer,
                "duration_ms": duration,
                "claim_count": len(payload.get("claims") or ()),
                "control_count": len(payload.get("behavioral_probes") or ()),
            }
        )
    return observations


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_files(root: Path) -> tuple[Path, ...]:
    if root.is_symlink() or not root.is_dir():
        raise LocalProofBundleError("proof bundle payload must be a nonsymlink directory")
    files: list[Path] = []
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in sorted(directories):
            if (current_path / name).is_symlink():
                raise LocalProofBundleError("proof bundle payload contains a symlink")
        for name in sorted(names):
            path = current_path / name
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise LocalProofBundleError("proof bundle payload contains a special file")
            files.append(path)
    return tuple(sorted(files))


def proof_identity(
    *,
    repository: str,
    base_commit: str,
    base_tree: str,
    candidate_commit: str,
    candidate_tree: str,
    evaluation_mode: str,
    evaluation_target: str | None,
    verification_plan: Mapping[str, Any],
    controller: Mapping[str, Any],
    policy: Mapping[str, Any],
    toolchain: Mapping[str, Any],
    python_executable: Path,
) -> dict[str, Any]:
    """Bind every mechanically knowable input to one local proof proposition."""

    executable = python_executable.resolve()
    if executable.is_symlink() or not executable.is_file():
        raise LocalProofBundleError("proof toolchain executable is missing or symlinked")
    version = subprocess.run(
        [str(executable), "--version"], capture_output=True, text=True, check=False
    )
    if version.returncode:
        raise LocalProofBundleError("proof toolchain version is unreadable")
    return {
        "repository": repository,
        "base": {"commit_sha": base_commit, "tree_sha": base_tree},
        "candidate": {"commit_sha": candidate_commit, "tree_sha": candidate_tree},
        "evaluation": {"mode": evaluation_mode, "target": evaluation_target},
        "verification_plan_sha256": hashlib.sha256(
            _canonical(dict(verification_plan))
        ).hexdigest(),
        "controller": dict(controller),
        "policy": dict(policy),
        "toolchain": {
            "admission": dict(toolchain),
            "implementation": version.stdout.strip() or version.stderr.strip(),
            "executable_sha256": _sha256_file(executable),
        },
        "producer_authority": "local_non_authoritative",
        "freshness": "exact_candidate_subject",
    }


def identity_digest(identity: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(dict(identity))).hexdigest()


def _cache_root(repo_root: Path) -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode or not result.stdout.strip():
        raise LocalProofBundleError("proof cache requires an authenticated Git repository")
    common = Path(result.stdout.strip()).resolve()
    root = common / "bcf" / "proof-bundles"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or not root.is_dir():
        raise LocalProofBundleError("proof cache root is unsafe")
    return root


def _manifest(repo_root: Path, bundle: Path) -> dict[str, Any]:
    manifest_path = bundle / MANIFEST_NAME
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        schema = json.loads(
            (repo_root / "schemas/proof-bundle.schema.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalProofBundleError("proof bundle manifest is unreadable") from exc
    errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=str)
    if errors:
        raise LocalProofBundleError(f"proof bundle schema violation: {errors[0].message}")
    return payload


def _inventory(payload_root: Path) -> list[dict[str, Any]]:
    return [
        {
            "path": path.relative_to(payload_root).as_posix(),
            "size": path.stat().st_size,
            "sha256": _sha256_file(path),
        }
        for path in _regular_files(payload_root)
    ]


def _verify(repo_root: Path, bundle: Path, identity: Mapping[str, Any]) -> dict[str, Any]:
    if bundle.is_symlink() or not bundle.is_dir():
        raise LocalProofBundleError("proof bundle is missing or symlinked")
    manifest = _manifest(repo_root, bundle)
    expected_digest = identity_digest(identity)
    if manifest["identity"] != dict(identity) or manifest["identity_sha256"] != expected_digest:
        raise LocalProofBundleError("proof bundle identity differs")
    actual = _inventory(bundle / PAYLOAD_ROOT)
    if actual != manifest["files"]:
        raise LocalProofBundleError("proof bundle file inventory differs")
    digest_payload = {key: value for key, value in manifest.items() if key != "bundle_sha256"}
    if manifest["bundle_sha256"] != hashlib.sha256(_canonical(digest_payload)).hexdigest():
        raise LocalProofBundleError("proof bundle digest differs")
    return manifest


def restore_proof_bundle(
    repo_root: Path, *, identity: Mapping[str, Any], destination: Path
) -> dict[str, Any] | None:
    """Materialize an exact cached proof, or return None when none exists."""

    cache = _cache_root(repo_root) / identity_digest(identity)
    if not cache.exists():
        return None
    try:
        manifest = _verify(repo_root, cache, identity)
    except LocalProofBundleError:
        if cache.resolve().parent != _cache_root(repo_root).resolve():
            raise
        shutil.rmtree(cache)
        return None
    if destination.exists() or destination.is_symlink():
        raise LocalProofBundleError("proof materialization target already exists")
    shutil.copytree(cache / PAYLOAD_ROOT, destination, symlinks=False)
    if _inventory(destination) != manifest["files"]:
        raise LocalProofBundleError("materialized proof bundle differs")
    return manifest


def store_proof_bundle(
    repo_root: Path, *, identity: Mapping[str, Any], source: Path
) -> dict[str, Any]:
    """Persist exact local receipts once under their content-addressed identity."""

    cache_root = _cache_root(repo_root)
    destination = cache_root / identity_digest(identity)
    if destination.exists():
        return _verify(repo_root, destination, identity)
    with tempfile.TemporaryDirectory(prefix=".proof-", dir=cache_root) as temporary:
        staged = Path(temporary) / "bundle"
        payload = staged / PAYLOAD_ROOT
        shutil.copytree(source, payload, symlinks=False)
        manifest: dict[str, Any] = {
            "schema_version": "1.0",
            "kind": "governance.local-proof-bundle.v1",
            "lifecycle": "persistent_shared_acceleration_only",
            "identity": dict(identity),
            "identity_sha256": identity_digest(identity),
            "files": _inventory(payload),
            "authority": {
                "class": "local_non_authoritative",
                "provider_authority_substituted": False,
            },
        }
        manifest["bundle_sha256"] = hashlib.sha256(_canonical(manifest)).hexdigest()
        staged.mkdir(parents=True, exist_ok=True)
        (staged / MANIFEST_NAME).write_bytes(_canonical(manifest))
        _verify(repo_root, staged, identity)
        try:
            staged.replace(destination)
        except FileExistsError:
            return _verify(repo_root, destination, identity)
    return _verify(repo_root, destination, identity)

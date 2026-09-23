"""Canonical state primitives for one-PR routine controller rotation."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from jsonschema import Draft202012Validator


SCHEMA = Path("schemas/controller-transition.schema.json")
_SHA = re.compile(r"^[a-f0-9]{40}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


class RoutineRotationError(ValueError):
    """Raised when routine rotation evidence is incomplete or contradictory."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _exact_sha(value: object, *, field: str) -> str:
    text = str(value)
    if _SHA.fullmatch(text) is None:
        raise RoutineRotationError(f"{field} must be one exact Git SHA")
    return text


def transition_id(
    *, repository_id: object, installed_commit: object,
    subject_commit: object, subject_tree: object, artifact_digest: object,
) -> str:
    """Derive the immutable transition identity; callers never choose it."""

    repository = str(repository_id)
    digest = str(artifact_digest)
    if not repository.isdigit() or int(repository) < 1:
        raise RoutineRotationError("repository ID must be positive")
    if _DIGEST.fullmatch(digest) is None:
        raise RoutineRotationError("controller artifact digest must be exact")
    identity = {
        "repository_id": repository,
        "installed_commit": _exact_sha(installed_commit, field="installed controller"),
        "subject_commit": _exact_sha(subject_commit, field="subject commit"),
        "subject_tree": _exact_sha(subject_tree, field="subject tree"),
        "artifact_digest": digest,
    }
    return hashlib.sha256(_canonical(identity)).hexdigest()


def validate_transition(repo_root: Path, payload: object) -> dict[str, Any]:
    """Validate the closed transition contract plus cross-field custody."""

    if not isinstance(payload, dict):
        raise RoutineRotationError("controller transition must be one object")
    try:
        schema = json.loads((repo_root / SCHEMA).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RoutineRotationError("controller transition schema is unavailable") from exc
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda item: list(item.absolute_path),
    )
    if errors:
        location = ".".join(str(value) for value in errors[0].absolute_path) or "<root>"
        raise RoutineRotationError(
            f"controller transition schema violation at {location}: {errors[0].message}"
        )
    value = dict(payload)
    subject = value["subject"]
    artifact = value["artifact"]
    expected = transition_id(
        repository_id=value["repository"]["id"],
        installed_commit=value["authority"]["installed_controller_commit"],
        subject_commit=subject["commit_sha"],
        subject_tree=subject["tree_sha"],
        artifact_digest=artifact["provider_digest"],
    )
    if value["transition_id"] != expected:
        raise RoutineRotationError("controller transition identity is not derived")
    if artifact["commit_sha"] != subject["commit_sha"] or artifact["tree_sha"] != subject["tree_sha"]:
        raise RoutineRotationError("controller artifact differs from transition subject")
    if artifact["commit_sha"] == value["authority"]["installed_controller_commit"]:
        raise RoutineRotationError("routine transition must change controller identity")
    if value["authority"]["policy_before_sha256"] != value["authority"]["policy_after_sha256"]:
        raise RoutineRotationError("routine transition cannot change authorization policy")
    runners = value["required_runners"]
    for stage in ("bootstrap", "probe", "promotion"):
        proofs = value[stage]
        if sorted(item["runner"] for item in proofs) != runners:
            raise RoutineRotationError(f"{stage} runner inventory is not exact")
        if any(item["controller_commit"] != artifact["commit_sha"] for item in proofs):
            raise RoutineRotationError(f"{stage} controller identity is not exact")
    if value["state"] == "active":
        activation = value.get("activation")
        if not isinstance(activation, dict):
            raise RoutineRotationError("active transition lacks activation decision")
        if activation["authorizing_controller_commit"] != value["authority"]["installed_controller_commit"]:
            raise RoutineRotationError("candidate controller cannot authorize itself")
        if activation["transition_id"] != value["transition_id"]:
            raise RoutineRotationError("activation decision is bound to another transition")
    return value


def select_active_transition(
    repo_root: Path,
    receipts: Iterable[Mapping[str, Any]],
    *,
    repository_id: str,
    installed_commit: str,
    current_main_commit: str,
) -> dict[str, Any] | None:
    """Select one unreplayed active transition or fail closed on ambiguity."""

    admitted: list[dict[str, Any]] = []
    for raw in receipts:
        value = validate_transition(repo_root, dict(raw))
        if value["state"] != "active":
            continue
        if (
            value["repository"]["id"] != repository_id
            or value["authority"]["installed_controller_commit"] != installed_commit
            or value["subject"]["commit_sha"] != current_main_commit
        ):
            continue
        admitted.append(value)
    identities = {value["transition_id"] for value in admitted}
    if len(admitted) > 1 or len(identities) > 1:
        raise RoutineRotationError("active controller transition is ambiguous")
    return admitted[0] if admitted else None


def run_rotation_command(argv: list[str]) -> None:
    """Expose deterministic dormant transition operations during migration."""

    parser = argparse.ArgumentParser(description="BCF routine controller rotation.")
    operations = parser.add_subparsers(dest="operation", required=True)
    verify = operations.add_parser("verify")
    verify.add_argument("--repo-root", type=Path, default=Path.cwd())
    verify.add_argument("--receipt", type=Path, required=True)
    derive = operations.add_parser("derive-id")
    derive.add_argument("--repository-id", required=True)
    derive.add_argument("--installed-commit", required=True)
    derive.add_argument("--subject-commit", required=True)
    derive.add_argument("--subject-tree", required=True)
    derive.add_argument("--artifact-digest", required=True)
    args = parser.parse_args(argv)
    if args.operation == "verify":
        payload = json.loads(args.receipt.read_text(encoding="utf-8"))
        result = validate_transition(args.repo_root, payload)
    else:
        result = {"transition_id": transition_id(
            repository_id=args.repository_id,
            installed_commit=args.installed_commit,
            subject_commit=args.subject_commit,
            subject_tree=args.subject_tree,
            artifact_digest=args.artifact_digest,
        )}
    print(json.dumps(result, sort_keys=True))

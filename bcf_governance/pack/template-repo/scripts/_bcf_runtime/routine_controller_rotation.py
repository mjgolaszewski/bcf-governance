"""Canonical state primitives for one-PR routine controller rotation."""

from __future__ import annotations

import argparse
import hashlib
import json
from enum import StrEnum
from pathlib import Path
import re
from typing import Any, Callable, Iterable, Mapping, Sequence

from jsonschema import Draft202012Validator


SCHEMA = Path("schemas/controller-transition.schema.json")
_SHA = re.compile(r"^[a-f0-9]{40}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
ROTATION_POLICY_PATHS = (
    "governance/github-protection.yml",
    "governance/self-governance-policy.yml",
    "governance/ci-extensions/bcf-trusted-control.yml",
    "schemas/controller-transition.schema.json",
)


class GovernedControllerLane(StrEnum):
    ORDINARY_PROTECTED_N_N_PLUS_1 = "ordinary_protected_n_n_plus_1"


ALTERNATE_POLICY_LANE_SEQUENCE = (
    "project_exact_provider_target",
    "bootstrap_required_runners",
    "probe_required_runners",
    "provider_compile_confirmation",
    "protected_confirmation_merge",
    "normalize_ordinary_current",
)
class RoutineRotationError(ValueError):
    """Raised when routine rotation evidence is incomplete or contradictory."""


def classify_callback_topology(
    *, expected_jobs: set[str], jobs: Sequence[Mapping[str, Any]]
) -> str:
    """Return the sole typed callback lane for one exact job inventory."""

    authorize = "Authorize protected routine controller transition"
    reconcile = "Commit the deterministic automation changelog entry"
    actual = {str(value.get("name", "")): value for value in jobs}
    if set(actual) != expected_jobs:
        raise RoutineRotationError("rotation callback job inventory is not exact")
    if authorize not in expected_jobs or reconcile not in expected_jobs:
        raise RoutineRotationError("rotation callback authority inventory is invalid")
    if actual[authorize].get("conclusion") != "success":
        raise RoutineRotationError("rotation callback authorization did not succeed")
    if actual[reconcile].get("conclusion") != "skipped":
        raise RoutineRotationError("rotation callback reconcile topology is invalid")
    conclusions = {
        str(actual[name].get("conclusion"))
        for name in expected_jobs - {authorize, reconcile}
    }
    if conclusions == {"skipped"}:
        return "no_transition"
    if conclusions == {"success"}:
        return "active_transition"
    raise RoutineRotationError("rotation callback topology is partial")


def transition_follows_normalization(
    *,
    transition_subject: object,
    normalization_subject: object,
    is_ancestor: Callable[[str, str], bool],
) -> bool:
    """Classify one transition against authenticated source normalization."""

    transition = _exact_sha(transition_subject, field="transition subject")
    normalization = _exact_sha(normalization_subject, field="normalization subject")
    if is_ancestor(normalization, transition):
        return True
    if is_ancestor(transition, normalization):
        return False
    raise RoutineRotationError(
        "controller transition is not ordered with source normalization"
    )


def alternate_policy_lane_contract() -> dict[str, Any]:
    """Return the sole governed route for a protected rotation-policy change."""

    return {
        "id": GovernedControllerLane.ORDINARY_PROTECTED_N_N_PLUS_1.value,
        "required_sequence": list(ALTERNATE_POLICY_LANE_SEQUENCE),
        "required_initial_state": "ordinary-pending-rotation",
        "required_terminal_state": "ordinary-current",
    }


def controller_policy_digest(read_content: Callable[[str], bytes]) -> str:
    """Bind the exact closed rotation-policy byte inventory."""

    digest = hashlib.sha256()
    for path in ROTATION_POLICY_PATHS:
        content = read_content(path)
        if not isinstance(content, bytes):
            raise RoutineRotationError("controller policy content must be exact bytes")
        digest.update(path.encode("utf-8") + b"\0" + content + b"\0")
    return digest.hexdigest()


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
    completed_stages = {
        "authorized": (),
        "installing": ("bootstrap",),
        "probed": ("bootstrap", "probe"),
        "active": ("bootstrap", "probe", "promotion"),
        "superseded": ("bootstrap", "probe", "promotion"),
        "failed": (),
    }[value["state"]]
    for stage in ("bootstrap", "probe", "promotion"):
        proofs = value[stage]
        expected = runners if stage in completed_stages else []
        if sorted(item["runner"] for item in proofs) != expected:
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


def advance_transition(
    repo_root: Path,
    payload: Mapping[str, Any],
    *,
    state: str,
    proofs: Sequence[Mapping[str, Any]] = (),
    activation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Advance one immutable transition by exactly one canonical state."""

    current = validate_transition(repo_root, dict(payload))
    expected = {
        "authorized": ("installing", "bootstrap"),
        "installing": ("probed", "probe"),
        "probed": ("active", "promotion"),
    }.get(current["state"])
    if expected is None or state != expected[0]:
        raise RoutineRotationError("controller transition state advance is not canonical")
    result = json.loads(json.dumps(current))
    result["state"] = state
    result[expected[1]] = [dict(value) for value in proofs]
    if state == "active":
        if activation is None:
            raise RoutineRotationError("active transition lacks activation decision")
        result["activation"] = dict(activation)
    elif activation is not None:
        raise RoutineRotationError("non-active transition cannot carry activation")
    return validate_transition(repo_root, result)


def select_controller_chain(
    repo_root: Path,
    receipts: Iterable[Mapping[str, Any]],
    *,
    repository_id: str,
    baseline_installed_commit: str,
    ancestor_commits: Iterable[str],
) -> tuple[dict[str, Any], ...]:
    """Select one linear, unreplayed active controller chain or fail closed."""

    baseline = _exact_sha(
        baseline_installed_commit, field="baseline installed controller"
    )
    ancestors = {
        _exact_sha(value, field="controller transition ancestor")
        for value in ancestor_commits
    }
    admitted: list[dict[str, Any]] = []
    identities: set[str] = set()
    for raw in receipts:
        value = validate_transition(repo_root, dict(raw))
        if value["transition_id"] in identities:
            raise RoutineRotationError("controller transition replay is ambiguous")
        identities.add(value["transition_id"])
        if value["state"] != "active":
            continue
        if value["repository"]["id"] != repository_id:
            continue
        if value["subject"]["commit_sha"] not in ancestors:
            continue
        admitted.append(value)
    chain: list[dict[str, Any]] = []
    current = baseline
    while True:
        candidates = [
            value for value in admitted
            if value["authority"]["installed_controller_commit"] == current
        ]
        if not candidates:
            break
        if len(candidates) != 1:
            raise RoutineRotationError("active controller transition is ambiguous")
        selected = candidates[0]
        chain.append(selected)
        admitted.remove(selected)
        current = selected["artifact"]["commit_sha"]
    if admitted:
        raise RoutineRotationError("active controller transition chain is disconnected")
    return tuple(chain)


def effective_controller_pin(
    baseline_pin: Mapping[str, Any], chain: Sequence[Mapping[str, Any]]
) -> dict[str, str]:
    """Project the effective controller pin without mutating source policy."""

    if not chain:
        return {str(key): str(value) for key, value in baseline_pin.items()}
    artifact = chain[-1]["artifact"]
    repository = chain[-1]["repository"]
    return {
        "BCF_BOOTSTRAP_ARTIFACT_ID": str(artifact["id"]),
        "BCF_BOOTSTRAP_ARTIFACT_NAME": str(artifact["name"]),
        "BCF_BOOTSTRAP_ARTIFACT_DIGEST": str(artifact["provider_digest"]),
        "BCF_BOOTSTRAP_RUN_ID": str(artifact["run_id"]),
        "BCF_BOOTSTRAP_RUN_ATTEMPT": str(artifact["run_attempt"]),
        "BCF_BOOTSTRAP_COMMIT_SHA": str(artifact["commit_sha"]),
        "BCF_BOOTSTRAP_TREE_SHA": str(artifact["tree_sha"]),
        "BCF_BOOTSTRAP_REPOSITORY_ID": str(repository["id"]),
        "BCF_BOOTSTRAP_WHEEL_SHA256": str(artifact["wheel_sha256"]),
    }


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

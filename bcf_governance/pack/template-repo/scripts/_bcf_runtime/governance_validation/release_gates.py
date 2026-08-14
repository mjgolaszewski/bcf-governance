"""release gates validation helpers."""
# ruff: noqa: F403,F405

from __future__ import annotations

from .common import *  # noqa: F403,F405

def _makefile_target_bodies(makefile_path: Path) -> dict[str, list[str]]:
    targets: dict[str, list[str]] = {}
    current_target: str | None = None
    for line in makefile_path.read_text(encoding="utf-8").splitlines():
        match = MAKE_TARGET_PATTERN.match(line)
        if match is not None:
            current_target = match.group(1)
            targets.setdefault(current_target, [])
            continue
        if current_target is not None:
            targets[current_target].append(line)
    return targets


def _meaningful_make_commands(lines: list[str]) -> list[str]:
    commands: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("@"):
            stripped = stripped[1:].strip()
        if stripped.startswith(("-", "+")):
            stripped = stripped[1:].strip()
        if not stripped or stripped.startswith(("#", "echo ", "printf ")):
            continue
        if stripped in {":", "true", "/bin/true"}:
            continue
        commands.append(stripped)
    return commands


def _release_gates_from_profile(profile: dict[str, Any] | None) -> dict[str, dict[str, str]]:
    if profile is None:
        return {
            target: {
                "status": "required",
                "command_policy": DEFAULT_RELEASE_GATE_POLICIES[target],
            }
            for target in sorted(DEFAULT_RELEASE_GATE_TARGETS)
        }
    release_gate_profile = _require_mapping(
        profile.get("release_gate_profile"), context="governance-profile.yml release_gate_profile"
    )
    gates = _require_mapping(
        release_gate_profile.get("gates"), context="governance-profile.yml release_gate_profile.gates"
    )
    gates_by_target: dict[str, dict[str, str]] = {}
    for gate_id, payload in gates.items():
        gate = _require_mapping(payload, context=f"governance-profile.yml release_gate_profile.gates.{gate_id}")
        target = _require_string(
            gate.get("target"), context=f"governance-profile.yml release_gate_profile.gates.{gate_id}.target"
        )
        status = _require_string(
            gate.get("status"), context=f"governance-profile.yml release_gate_profile.gates.{gate_id}.status"
        )
        command_policy = _require_string(
            gate.get("command_policy"),
            context=f"governance-profile.yml release_gate_profile.gates.{gate_id}.command_policy",
        )
        if command_policy not in RELEASE_GATE_POLICY_MARKERS:
            raise GovernanceValidationError(
                "governance-profile.yml release_gate_profile.gates."
                f"{gate_id}.command_policy must be one of {sorted(RELEASE_GATE_POLICY_MARKERS)}"
            )
        gates_by_target[target] = {"status": status, "command_policy": command_policy}
    return gates_by_target


def _release_gate_makefile_path(repo_root: Path) -> Path | None:
    for relative_path in ("Makefile", "Makefile.fragment"):
        path = repo_root / relative_path
        if path.exists():
            return path
    return None


def _validate_release_gate_command_semantics(
    *,
    makefile_display: str,
    target: str,
    commands: list[str],
    command_policy: str,
) -> None:
    lowered_commands = [command.lower() for command in commands]
    for command in lowered_commands:
        if RELEASE_GATE_MEANINGLESS_VERSION_PATTERN.search(command):
            raise GovernanceValidationError(
                f"{makefile_display} target {target} uses a version/probe command, not release evidence"
            )

    joined_commands = "\n".join(lowered_commands)
    required_markers = RELEASE_GATE_POLICY_MARKERS[command_policy]
    if not any(marker in joined_commands for marker in required_markers):
        raise GovernanceValidationError(
            f"{makefile_display} target {target} must look like {command_policy} evidence "
            f"(expected one of: {', '.join(required_markers)})"
        )


def _validate_release_gate_targets(
    repo_root: Path,
    profile: dict[str, Any] | None,
    *,
    allow_release_gate_placeholders: bool,
) -> None:
    if allow_release_gate_placeholders:
        return
    makefile_path = _release_gate_makefile_path(repo_root)
    if makefile_path is None:
        raise GovernanceValidationError("Makefile or Makefile.fragment must define release-check")
    makefile_display = _repo_relative_path(repo_root, makefile_path)

    makefile_text = makefile_path.read_text(encoding="utf-8")
    lowered_makefile = makefile_text.lower()
    for marker in RELEASE_GATE_PLACEHOLDER_MARKERS:
        if marker in lowered_makefile:
            raise GovernanceValidationError(
                f"{makefile_display} contains unresolved release gate placeholder marker {marker!r}"
            )

    target_bodies = _makefile_target_bodies(makefile_path)
    release_check_body = target_bodies.get("release-check")
    if release_check_body is None:
        raise GovernanceValidationError(f"{makefile_display} must define release-check")
    if not _meaningful_make_commands(release_check_body):
        raise GovernanceValidationError(
            f"{makefile_display} release-check must run real validation commands"
        )

    gates_by_target = _release_gates_from_profile(profile)
    required_targets = {
        target for target, gate in gates_by_target.items() if gate["status"] in RELEASE_GATE_REQUIRED_STATUSES
    }
    missing_targets = sorted(required_targets - set(target_bodies))
    if missing_targets:
        raise GovernanceValidationError(
            f"{makefile_display} must define required release gate targets: "
            + ", ".join(missing_targets)
        )


def _validate_ci_profile(profile: dict[str, Any] | None) -> None:
    if profile is None:
        return
    ci_profile = _require_mapping(
        profile.get("ci_profile"), context="governance-profile.yml ci_profile"
    )
    required_push_jobs = _require_string_sequence(
        ci_profile.get("required_push_jobs"),
        context="governance-profile.yml ci_profile.required_push_jobs",
        min_items=1,
    )
    gates_by_target = _release_gates_from_profile(profile)
    missing_jobs = sorted(job for job in required_push_jobs if job not in gates_by_target)
    if missing_jobs:
        raise GovernanceValidationError(
            "governance-profile.yml ci_profile.required_push_jobs must reference release gate "
            "targets: " + ", ".join(missing_jobs)
        )
    inactive_jobs = sorted(
        job
        for job in required_push_jobs
        if gates_by_target[job]["status"] in RELEASE_GATE_INACTIVE_STATUSES
    )
    if inactive_jobs:
        raise GovernanceValidationError(
            "governance-profile.yml ci_profile.required_push_jobs cannot reference inactive "
            "release gates: " + ", ".join(inactive_jobs)
        )


def _validate_structural_gate_contract(
    profile: dict[str, Any] | None,
    architecture_rules: dict[str, Any] | None,
) -> None:
    if architecture_rules is None:
        return
    profile_block = profile.get("profile") if isinstance(profile, dict) else None
    if isinstance(profile_block, dict) and profile_block.get("selected") == "lite":
        return
    architecture = _require_mapping(
        architecture_rules.get("architecture"), context="architecture-boundaries.yml architecture"
    )
    gate_policy = _require_mapping(
        architecture.get("mandatory_rule_gate_policy"),
        context="architecture-boundaries.yml architecture.mandatory_rule_gate_policy",
    )
    if not gate_policy.get("every_mandatory_rule_has_executable_gate", False):
        return
    human_review_rules = _require_sequence(
        gate_policy.get("human_review_only_rules"),
        context="architecture-boundaries.yml architecture.mandatory_rule_gate_policy.human_review_only_rules",
    )
    human_review_ids = {
        _require_string(
            _require_mapping(
                rule,
                context=(
                    "architecture-boundaries.yml "
                    f"architecture.mandatory_rule_gate_policy.human_review_only_rules[{index}]"
                ),
            ).get("rule_id"),
            context=(
                "architecture-boundaries.yml "
                f"architecture.mandatory_rule_gate_policy.human_review_only_rules[{index}].rule_id"
            ),
        )
        for index, rule in enumerate(human_review_rules, start=1)
    }
    gates_by_target = _release_gates_from_profile(profile)
    missing_targets = sorted(
        target
        for target in MANDATORY_STRUCTURAL_GATE_TARGETS
        if target not in gates_by_target and target not in human_review_ids
    )
    if missing_targets:
        raise GovernanceValidationError(
            "mandatory structural rules must have executable release gates or human_review_only "
            "rationale: " + ", ".join(missing_targets)
        )
    inactive_targets = sorted(
        target
        for target in MANDATORY_STRUCTURAL_GATE_TARGETS
        if target in gates_by_target
        and gates_by_target[target]["status"] in RELEASE_GATE_INACTIVE_STATUSES
        and target not in human_review_ids
    )
    if inactive_targets:
        raise GovernanceValidationError(
            "mandatory structural release gates cannot be inactive without human_review_only "
            "rationale: " + ", ".join(inactive_targets)
        )

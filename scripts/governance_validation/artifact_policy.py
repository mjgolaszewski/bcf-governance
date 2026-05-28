"""artifact policy validation helpers."""
# ruff: noqa: F403,F405

from __future__ import annotations

import hashlib
import shlex
import subprocess

from .common import *  # noqa: F403,F405
from .phase_artifacts import _phase_number

def _validate_observability_contracts(
    repo_root: Path, schema_cache: dict[str, dict[str, Any]]
) -> list[Path]:
    paths: list[Path] = []
    for relative_path in OBSERVABILITY_CONTRACT_PATHS:
        path = _require_path(
            repo_root,
            relative_path,
            context="observability contract template",
        )
        payload = _load_yaml(path)
        _validate_schema(
            repo_root,
            schema_cache,
            payload,
            schema_name=OBSERVABILITY_CONTRACT_SCHEMA,
            context=relative_path,
        )
        contract_id = _require_string(
            payload.get("contract_id"), context=f"{relative_path} contract_id"
        )
        expected_domain = "telemetry" if "telemetry" in relative_path else "logging"
        if f".{expected_domain}." not in contract_id:
            raise GovernanceValidationError(
                f"{relative_path} contract_id must include .{expected_domain}."
            )
        paths.append(path)
    return paths


def _artifact_root_paths(manifest: dict[str, Any]) -> dict[str, str]:
    roots = _require_mapping(
        manifest.get("artifact_roots"), context="governance/artifact-manifest.yml artifact_roots"
    )
    root_paths: dict[str, str] = {}
    for root_id, payload in roots.items():
        root = _require_mapping(
            payload, context=f"governance/artifact-manifest.yml artifact_roots.{root_id}"
        )
        path = _require_string(
            root.get("path"), context=f"governance/artifact-manifest.yml artifact_roots.{root_id}.path"
        )
        _validate_portable_relative_path(
            path, context=f"governance/artifact-manifest.yml artifact_roots.{root_id}.path"
        )
        root_paths[str(root_id)] = path
    return root_paths


def _declared_vendor_prefixes(manifest: dict[str, Any]) -> list[str]:
    nested = _require_mapping(
        manifest.get("nested_governance"), context="governance/artifact-manifest.yml nested_governance"
    )
    vendors = _require_sequence(
        nested.get("declared_vendors"),
        context="governance/artifact-manifest.yml nested_governance.declared_vendors",
    )
    prefixes: list[str] = []
    for index, vendor in enumerate(vendors, start=1):
        vendor_mapping = _require_mapping(
            vendor,
            context=f"governance/artifact-manifest.yml nested_governance.declared_vendors[{index}]",
        )
        path = _require_string(
            vendor_mapping.get("path"),
            context=(
                "governance/artifact-manifest.yml "
                f"nested_governance.declared_vendors[{index}].path"
            ),
        )
        _validate_portable_relative_path(
            path,
            context=(
                "governance/artifact-manifest.yml "
                f"nested_governance.declared_vendors[{index}].path"
            ),
        )
        prefixes.append(path)
    return prefixes


def _is_nested_governance_marker(relative_path: str) -> bool:
    path = Path(relative_path)
    parts = path.parts
    if len(parts) > 1 and path.name in GOVERNANCE_MARKER_FILENAMES:
        return True
    if path.suffix not in {".yml", ".yaml"}:
        return False
    for marker_dir in GOVERNANCE_MARKER_DIRS:
        if marker_dir in parts[:-1] and parts[0] != marker_dir:
            return True
    return False


def _validate_audit_root_policy(
    repo_root: Path,
    manifest: dict[str, Any],
    *,
    root_paths: dict[str, str],
    vendor_prefixes: list[str],
) -> None:
    audit_root = root_paths.get("audits")
    if audit_root is None:
        raise GovernanceValidationError("governance/artifact-manifest.yml must declare artifact_roots.audits")
    _require_path(repo_root, audit_root, context="governance/artifact-manifest.yml artifact_roots.audits.path")

    violations: list[str] = []
    for path in _iter_repo_files(repo_root):
        relative_path = _repo_relative_path(repo_root, path)
        if _relative_path_is_under(relative_path, audit_root) or _relative_path_is_under_any(
            relative_path, vendor_prefixes
        ):
            continue
        if any(part.lower() in AUDIT_PATH_COMPONENTS for part in Path(relative_path).parts[:-1]):
            violations.append(relative_path)

    if violations:
        raise GovernanceValidationError(
            "audit artifacts must live under the declared audit root "
            f"{audit_root}: " + ", ".join(sorted(violations)[:20])
        )


def _validate_nested_governance_policy(
    repo_root: Path,
    manifest: dict[str, Any],
    *,
    vendor_prefixes: list[str],
) -> None:
    nested = _require_mapping(
        manifest.get("nested_governance"), context="governance/artifact-manifest.yml nested_governance"
    )
    policy = _require_string(
        nested.get("policy"), context="governance/artifact-manifest.yml nested_governance.policy"
    )
    if policy != "declared_vendor_only":
        raise GovernanceValidationError(
            "governance/artifact-manifest.yml nested_governance.policy must be declared_vendor_only"
        )

    violations = []
    for path in _iter_repo_files(repo_root):
        relative_path = _repo_relative_path(repo_root, path)
        if _relative_path_is_under_any(relative_path, vendor_prefixes):
            continue
        if _is_nested_governance_marker(relative_path):
            violations.append(relative_path)

    if violations:
        raise GovernanceValidationError(
            "nested governance artifacts must be declared as vendored packs: "
            + ", ".join(sorted(violations)[:20])
        )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_vendored_artifacts(repo_root: Path, manifest: dict[str, Any]) -> None:
    vendored = _require_mapping(
        manifest.get("vendored_artifacts"), context="governance/artifact-manifest.yml vendored_artifacts"
    )
    required_fields = _require_string_sequence(
        vendored.get("required_fields"),
        context="governance/artifact-manifest.yml vendored_artifacts.required_fields",
        min_items=1,
    )
    artifacts = _require_sequence(
        vendored.get("artifacts"), context="governance/artifact-manifest.yml vendored_artifacts.artifacts"
    )
    for index, artifact in enumerate(artifacts, start=1):
        artifact_mapping = _require_mapping(
            artifact, context=f"governance/artifact-manifest.yml vendored_artifacts.artifacts[{index}]"
        )
        missing_fields = sorted(field for field in required_fields if not artifact_mapping.get(field))
        if missing_fields:
            raise GovernanceValidationError(
                "governance/artifact-manifest.yml vendored_artifacts.artifacts"
                f"[{index}] missing required fields: " + ", ".join(missing_fields)
            )
        artifact_rel = _require_string(
            artifact_mapping.get("artifact_path"),
            context=f"governance/artifact-manifest.yml vendored_artifacts.artifacts[{index}].artifact_path",
        )
        artifact_path = _require_path(
            repo_root,
            artifact_rel,
            context=f"governance/artifact-manifest.yml vendored_artifacts.artifacts[{index}].artifact_path",
        )
        expected_sha = _require_string(
            artifact_mapping.get("artifact_sha256"),
            context=f"governance/artifact-manifest.yml vendored_artifacts.artifacts[{index}].artifact_sha256",
        )
        actual_sha = _file_sha256(artifact_path)
        if actual_sha != expected_sha:
            raise GovernanceValidationError(
                "governance/artifact-manifest.yml vendored_artifacts.artifacts"
                f"[{index}] artifact_sha256 mismatch for {artifact_rel}"
            )


def _validate_context_budgets(repo_root: Path, manifest: dict[str, Any]) -> None:
    context_budgets = _require_mapping(
        manifest.get("context_budgets"), context="governance/artifact-manifest.yml context_budgets"
    )
    agent_required_files = _require_mapping(
        context_budgets.get("agent_required_files"),
        context="governance/artifact-manifest.yml context_budgets.agent_required_files",
    )
    violations: list[str] = []
    for relative_path, budget in agent_required_files.items():
        budget_value = _require_positive_int(
            budget,
            context=(
                "governance/artifact-manifest.yml "
                f"context_budgets.agent_required_files.{relative_path}"
            ),
        )
        path = _require_path(
            repo_root,
            str(relative_path),
            context=(
                "governance/artifact-manifest.yml "
                f"context_budgets.agent_required_files.{relative_path}"
            ),
        )
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        if line_count > budget_value:
            violations.append(f"{relative_path} has {line_count} lines; budget is {budget_value}")
    if violations:
        raise GovernanceValidationError(
            "agent-required governance files exceeded context budgets:\n" + "\n".join(violations)
        )


def _phase_retention_policy(manifest: dict[str, Any]) -> dict[str, Any] | None:
    policy = manifest.get("phase_retention_policy")
    if policy is None:
        return None
    return _require_mapping(
        policy, context="governance/artifact-manifest.yml phase_retention_policy"
    )


def _phase_retention_mode(manifest: dict[str, Any]) -> str | None:
    policy = _phase_retention_policy(manifest)
    if policy is None or policy.get("mode") is None:
        return None
    mode = _require_string(
        policy.get("mode"),
        context="governance/artifact-manifest.yml phase_retention_policy.mode",
    )
    normalized = mode.replace("-", "_")
    if normalized not in PHASE_RETENTION_MODES:
        raise GovernanceValidationError(
            "governance/artifact-manifest.yml phase_retention_policy.mode must be one of "
            f"{sorted(PHASE_RETENTION_MODES)}"
        )
    return normalized


def _phase_archive_root(manifest: dict[str, Any]) -> str:
    policy = _phase_retention_policy(manifest)
    if policy is None:
        return "governance/archive/phase-artifacts/"
    archive = _require_mapping(
        policy.get("archive"),
        context="governance/artifact-manifest.yml phase_retention_policy.archive",
    )
    root = _require_string(
        archive.get("root"),
        context="governance/artifact-manifest.yml phase_retention_policy.archive.root",
    )
    return root.rstrip("/") + "/"


def _gitignore_lines(repo_root: Path) -> set[str]:
    gitignore = repo_root / ".gitignore"
    if not gitignore.exists():
        return set()
    return {
        line.strip()
        for line in gitignore.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }


def _archive_root_is_ignored(repo_root: Path, manifest: dict[str, Any]) -> bool:
    archive_root = _phase_archive_root(manifest).rstrip("/")
    lines = _gitignore_lines(repo_root)
    return f"{archive_root}/*" in lines and f"!{archive_root}/.gitkeep" in lines


def _git_show_sha256(repo_root: Path, git_ref: str, relative_path: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "show", f"{git_ref}:{relative_path}"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return hashlib.sha256(result.stdout).hexdigest()


def _validate_phase_retention_policy(repo_root: Path, manifest: dict[str, Any]) -> None:
    mode = _phase_retention_mode(manifest)
    if mode == "archive" and not _archive_root_is_ignored(repo_root, manifest):
        raise GovernanceValidationError(
            "archive phase retention mode requires .gitignore to ignore "
            f"{_phase_archive_root(manifest).rstrip('/')}/* and keep .gitkeep"
        )


def _phase_history_path_from_policy(
    repo_root: Path, manifest: dict[str, Any]
) -> Path | None:
    policy = _phase_retention_policy(manifest)
    if policy is None:
        return None
    history_path = _require_string(
        policy.get("history_path"),
        context="governance/artifact-manifest.yml phase_retention_policy.history_path",
    )
    return _require_path(
        repo_root,
        history_path,
        context="governance/artifact-manifest.yml phase_retention_policy.history_path",
    )


def _load_phase_history(
    repo_root: Path,
    schema_cache: dict[str, dict[str, Any]],
    manifest: dict[str, Any],
) -> tuple[dict[str, Any] | None, Path | None]:
    history_path = _phase_history_path_from_policy(repo_root, manifest)
    if history_path is None:
        return None, None
    phase_history = _load_yaml(history_path)
    _validate_schema(
        repo_root,
        schema_cache,
        phase_history,
        schema_name=PHASE_HISTORY_SCHEMA,
        context=str(history_path),
    )
    _validate_document_path(repo_root, phase_history, history_path, context=str(history_path))
    return phase_history, history_path


def _phase_history_entries(phase_history: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if phase_history is None:
        return {}
    entries = _require_sequence(phase_history.get("entries"), context="plans/phase-history.yml entries")
    by_phase: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(entries, start=1):
        entry_mapping = _require_mapping(
            entry, context=f"plans/phase-history.yml entries[{index}]"
        )
        phase_id = _require_string(
            entry_mapping.get("phase_id"),
            context=f"plans/phase-history.yml entries[{index}].phase_id",
        )
        if phase_id in by_phase:
            raise GovernanceValidationError(
                f"plans/phase-history.yml contains duplicate entry for {phase_id}"
            )
        by_phase[phase_id] = entry_mapping
    return by_phase


def _validate_phase_history_entries(
    repo_root: Path,
    phase_history: dict[str, Any] | None,
    *,
    product_phase_map: dict[str, dict[str, Any]],
    build_phase_map: dict[str, dict[str, Any]],
    manifest: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    history_entries = _phase_history_entries(phase_history)
    policy_mode = _phase_retention_mode(manifest)
    archive_root = _phase_archive_root(manifest)
    for phase_id, entry in history_entries.items():
        if phase_id not in build_phase_map:
            raise GovernanceValidationError(
                f"plans/phase-history.yml entry {phase_id} is not declared in the build plan"
            )
        build_block = _require_string(
            entry.get("build_block"),
            context=f"plans/phase-history.yml entries.{phase_id}.build_block",
        )
        if build_block != build_phase_map[phase_id].get("build_block"):
            raise GovernanceValidationError(
                f"plans/phase-history.yml entry {phase_id} build_block must match build plan"
            )
        release_train = entry.get("release_train")
        if release_train is not None and release_train != product_phase_map[phase_id].get("release_train"):
            raise GovernanceValidationError(
                f"plans/phase-history.yml entry {phase_id} release_train must match product spec"
            )
        status = _require_string(
            entry.get("status"), context=f"plans/phase-history.yml entries.{phase_id}.status"
        )
        if status not in PHASE_HISTORY_STATUSES:
            raise GovernanceValidationError(
                f"plans/phase-history.yml entry {phase_id} status must be one of "
                f"{sorted(PHASE_HISTORY_STATUSES)}"
            )
        entry_source = entry.get("retention_source")
        if policy_mode is not None:
            retention_source = _require_string(
                entry_source,
                context=f"plans/phase-history.yml entries.{phase_id}.retention_source",
            ).replace("-", "_")
            if retention_source != policy_mode:
                raise GovernanceValidationError(
                    f"plans/phase-history.yml entry {phase_id} retention_source "
                    "must match phase_retention_policy.mode"
                )
        else:
            retention_source = str(entry_source).replace("-", "_") if entry_source else None

        retention_ref = entry.get("retention_ref")
        if retention_source == "git_history":
            retention_ref = _require_string(
                retention_ref,
                context=f"plans/phase-history.yml entries.{phase_id}.retention_ref",
            )
        artifacts = _require_sequence(
            entry.get("archived_artifacts"),
            context=f"plans/phase-history.yml entries.{phase_id}.archived_artifacts",
        )
        if not artifacts:
            raise GovernanceValidationError(
                f"plans/phase-history.yml entry {phase_id} archived_artifacts "
                "must contain retained evidence"
            )
        for artifact_index, artifact in enumerate(artifacts, start=1):
            artifact_mapping = _require_mapping(
                artifact,
                context=(
                    "plans/phase-history.yml "
                    f"entries.{phase_id}.archived_artifacts[{artifact_index}]"
                ),
            )
            artifact_rel = _require_string(
                artifact_mapping.get("path"),
                context=(
                    "plans/phase-history.yml "
                    f"entries.{phase_id}.archived_artifacts[{artifact_index}].path"
                ),
            )
            _validate_portable_relative_path(
                artifact_rel,
                context=(
                    "plans/phase-history.yml "
                    f"entries.{phase_id}.archived_artifacts[{artifact_index}].path"
                ),
            )
            artifact_path = repo_root / artifact_rel
            expected_sha = _require_string(
                artifact_mapping.get("sha256"),
                context=(
                    "plans/phase-history.yml "
                    f"entries.{phase_id}.archived_artifacts[{artifact_index}].sha256"
                ),
            )
            if artifact_path.exists():
                actual_sha = _file_sha256(artifact_path)
            elif retention_source == "git_history":
                artifact_ref = str(artifact_mapping.get("git_commit") or retention_ref)
                actual_sha = _git_show_sha256(
                    repo_root,
                    artifact_ref,
                    str(artifact_mapping.get("path")),
                )
                if actual_sha is None:
                    raise GovernanceValidationError(
                        f"plans/phase-history.yml entry {phase_id} archived artifact "
                        f"{artifact_mapping.get('path')} is missing and not available from git history"
                    )
            elif retention_source == "archive":
                if not _relative_path_is_under(artifact_rel, archive_root):
                    raise GovernanceValidationError(
                        f"plans/phase-history.yml entry {phase_id} archived artifact "
                        "must live under the phase archive root"
                    )
                actual_sha = expected_sha
            else:
                raise GovernanceValidationError(
                    f"plans/phase-history.yml entry {phase_id} archived artifact "
                    f"{artifact_rel} is missing"
                )

            if actual_sha != expected_sha:
                raise GovernanceValidationError(
                    f"plans/phase-history.yml entry {phase_id} archived artifact "
                    f"{_repo_relative_path(repo_root, artifact_path)} has a sha256 mismatch"
                )
    return history_entries


def _retained_phase_ids(
    *,
    build_phase_map: dict[str, dict[str, Any]],
    ledger: dict[str, Any],
    manifest: dict[str, Any],
) -> set[str] | None:
    policy = _phase_retention_policy(manifest)
    if policy is None:
        return None
    active_window = _require_mapping(
        policy.get("active_window"),
        context="governance/artifact-manifest.yml phase_retention_policy.active_window",
    )
    active_phase = _require_mapping(
        ledger.get("active_phase"), context="plans/phase-ledger.yml active_phase"
    )
    active_id = _require_string(active_phase.get("id"), context="plans/phase-ledger.yml active_phase.id")
    retained: set[str] = set()
    sorted_phase_ids = sorted(build_phase_map, key=_phase_number)
    if active_window.get("include_active", True):
        retained.add(active_id)
    if active_window.get("include_next", True):
        for phase_id in sorted_phase_ids:
            if _phase_number(phase_id) > _phase_number(active_id):
                retained.add(phase_id)
                break
    keep_recent_closed = _require_non_negative_int(
        active_window.get("keep_recent_closed", 0),
        context=(
            "governance/artifact-manifest.yml "
            "phase_retention_policy.active_window.keep_recent_closed"
        ),
    )
    prior_phase_ids = [
        phase_id
        for phase_id in sorted_phase_ids
        if _phase_number(phase_id) < _phase_number(active_id)
    ]
    retained.update(prior_phase_ids[-keep_recent_closed:] if keep_recent_closed else [])
    return retained


def _strict_phase_retention_enabled(manifest: dict[str, Any]) -> bool:
    return _phase_retention_mode(manifest) is not None


def _pytest_paths_from_command(command: str) -> list[str]:
    normalized = command.replace("$(PYTEST)", "pytest")
    try:
        tokens = shlex.split(normalized)
    except ValueError:
        tokens = normalized.split()
    paths: list[str] = []
    pytest_index: int | None = None
    for index, token in enumerate(tokens):
        if token == "pytest":
            pytest_index = index
            break
        if token == "pytest;" or token.endswith("/pytest"):
            pytest_index = index
            break
        if token == "-m" and index > 0 and tokens[index - 1].startswith("python") and index + 1 < len(tokens):
            if tokens[index + 1] == "pytest":
                pytest_index = index + 1
                break
    if pytest_index is None:
        return []
    options_with_value = {
        "-k",
        "-m",
        "-o",
        "--basetemp",
        "--cache-clear",
        "--confcutdir",
        "--cov",
        "--cov-report",
        "--ignore",
        "--ignore-glob",
        "--junitxml",
        "--maxfail",
        "--rootdir",
    }
    skip_next = False
    for token in tokens[pytest_index + 1 :]:
        if skip_next:
            skip_next = False
            continue
        if token in {";", "&&", "||", "|"}:
            break
        if token in options_with_value:
            skip_next = True
            continue
        if any(token.startswith(f"{option}=") for option in options_with_value):
            continue
        if token.startswith("-") or "=" in token:
            continue
        if token == ".":
            continue
        if "/" in token or token in {"test", "tests"} or token.endswith("_tests"):
            paths.append(token.rstrip("/"))
    return paths


def _discover_invoked_test_paths(repo_root: Path) -> list[str]:
    discovered: set[str] = set()
    for relative_path in ("Makefile", "Makefile.fragment"):
        makefile_path = repo_root / relative_path
        if makefile_path.exists():
            for line in makefile_path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped.startswith("@"):
                    stripped = stripped[1:].strip()
                for test_path in _pytest_paths_from_command(stripped):
                    discovered.add(test_path)

    workflow_root = repo_root / ".github" / "workflows"
    if workflow_root.exists():
        for workflow_path in sorted(workflow_root.glob("*.yml")) + sorted(workflow_root.glob("*.yaml")):
            for line in workflow_path.read_text(encoding="utf-8").splitlines():
                for test_path in _pytest_paths_from_command(line.strip()):
                    discovered.add(test_path)

    for child in repo_root.iterdir():
        if child.is_dir() and (child.name in {"test", "tests"} or child.name.endswith("_tests")):
            discovered.add(child.name)
    return sorted(discovered)


def _declared_test_roots(agents: dict[str, Any]) -> list[str]:
    testing = _require_mapping(agents.get("testing_governance"), context="AGENTS.yml testing_governance")
    return _require_string_sequence(
        testing.get("test_roots"),
        context="AGENTS.yml testing_governance.test_roots",
        min_items=1,
    )


def _validate_declared_test_roots(repo_root: Path, agents: dict[str, Any]) -> None:
    declared_roots = _declared_test_roots(agents)
    violations = [
        test_path
        for test_path in _discover_invoked_test_paths(repo_root)
        if not _relative_path_is_under_any(test_path, declared_roots)
    ]
    if violations:
        raise GovernanceValidationError(
            "test paths invoked by Makefile or CI must be declared in AGENTS.yml "
            "testing_governance.test_roots: " + ", ".join(violations)
        )


def _validate_ephemeral_evidence_references(repo_root: Path, manifest: dict[str, Any]) -> None:
    ephemeral = _require_mapping(
        manifest.get("ephemeral_evidence"), context="governance/artifact-manifest.yml ephemeral_evidence"
    )
    if not ephemeral.get("durable_reference_required", False):
        return
    roots = _require_string_sequence(
        ephemeral.get("roots"),
        context="governance/artifact-manifest.yml ephemeral_evidence.roots",
    )
    governed_prefixes = ["audits/", "docs/", "governance/", "plans/", "phases/"]
    durable_markers = ("sha256", "ci artifact", "non-authoritative", "uploaded artifact")
    violations: list[str] = []
    for path in _iter_repo_files(repo_root):
        relative_path = _repo_relative_path(repo_root, path)
        if relative_path == "governance/artifact-manifest.yml":
            continue
        if relative_path not in {"AGENTS.yml", "MEMORY.yml"} and not _relative_path_is_under_any(
            relative_path, governed_prefixes
        ):
            continue
        if path.suffix.lower() not in {".md", ".yml", ".yaml"}:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(lines, start=1):
            lowered = line.lower()
            if not _line_mentions_ephemeral_root(lowered, roots):
                continue
            window = "\n".join(lines[line_number - 1 : line_number + 2]).lower()
            if not any(marker in window for marker in durable_markers):
                violations.append(f"{relative_path}:{line_number}")
    if violations:
        raise GovernanceValidationError(
            "ephemeral artifact references in governed docs need sha256, CI artifact, "
            "uploaded artifact, or non-authoritative marker: " + ", ".join(violations[:20])
        )


def _line_mentions_ephemeral_root(line: str, roots: list[str]) -> bool:
    for root in roots:
        root_value = root.lower().strip()
        normalized = root_value.rstrip("/")
        if not normalized:
            continue
        suffix = "/" if root_value.endswith("/") else r"(?:/|$)"
        pattern = rf"(?<![A-Za-z0-9_.-]){re.escape(normalized)}{suffix}"
        if re.search(pattern, line):
            return True
    return False


def _validate_artifact_manifest(
    repo_root: Path,
    manifest: dict[str, Any] | None,
    agents: dict[str, Any],
) -> list[Path]:
    if manifest is None:
        return []

    root_paths = _artifact_root_paths(manifest)
    for root_id, root_path in root_paths.items():
        _require_path(repo_root, root_path, context=f"governance/artifact-manifest.yml artifact_roots.{root_id}.path")

    vendor_prefixes = _declared_vendor_prefixes(manifest)
    for vendor_prefix in vendor_prefixes:
        _require_path(
            repo_root,
            vendor_prefix,
            context="governance/artifact-manifest.yml nested_governance.declared_vendors.path",
        )

    _validate_audit_root_policy(
        repo_root, manifest, root_paths=root_paths, vendor_prefixes=vendor_prefixes
    )
    _validate_nested_governance_policy(repo_root, manifest, vendor_prefixes=vendor_prefixes)
    _validate_vendored_artifacts(repo_root, manifest)
    _validate_phase_retention_policy(repo_root, manifest)
    _validate_context_budgets(repo_root, manifest)
    _validate_declared_test_roots(repo_root, agents)
    _validate_ephemeral_evidence_references(repo_root, manifest)
    return [repo_root / root_path for root_path in root_paths.values()]

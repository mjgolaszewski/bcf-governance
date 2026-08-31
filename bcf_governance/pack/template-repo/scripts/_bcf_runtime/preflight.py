"""Run deterministic, cheap release or PR checks before evidence and expense."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Callable, Mapping

import yaml  # type: ignore[import-untyped]

from .evidence_execution import _selected_python
from .evidence_sessions import (
    EvidenceSession,
    allocate_session,
    local_producer_identity,
)
from .governance_validation.runner import validate_repo_root
from .semantic_ownership_scan import run_scan as run_semantic_ownership_scan
from .test_manifests import check_all


class PreflightError(ValueError):
    """Raised before evidence or expensive gates when deterministic state is invalid."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise PreflightError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo_root, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise PreflightError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def _tracked_files(repo_root: Path) -> list[Path]:
    output = subprocess.run(
        ["git", "ls-files", "-z"], cwd=repo_root, capture_output=True, check=True
    ).stdout
    return [
        repo_root / value.decode("utf-8")
        for value in output.split(b"\0")
        if value and (repo_root / value.decode("utf-8")).is_file()
    ]


def _git_state(repo_root: Path) -> dict[str, Any]:
    status_value = _git(
        repo_root, "status", "--porcelain=v1", "--untracked-files=all", "--ignored=no"
    )
    if status_value:
        raise PreflightError("preflight requires a clean committed HEAD")
    commit = _git(repo_root, "rev-parse", "HEAD")
    tree = _git(repo_root, "rev-parse", "HEAD^{tree}")
    root = repo_root.resolve()
    for line in _git(repo_root, "ls-files", "-s").splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) != 4 or fields[0] != "120000":
            continue
        relative = Path(fields[3])
        link = repo_root / relative
        target = Path(os.readlink(link))
        resolved = target if target.is_absolute() else (link.parent / target).resolve()
        if target.is_absolute() or not resolved.is_relative_to(root):
            raise PreflightError(f"tracked symlink escapes governed tree: {relative}")
    return {
        "commit_sha": commit,
        "tree_sha": tree,
        "status_porcelain_sha256": hashlib.sha256(status_value.encode()).hexdigest(),
    }


def _syntax_checks(repo_root: Path) -> dict[str, int]:
    counts = {"python": 0, "yaml": 0, "json": 0, "shell": 0}
    for path in _tracked_files(repo_root):
        relative = path.relative_to(repo_root).as_posix()
        try:
            if path.suffix == ".py":
                ast.parse(path.read_text(encoding="utf-8"), filename=relative)
                counts["python"] += 1
            elif path.suffix in {".yml", ".yaml"}:
                yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
                counts["yaml"] += 1
            elif path.suffix == ".json":
                json.loads(path.read_text(encoding="utf-8"))
                counts["json"] += 1
            elif path.suffix == ".sh":
                result = subprocess.run(
                    ["bash", "-n", str(path)], capture_output=True, text=True, check=False
                )
                if result.returncode != 0:
                    raise PreflightError(
                        f"shell syntax failed for {relative}: {result.stderr.strip()}"
                    )
                counts["shell"] += 1
        except (SyntaxError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
            raise PreflightError(f"syntax validation failed for {relative}: {exc}") from exc
    return counts


def _vendored_source_locks(repo_root: Path) -> int:
    manifest = yaml.safe_load(
        (repo_root / "governance/artifact-manifest.yml").read_text(encoding="utf-8")
    )
    vendored = manifest.get("vendored_artifacts", {}) if isinstance(manifest, dict) else {}
    artifacts = vendored.get("artifacts", []) if isinstance(vendored, dict) else []
    if not isinstance(artifacts, list):
        raise PreflightError("vendored artifact source-lock registry is invalid")
    for raw in artifacts:
        if not isinstance(raw, dict):
            raise PreflightError("vendored artifact source-lock entry is invalid")
        relative = raw.get("artifact_path")
        expected = raw.get("artifact_sha256")
        if (
            not isinstance(relative, str)
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
        ):
            raise PreflightError("vendored artifact source-lock path is unsafe")
        path = repo_root / relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise PreflightError(f"vendored artifact source lock mismatched: {relative}")
    return len(artifacts)


def _required_gates(repo_root: Path) -> list[str]:
    profile = yaml.safe_load(
        (repo_root / "governance-profile.yml").read_text(encoding="utf-8")
    )
    release = profile.get("release_gate_profile") if isinstance(profile, dict) else None
    gates = release.get("gates") if isinstance(release, dict) else None
    if not isinstance(gates, dict):
        raise PreflightError("governance profile has no release gate inventory")
    targets = sorted(
        str(value.get("target"))
        for value in gates.values()
        if isinstance(value, dict)
        and value.get("status") == "required"
        and isinstance(value.get("target"), str)
    )
    if not targets:
        raise PreflightError("governance profile has no required gates")
    return targets


def _negative_control_targets(repo_root: Path) -> int:
    """Fail cheaply when a declared control no longer targets canonical source."""
    registry_path = repo_root / "governance/gate-contracts.yml"
    registry = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    gates = registry.get("gates") if isinstance(registry, dict) else None
    if not isinstance(gates, dict):
        raise PreflightError("gate contract registry has no gate mappings")
    ledger: dict[str, Any] | None = None
    checked = 0
    root = repo_root.resolve()
    for gate_id, gate in gates.items():
        controls = gate.get("negative_controls") if isinstance(gate, dict) else None
        if not isinstance(controls, list):
            continue
        for control in controls:
            if not isinstance(control, dict) or not isinstance(control.get("mutation"), dict):
                raise PreflightError(f"negative control is invalid: {gate_id}")
            control_id = str(control.get("id", gate_id))
            mutation = control["mutation"]
            relative_value = mutation.get("path")
            if relative_value == "@active_phase_log":
                if ledger is None:
                    ledger_value = yaml.safe_load(
                        (repo_root / "plans/phase-ledger.yml").read_text(encoding="utf-8")
                    )
                    ledger = ledger_value if isinstance(ledger_value, dict) else {}
                active = ledger.get("active_phase")
                relative_value = active.get("log") if isinstance(active, dict) else None
            if not isinstance(relative_value, str):
                raise PreflightError(f"negative control target is missing: {control_id}")
            relative = Path(relative_value)
            if relative.is_absolute() or ".." in relative.parts:
                raise PreflightError(f"negative control target is unsafe: {control_id}")
            target = repo_root / relative
            if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(root):
                raise PreflightError(f"negative control target is absent: {control_id}")
            if _git(repo_root, "ls-files", "--error-unmatch", relative.as_posix()) != relative.as_posix():
                raise PreflightError(f"negative control target is untracked: {control_id}")
            search = mutation.get("search")
            if isinstance(search, str):
                occurrences = target.read_text(encoding="utf-8").count(search)
                if occurrences == 0:
                    raise PreflightError(
                        f"negative control target is stale: {control_id}"
                    )
            else:
                yaml_path = mutation.get("yaml_path")
                if not isinstance(yaml_path, str) or "value" not in mutation:
                    raise PreflightError(f"negative control mutation is unsupported: {control_id}")
                current: Any = yaml.safe_load(target.read_text(encoding="utf-8"))
                try:
                    for token in yaml_path.split("."):
                        current = current[int(token)] if isinstance(current, list) else current[token]
                except (KeyError, IndexError, TypeError, ValueError) as exc:
                    raise PreflightError(
                        f"negative control YAML target is stale: {control_id}"
                    ) from exc
                if current == mutation["value"]:
                    raise PreflightError(
                        f"negative control YAML target is already mutated: {control_id}"
                    )
            checked += 1
    return checked


def _semantic_ownership(repo_root: Path) -> dict[str, Any]:
    registry = repo_root / "governance/canonical-representations.yml"
    if not registry.is_file():
        return {"status": "not_applicable", "blocking_violation_count": 0}
    report = run_semantic_ownership_scan(repo_root)
    if report.get("verdict") != "conformant":
        violations = report.get("violations")
        first = violations[0] if isinstance(violations, list) and violations else {}
        detail = (
            f"{first.get('kind', 'unknown')}:{first.get('symbol', 'unknown')}"
            if isinstance(first, dict)
            else "unknown"
        )
        raise PreflightError(f"semantic ownership preflight failed: {detail}")
    return {
        "status": "conformant",
        "blocking_violation_count": int(report.get("blocking_violation_count", 0)),
    }


def _pr_context(repo_root: Path, mode: str) -> dict[str, Any]:
    if mode != "pr":
        return {"applicable": False}
    base = os.environ.get("BCF_PR_BASE_SHA", "")
    if not re.fullmatch(r"[a-f0-9]{40,64}", base):
        raise PreflightError("PR preflight requires exact BCF_PR_BASE_SHA")
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", base, "HEAD"],
        cwd=repo_root,
        check=False,
    )
    if result.returncode != 0:
        raise PreflightError("PR base SHA is not an ancestor of HEAD")
    return {"applicable": True, "base_sha": base}


def run_preflight(
    repo_root: Path,
    *,
    mode: str,
    python_executable: str | Path | None = None,
    artifact_root: Path | None = None,
    expected_producers: list[str] | None = None,
    producer_identity: Mapping[str, str] | None = None,
    trace: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Validate deterministic state, then optionally seed one fresh session."""
    if mode not in {"release", "pr"}:
        raise PreflightError("preflight mode must be release or pr")
    repo_root = repo_root.resolve()
    python = _selected_python(python_executable)

    def step(name: str, operation: Callable[[], Any]) -> Any:
        if trace is not None:
            trace(name)
        return operation()

    subject = step("git-state", lambda: _git_state(repo_root))
    syntax = step("syntax", lambda: _syntax_checks(repo_root))
    step("governance", lambda: validate_repo_root(repo_root))
    negative_controls = step(
        "negative-controls", lambda: _negative_control_targets(repo_root)
    )
    semantic_ownership = step(
        "semantic-ownership", lambda: _semantic_ownership(repo_root)
    )
    source_locks = step("source-locks", lambda: _vendored_source_locks(repo_root))
    test_manifests = step(
        "test-manifests", lambda: check_all(repo_root, python_executable=python)
    )
    pr_context = step("pr-context", lambda: _pr_context(repo_root, mode))
    session: EvidenceSession | None = None
    if artifact_root is not None:
        session = step(
            "session",
            lambda: allocate_session(
                repo_root,
                artifact_root,
                _required_gates(repo_root),
                expected_producers=(
                    expected_producers
                    or [os.environ.get("GITHUB_JOB", "local")]
                ),
                producer_identity=producer_identity,
            ),
        )
    return {
        "status": "pass",
        "mode": mode,
        "subject": subject,
        "syntax": syntax,
        "source_locks": source_locks,
        "negative_controls": negative_controls,
        "test_manifests": test_manifests,
        "pr_context": pr_context,
        "selected_interpreter": {"name": python.name},
        "semantic_ownership": semantic_ownership,
        "session_manifest": (
            session.manifest_path.relative_to(repo_root).as_posix()
            if session and session.manifest_path.is_relative_to(repo_root)
            else session.manifest_path.as_posix() if session else None
        ),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run cheap governance preflight.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--mode", choices=("release", "pr"), required=True)
    parser.add_argument("--python", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--expected-producer", action="append")
    parser.add_argument("--local-producer-id")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        report = run_preflight(
            args.repo_root,
            mode=args.mode,
            python_executable=args.python,
            artifact_root=args.artifact_root,
            expected_producers=args.expected_producer,
            producer_identity=(
                local_producer_identity(args.repo_root, args.local_producer_id)
                if args.local_producer_id
                else None
            ),
        )
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"preflight-ok mode={report['mode']} commit={report['subject']['commit_sha']}")
        if report["session_manifest"]:
            print(report["session_manifest"])


if __name__ == "__main__":
    main()

"""Run deterministic, cheap release or PR checks before evidence and expense."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import runpy
import subprocess
from pathlib import Path
from typing import Any, Callable, Mapping

import yaml  # type: ignore[import-untyped]

from .evidence_execution import _selected_python
from .evidence_planning import load_prior_receipts, verification_plan as build_verification_plan
from .evaluation_scope import EvaluationIntent, evaluation_scope
from .ci_authority_pins import CIAuthorityPinError, verify_workflow_authority
from .ci_github_identity import GitHubControllerError
from .ci_self_controller import verify_self_controller_projection
from .check_governance_exposure import scan_exposures
from .evidence_sessions import (
    EvidenceSession,
    allocate_session,
    local_producer_identity,
)
from .governance_validation.runner import check_editorial, validate_repo_root
from .governance_validation.structural_limits import validate_structural_limits
from .install_governance_pack import _pack_manifest_entries
from .interpreter_environment import (
    InterpreterEnvironmentError,
    derive_interpreter_environment,
    validate_runtime_import_dependencies,
    verify_interpreter_environment_projection,
)
from .prior_evidence_receipts import load_provisional_transport, provisional_receipts
from .governance_validation.preflight_negative_controls import (
    NegativeControlPreflightError,
    inspect_negative_control_targets,
    stale_negative_control_oracles,
)
from .semantic_ownership_scan import run_scan as run_semantic_ownership_scan
from .self_workflow_contracts import (
    SelfWorkflowContractError,
    validate_self_workflow_contracts,
)
from .test_manifests import check_all
from .trusted_controller_compatibility import (
    TrustedControllerCompatibilityError,
    TrustedControllerRoutineRotationIncompatibleError,
    TrustedControllerRuntimeStaleError,
    ordinary_alternate_lane_available,
    verify_pr_bootstrap_compatibility,
    verify_trusted_controller_compatibility,
)


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


def _exposure_scan(repo_root: Path) -> dict[str, int]:
    """Reject local paths and private infrastructure markers at the front door."""

    report = scan_exposures(repo_root)
    if report.status != "pass":
        finding = report.findings[0]
        raise PreflightError(
            "governance exposure preflight failed: "
            f"{finding.path}:{finding.line}:{finding.pattern}"
        )
    return {"scanned_files": report.scanned_files, "findings": 0}


def _module_time_bcf_imports(tree: ast.Module) -> list[ast.Import | ast.ImportFrom]:
    """Return package imports that execute while a source entrypoint starts."""

    imports: list[ast.Import | ast.ImportFrom] = []

    def visit(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return
        if isinstance(node, ast.Import):
            if any(alias.name == "bcf_governance" or alias.name.startswith("bcf_governance.") for alias in node.names):
                imports.append(node)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "bcf_governance" or (node.module or "").startswith("bcf_governance."):
                imports.append(node)
        for child in ast.iter_child_nodes(node):
            visit(child)

    for statement in tree.body:
        visit(statement)
    return imports


def _source_entrypoint_authority(repo_root: Path) -> dict[str, int]:
    """Require source entrypoints to establish their checkout before package imports."""

    roots = {"scripts": 1, ".github/scripts": 2}
    discovered = 0
    checked = 0
    for path in _tracked_files(repo_root):
        relative = path.relative_to(repo_root)
        if path.suffix != ".py" or relative.parent not in {
            Path(prefix) for prefix in roots
        }:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative.as_posix())
        if not any(
            isinstance(node, ast.If)
            and any(
                isinstance(value, ast.Constant) and value.value == "__main__"
                for value in ast.walk(node.test)
            )
            for node in tree.body
        ):
            continue
        discovered += 1
        imports = _module_time_bcf_imports(tree)
        if not imports:
            continue
        first_import_line = min(node.lineno for node in imports)
        prefix = ".github/scripts" if relative.is_relative_to(Path(".github/scripts")) else "scripts"
        expected_root = f"Path(__file__).resolve().parents[{roots[prefix]}]"
        root_names = {
            target.id
            for node in tree.body
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            and node.lineno < first_import_line
            and (value := getattr(node, "value", None)) is not None
            and ast.unparse(value) == expected_root
            for target in (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
            if isinstance(target, ast.Name)
        }
        authorized = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or node.lineno >= first_import_line:
                continue
            if ast.unparse(node.func) != "sys.path.insert" or len(node.args) < 2:
                continue
            if not isinstance(node.args[0], ast.Constant) or node.args[0].value != 0:
                continue
            source = ast.unparse(node.args[1])
            allowed = {f"str({expected_root})", *(f"str({name})" for name in root_names)}
            if source in allowed:
                authorized = True
                break
        if not authorized:
            raise PreflightError(
                "source entrypoint imports bcf_governance before establishing its "
                f"repository root: {relative.as_posix()}"
            )
        checked += 1
    return {"discovered": discovered, "package_imports_checked": checked}


def _interpreter_identity(python: Path) -> dict[str, str]:
    """Prove the selected executable and any lexical virtual environment agree."""

    probe = (
        "import json,platform,sys\n"
        "print(json.dumps({'executable':sys.executable,'prefix':sys.prefix,"
        "'base_prefix':sys.base_prefix,'python_version':platform.python_version()},"
        "sort_keys=True))\n"
    )
    try:
        result = subprocess.run(
            [str(python), "-I", "-c", probe],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PreflightError("selected interpreter identity probe failed") from exc
    if result.returncode:
        raise PreflightError(
            "selected interpreter is not runnable: "
            + (result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "unknown")
        )
    try:
        identity = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise PreflightError("selected interpreter identity probe was invalid") from exc
    if not isinstance(identity, dict) or not all(
        isinstance(identity.get(key), str)
        for key in ("executable", "prefix", "base_prefix", "python_version")
    ):
        raise PreflightError("selected interpreter identity is incomplete")
    lexical = Path(os.path.abspath(python))
    if Path(identity["executable"]) != lexical:
        raise PreflightError("selected interpreter changed executable identity")
    environment_root = lexical.parent.parent
    venv_config = environment_root / "pyvenv.cfg"
    claims_venv = ".venv" in lexical.parts or os.environ.get("VIRTUAL_ENV") is not None
    if claims_venv and not venv_config.is_file():
        raise PreflightError("selected virtual environment has no pyvenv.cfg")
    if venv_config.is_file():
        config: dict[str, str] = {}
        for line in venv_config.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                config[key.strip().lower()] = value.strip()
        if Path(identity["prefix"]) != environment_root:
            raise PreflightError("selected virtual environment prefix is inconsistent")
        if identity["base_prefix"] == identity["prefix"]:
            raise PreflightError("selected virtual environment is not isolated from base Python")
        if config.get("include-system-site-packages", "false").lower() != "false":
            raise PreflightError("selected virtual environment exposes system site packages")
        declared = os.environ.get("VIRTUAL_ENV")
        if declared and Path(os.path.abspath(declared)) != environment_root:
            raise PreflightError("VIRTUAL_ENV does not identify the selected interpreter")
        identity["environment_kind"] = "virtualenv"
        identity["environment_root"] = str(environment_root)
    else:
        identity["environment_kind"] = "standalone"
        identity["environment_root"] = identity["prefix"]
    return {str(key): str(value) for key, value in sorted(identity.items())}


def _interpreter_requirements(repo_root: Path, python: Path) -> dict[str, Any]:
    """Verify selected environment identity and versions before evidence."""

    try:
        validate_runtime_import_dependencies(repo_root)
        plan = derive_interpreter_environment(repo_root)
        if plan is not None:
            verify_interpreter_environment_projection(plan)
    except InterpreterEnvironmentError as exc:
        raise PreflightError(str(exc)) from exc
    if plan is None:
        return {}
    identity = _interpreter_identity(python)
    probe = (
        "import importlib.metadata as m,json,platform,sys\n"
        "from packaging.requirements import Requirement\n"
        "from packaging.specifiers import SpecifierSet\n"
        "requirements=json.loads(sys.argv[1])\n"
        "versions={}\n"
        "for raw in requirements:\n"
        " req=Requirement(raw)\n"
        " if req.marker is not None and not req.marker.evaluate(): continue\n"
        " installed=m.version(req.name)\n"
        " if req.specifier and not req.specifier.contains(installed,prereleases=True):\n"
        "  raise SystemExit(f'{req.name} {installed} violates {req.specifier}')\n"
        " versions[req.name]=installed\n"
        "python_spec=SpecifierSet(sys.argv[2])\n"
        "python_version=platform.python_version()\n"
        "if not python_spec.contains(python_version,prereleases=True):\n"
        " raise SystemExit(f'Python {python_version} violates {python_spec}')\n"
        "print(json.dumps(versions,sort_keys=True))\n"
    )
    try:
        result = subprocess.run(
            [
                str(python),
                "-I",
                "-c",
                probe,
                json.dumps(list(plan.requirements)),
                plan.requires_python,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PreflightError("selected interpreter dependency probe failed") from exc
    if result.returncode:
        diagnostic = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "unknown"
        raise PreflightError(
            "selected interpreter dependency contract failed: " + diagnostic
        )
    try:
        versions = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise PreflightError("selected interpreter dependency probe was invalid") from exc
    if not isinstance(versions, dict) or {
        re.sub(r"[-_.]+", "-", value).lower() for value in versions
    } != set(plan.distribution_names):
        raise PreflightError("selected interpreter dependency inventory is incomplete")
    return {
        "identity": identity,
        "versions": {str(key): str(value) for key, value in sorted(versions.items())},
    }


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


def _workflow_authority(repo_root: Path) -> int:
    if not (repo_root / "governance/ci-authority.yml").is_file():
        return 0
    try:
        return verify_workflow_authority(
            repo_root, authority_path=Path("governance/ci-authority.yml")
        )
    except CIAuthorityPinError as exc:
        raise PreflightError(f"workflow authority preflight failed: {exc}") from exc


def _self_controller(
    repo_root: Path, *, allow_stale_runtime: bool = False,
    pr_base_sha: str | None = None,
    transported_authority: Mapping[str, Any] | None = None,
) -> int | dict[str, Any]:
    policy = repo_root / "governance/self-governance-policy.yml"
    if not policy.is_file():
        return 0
    payload = yaml.safe_load(policy.read_text(encoding="utf-8"))
    runner = payload.get("runner_security") if isinstance(payload, dict) else None
    if not isinstance(runner, dict) or "trusted_controller_artifact" not in runner:
        return 0
    try:
        count = verify_self_controller_projection(repo_root)
        target = str(runner["trusted_controller_artifact"]["BCF_BOOTSTRAP_COMMIT_SHA"])
        if transported_authority is not None:
            transported_commit = transported_authority.get("controller_commit_sha")
            transported_bundle = transported_authority.get("controller_bundle_sha256")
            if (
                set(transported_authority) != {
                    "controller_commit_sha", "controller_bundle_sha256"
                }
                or not isinstance(transported_commit, str)
                or not re.fullmatch(r"[a-f0-9]{40}", transported_commit)
                or not isinstance(transported_bundle, str)
                or not re.fullmatch(r"[a-f0-9]{64}", transported_bundle)
            ):
                raise TrustedControllerCompatibilityError(
                    "transported controller authority is invalid"
                )
            target = transported_commit
        if pr_base_sha is not None:
            verify_pr_bootstrap_compatibility(
                repo_root, base_commit=pr_base_sha, target_commit=target
            )
        try:
            verify_trusted_controller_compatibility(
                repo_root, target_commit=target
            )
        except TrustedControllerRoutineRotationIncompatibleError:
            if not allow_stale_runtime or not ordinary_alternate_lane_available(
                repo_root
            ):
                raise
            return {
                "status": "pending_rotation",
                "projection_count": count,
                "transition_requirement": "alternate_lane_required",
                "release_authority": False,
            }
        except TrustedControllerRuntimeStaleError:
            if not allow_stale_runtime:
                raise
            return {
                "status": "pending_rotation",
                "projection_count": count,
                "release_authority": False,
            }
        return count
    except (GitHubControllerError, KeyError, TypeError, TrustedControllerCompatibilityError) as exc:
        raise PreflightError(f"self-controller preflight failed: {exc}") from exc


def _self_workflows(repo_root: Path) -> int:
    if not (repo_root / "governance/self-governance-policy.yml").is_file():
        return 0
    try:
        return validate_self_workflow_contracts(repo_root)
    except SelfWorkflowContractError as exc:
        raise PreflightError(f"self-workflow preflight failed: {exc}") from exc


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
    try:
        stale_oracles = stale_negative_control_oracles(repo_root)
        if stale_oracles:
            raise PreflightError(
                "negative control oracle nodes are stale: " + ", ".join(stale_oracles)
            )
        declared = inspect_negative_control_targets(repo_root, git=_git)
        mutant_path = repo_root / ".github/scripts/run_validator_mutants.py"
        if not mutant_path.is_file():
            return declared
        mutant_contract = runpy.run_path(str(mutant_path))
        validator = mutant_contract.get("validate_mutant_targets")
        if not callable(validator):
            raise PreflightError("scheduled mutant contract has no canonical validator")
        scheduled = validator()
        return declared + int(scheduled)
    except (NegativeControlPreflightError, RuntimeError) as exc:
        raise PreflightError(str(exc)) from exc


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


def _pack_manifest(repo_root: Path) -> dict[str, Any]:
    """Verify BCF's generated pack bytes before package or evidence work."""

    template_root = repo_root / "bcf_governance/pack/template-repo"
    if not template_root.is_dir():
        return {"applicable": False}
    try:
        entries = _pack_manifest_entries(template_root)
    except ValueError as exc:
        raise PreflightError(str(exc)) from exc
    return {"applicable": True, "file_count": len(entries)}


def run_preflight(
    repo_root: Path,
    *,
    mode: str,
    python_executable: str | Path | None = None,
    artifact_root: Path | None = None,
    expected_producers: list[str] | None = None,
    producer_identity: Mapping[str, str] | None = None,
    evaluation_mode: str | None = None,
    evaluation_target: str | None = None,
    prior_receipts: list[Mapping[str, Any]] | None = None,
    prior_transport_dir: Path | None = None,
    trace: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Validate deterministic state, then optionally seed one fresh session."""
    if mode not in {"release", "pr"}:
        raise PreflightError("preflight mode must be release or pr")
    selected_mode = evaluation_mode or "pr"
    if selected_mode in {"workitem", "closure"} and mode != "release":
        raise PreflightError("main evaluation requires release preflight mode")
    repo_root = repo_root.resolve()
    python = _selected_python(python_executable)

    def step(name: str, operation: Callable[[], Any]) -> Any:
        if trace is not None:
            trace(name)
        return operation()

    subject = step("git-state", lambda: _git_state(repo_root))
    structural_limits = step(
        "structural-limits", lambda: validate_structural_limits(repo_root)
    )
    transported_authority: Mapping[str, Any] | None = None
    if prior_transport_dir is not None:
        if prior_receipts:
            raise PreflightError("prior transport and legacy receipt inputs are ambiguous")
        material = step(
            "prior-transport",
            lambda: load_provisional_transport(
                repo_root, prior_transport_dir, current_subject=subject,
            ),
        )
        prior_receipts = provisional_receipts(material)
        transported_authority = material.manifest["authority"]
    try:
        scope = evaluation_scope(
            selected_mode,
            target=evaluation_target or None,
            phase_id="PREFLIGHT",
            subject_commit="PREFLIGHT",
        )
    except ValueError as exc:
        raise PreflightError(str(exc)) from exc
    syntax = step("syntax", lambda: _syntax_checks(repo_root))
    exposure = step("exposure", lambda: _exposure_scan(repo_root))
    interpreter = step(
        "interpreter", lambda: _interpreter_requirements(repo_root, python)
    )
    source_entrypoints = step(
        "source-entrypoints", lambda: _source_entrypoint_authority(repo_root)
    )
    step("governance", lambda: validate_repo_root(repo_root))
    closure_authoring = {
        "requested": scope.intent is EvaluationIntent.PHASE_CLOSURE,
        "execution_trigger": False,
        "state": "derived_from_authenticated_truth",
    }
    self_workflows = step("self-workflows", lambda: _self_workflows(repo_root))
    workflow_authority = step(
        "workflow-authority", lambda: _workflow_authority(repo_root)
    )
    pr_context = step("pr-context", lambda: _pr_context(repo_root, mode))
    self_controller = step(
        "self-controller",
        lambda: _self_controller(
            repo_root,
            allow_stale_runtime=mode == "pr",
            pr_base_sha=(
                str(pr_context["base_sha"])
                if pr_context.get("applicable") is True
                else None
            ),
            transported_authority=transported_authority,
        ),
    )
    negative_controls = step(
        "negative-controls", lambda: _negative_control_targets(repo_root)
    )
    semantic_ownership = step(
        "semantic-ownership", lambda: _semantic_ownership(repo_root)
    )
    source_locks = step("source-locks", lambda: _vendored_source_locks(repo_root))
    pack_manifest = step("pack-manifest", lambda: _pack_manifest(repo_root))
    editorial_contract = step("editorial-contract", lambda: check_editorial(repo_root, python))
    test_manifests = step(
        "test-manifests", lambda: check_all(repo_root, python_executable=python)
    )
    verification_plan = step(
        "verification-plan",
        lambda: build_verification_plan(repo_root, subject, prior_receipts or []),
    )
    session: EvidenceSession | None = None
    if artifact_root is not None:
        planned_producers = [
            str(node["producer"])
            for node in verification_plan["execution_dag"]["nodes"]
        ]
        session = step(
            "session",
            lambda: allocate_session(
                repo_root,
                artifact_root,
                planned_producers,
                expected_producers=(
                    expected_producers
                    or [os.environ.get("GITHUB_JOB", "local")]
                ),
                producer_identity=producer_identity,
                verification_plan=verification_plan,
            ),
        )
    return {
        "status": "pass",
        "mode": mode,
        "subject": subject,
        "structural_limits": structural_limits,
        "syntax": syntax,
        "exposure": exposure,
        "interpreter": interpreter,
        "source_entrypoints": source_entrypoints,
        "source_locks": source_locks,
        "pack_manifest": pack_manifest,
        "editorial_contract": editorial_contract,
        "self_workflows": self_workflows,
        "workflow_authority": workflow_authority,
        "self_controller": self_controller,
        "negative_controls": negative_controls,
        "test_manifests": test_manifests,
        "pr_context": pr_context,
        "selected_interpreter": {"name": python.name},
        "semantic_ownership": semantic_ownership,
        "closure_authoring": closure_authoring,
        "verification_plan": verification_plan,
        "session_manifest": (
            session.manifest_path.relative_to(repo_root).as_posix()
            if session and session.manifest_path.is_relative_to(repo_root)
            else session.manifest_path.as_posix() if session else None
        ),
    }


def preflight_mode_for_evaluation(evaluation_mode: str | None) -> str:
    """Derive the preflight authority boundary from one effective intent."""

    try:
        intent = EvaluationIntent(evaluation_mode or "pr")
    except ValueError as exc:
        raise PreflightError("evaluation mode must be pr, workitem, or closure")
    return "pr" if intent is EvaluationIntent.PR_PROGRESS else "release"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run cheap governance preflight.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--mode", choices=("release", "pr"))
    parser.add_argument("--evaluation-mode", choices=("pr", "workitem", "closure"))
    parser.add_argument("--evaluation-target")
    parser.add_argument("--python", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--expected-producer", action="append")
    parser.add_argument("--local-producer-id")
    parser.add_argument("--prior-evidence-dir", type=Path)
    parser.add_argument("--prior-evidence-digest")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        prior_receipts = (
            load_prior_receipts(
                args.repo_root, args.prior_evidence_dir, args.prior_evidence_digest
            ) if args.prior_evidence_digest else []
        )
        report = run_preflight(
            args.repo_root,
            mode=args.mode or preflight_mode_for_evaluation(args.evaluation_mode),
            python_executable=args.python,
            artifact_root=args.artifact_root,
            expected_producers=args.expected_producer,
            evaluation_mode=args.evaluation_mode,
            evaluation_target=args.evaluation_target,
            producer_identity=(
                local_producer_identity(args.repo_root, args.local_producer_id)
                if args.local_producer_id
                else None
            ),
            prior_receipts=prior_receipts,
            prior_transport_dir=(
                args.prior_evidence_dir if args.prior_evidence_digest is None else None
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

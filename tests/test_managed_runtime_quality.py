"""Characterize preserved runtime contracts and native quality gate failures."""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOTFIX_FUNCTION_AST_SHA256 = {'_phase_hotfix_paths_by_phase': '56fcaa947aa7c9e7b5593a651571dc75e8e0a14d0da899e2e0106635475c1fa9', '_validate_hotfix_log': 'cc2ac2174ae4b9faa16bacc086a0be12eeb0588b17f0662ddd1dd808b25b3d12', '_validate_hotfix_lane': '09d1eaaad1df5d901c95de48140a0393e69227b9497d41376b0c1e10622067fd'}



def _portable_ast_sha256(node: ast.AST) -> str:
    normalized = copy.deepcopy(node)
    # Python 3.12 added empty generic-parameter fields; retain that source shape
    # when the supported Python 3.11 parser has no such field yet.
    for item in ast.walk(normalized):
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if "type_params" not in item._fields:
                item._fields = (*item._fields, "type_params")
                setattr(item, "type_params", [])
    if sys.version_info >= (3, 13):
        rendered = ast.dump(normalized, include_attributes=False, show_empty=True)
    else:
        rendered = ast.dump(normalized, include_attributes=False)
    return hashlib.sha256(rendered.encode()).hexdigest()


def test_hotfix_function_bodies_keep_exact_characterized_ast() -> None:
    directory = ROOT / "bcf_governance/tooling/governance_validation"
    owners = [directory / "phase_catalog.py", directory / "hotfix_validation.py"]
    found = {}
    for path in owners:
        if not path.exists():
            continue
        for node in ast.parse(path.read_text()).body:
            if isinstance(node, ast.FunctionDef) and node.name in HOTFIX_FUNCTION_AST_SHA256:
                assert node.name not in found, "hotfix function has duplicate owners"
                found[node.name] = _portable_ast_sha256(node)
    assert found == HOTFIX_FUNCTION_AST_SHA256


def test_wrappers_keep_runtime_import_and_expose_the_same_static_target() -> None:
    wrappers = ROOT / "template-repo/scripts"
    checked = 0
    for path in sorted(wrappers.glob("*.py")):
        tree = ast.parse(path.read_text())
        choices = [node for node in tree.body if isinstance(node, ast.If)
                   and isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING"]
        if not choices:
            continue
        assert len(choices) == 1
        static, = choices[0].body
        runtime, = choices[0].orelse
        assert isinstance(static, ast.ImportFrom) and isinstance(runtime, ast.ImportFrom)
        assert static.level == 1 and runtime.level == 0
        assert static.module == runtime.module
        assert runtime.module is not None and runtime.module.startswith("_bcf_runtime")
        assert [(name.name, name.asname) for name in static.names] == [
            (name.name, name.asname) for name in runtime.names
        ]
        assert len(path.read_text().splitlines()) < 20
        checked += 1
    assert checked == 14


def test_observation_validator_has_a_resolvable_json_dependency(tmp_path: Path) -> None:
    from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source

    source = (ROOT / "bcf_governance/tooling/operational_observations.py").read_text()
    clean = tmp_path / "clean.py"
    dynamic = tmp_path / "dynamic.py"
    clean.write_text(source)
    assert "schema = json.loads(" in source
    dynamic.write_text(source.replace("schema = json.loads(", 'schema = __import__("json").loads('))
    clean_inventory = discover_python_source(tmp_path, files=[clean])
    dynamic_inventory = discover_python_source(tmp_path, files=[dynamic])
    assert clean_inventory["unresolved"] == []
    assert len(dynamic_inventory["unresolved"]) == 1


ADDITIONAL_SPLIT_CHARACTERIZATION = [{'parent': 'preflight.py', 'child': 'governance_validation/preflight_imports.py', 'functions': {'_module_time_bcf_imports': 'e58f352ecde4f26455e7101534d535a0bc0d4fbeb72f41c908b5f4353e85c227'}}, {'parent': 'governance_evidence.py', 'child': 'evidence_output_artifacts.py', 'functions': {'_sha256': '59397cf9f747263caf0fd7b8bd8343e939ee4181ed49d916a0d771fc1a2146cb', '_write_output_artifacts': '6e8b5637027d36f974d5667cc4c61abae19b738838493cbf012e1398c2402582'}}]

def test_additional_splits_preserve_function_ast_and_unique_owner() -> None:
    root = ROOT / "bcf_governance/tooling"
    for case in ADDITIONAL_SPLIT_CHARACTERIZATION:
        found = {}
        for relative in (case["parent"], case["child"]):
            path = root / relative
            if not path.exists():
                continue
            for node in ast.parse(path.read_text()).body:
                if isinstance(node, ast.FunctionDef) and node.name in case["functions"]:
                    assert node.name not in found
                    found[node.name] = _portable_ast_sha256(node)
        assert found == case["functions"]


def test_string_enums_preserve_existing_string_and_format_contract() -> None:
    from bcf_governance.tooling.ci_github_downloads import GitHubDownloadKind
    from bcf_governance.tooling.ci_graph_controller_lifecycle import (
        ControllerLifecycleState, ControllerRequirement,
    )
    from bcf_governance.tooling.governance_validation.audit_artifacts import AuditArtifactKind
    from bcf_governance.tooling.local_pr_context import LocalValidationLane

    for enum in (GitHubDownloadKind, ControllerLifecycleState, ControllerRequirement,
                 AuditArtifactKind, LocalValidationLane):
        for member in enum:
            assert str(member) == f"{enum.__name__}.{member.name}"
            assert format(member, ">60") == format(str(member), ">60")
            assert member == member.value
            assert hash(member) == hash(member.value)
            assert enum(member.value) is member
            assert json.loads(json.dumps(member)) == member.value


def test_native_quality_gates_reject_tool_failure(monkeypatch) -> None:
    import runpy
    import subprocess

    import pytest

    namespace = runpy.run_path(str(ROOT / ".github/scripts/run_self_governance_gate.py"))
    for gate, tool in (("lint", "ruff"), ("typecheck", "mypy")):
        entrypoint = namespace[f"_{gate}"]
        entrypoint.__globals__["_tracked_files"] = lambda: []
        observed = []

        def failing_tool(command, **kwargs):
            observed.append(command)
            return subprocess.CompletedProcess(command, 1 if tool in command else 0)

        with monkeypatch.context() as patch:
            patch.setattr(subprocess, "run", failing_tool)
            with pytest.raises(SystemExit) as failure:
                entrypoint(gate)
        assert failure.value.code == 1
        assert any(tool in command for command in observed)


def test_ast_characterization_detects_changed_function_body() -> None:
    original = ast.parse("def function():\n    return 1\n").body[0]
    changed = ast.parse("def function():\n    return 2\n").body[0]
    assert _portable_ast_sha256(original) != _portable_ast_sha256(changed)


PREFLIGHT_IDENTITY_GOLDENS = {'PreflightError': '760f98bf526de9e5a8f990906cc99483c84bc4f869cea3cdf994a9fc9be5d183', '_interpreter_identity': '89d5d7db1739a38c953dfb7360409411e4ffa7e5cb02413a3ea12b27733f3974'}

def test_preflight_identity_responsibility_has_one_characterized_owner() -> None:
    root = ROOT / "bcf_governance/tooling"
    found = {}
    for relative in ("preflight.py", "governance_validation/preflight_interpreter.py",
                     "governance_validation/preflight_errors.py"):
        path = root / relative
        if not path.exists():
            continue
        for node in ast.parse(path.read_text()).body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in PREFLIGHT_IDENTITY_GOLDENS:
                assert node.name not in found
                normalized = copy.deepcopy(node)
                if isinstance(normalized, ast.FunctionDef):
                    assert [argument.arg for argument in normalized.args.kwonlyargs] == ["runtime_settings"]
                    assert all(isinstance(value, ast.Constant) and value.value is None
                               for value in normalized.args.kw_defaults)
                    normalized.args.kwonlyargs = []
                    normalized.args.kw_defaults = []
                    binding = normalized.body[1]
                    expected = ast.parse("runtime_settings = _default_runtime_settings() if runtime_settings is None else runtime_settings").body[0]
                    assert ast.dump(binding, include_attributes=False) == ast.dump(expected, include_attributes=False)
                    del normalized.body[1]
                    class RestoreOriginalRead(ast.NodeTransformer):
                        replacements = 0

                        def visit_Call(self, call):
                            if (isinstance(call.func, ast.Attribute)
                                and isinstance(call.func.value, ast.Name)
                                and call.func.value.id == "runtime_settings"
                                and call.func.attr == "virtual_env"):
                                assert not call.args and not call.keywords
                                self.replacements += 1
                                return ast.parse('os.environ.get("VIRTUAL_ENV")', mode="eval").body
                            return self.generic_visit(call)
                    restore = RestoreOriginalRead()
                    normalized = restore.visit(normalized)
                    assert restore.replacements == 2
                found[node.name] = _portable_ast_sha256(normalized)
    assert found == PREFLIGHT_IDENTITY_GOLDENS

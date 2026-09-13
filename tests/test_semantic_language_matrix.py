"""Complete semantic adoption for genuine single-language product consumers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

from bcf_governance.tooling import semantic_authority_commands as commands
from bcf_governance.tooling.semantic_authority_contracts import SemanticAuthorityError
from bcf_governance.tooling.semantic_ownership_scan import run_scan
from bcf_governance.tooling.semantic_source_discovery import discover_source
from semantic_typescript_fixture import dump, git, repository, write


def _contracts(root: Path, payload: dict) -> None:
    for key, name in (("semantic_families", "semantic-families"),
                      ("application_operations", "application-operations"),
                      ("canonical_representations", "canonical-representations")):
        dump(root, f"governance/{name}.yml", payload["contracts"][key])
    dump(root, "adopt.yml", payload)


def _single_language(root: Path, language: str, projection: bool) -> None:
    payload = repository(root, registry_engine=language == "typescript", typescript_family=language == "typescript")
    registry = payload["contracts"]["canonical_representations"]
    if language == "typescript":
        registry["source_authority"]["authoritative_python_roots"] = ["."]
        (root / "model.py").unlink()
    else:
        for relative in ("src", "node_modules", "declared-types"):
            shutil.rmtree(root / relative)
        for relative in ("package.json", "package-lock.json", "tsconfig.json"):
            (root / relative).unlink()
        write(root, "api.py", '__all__ = ["query"]\n\ndef query() -> int:\n    return 1\n')
        operations = payload["contracts"]["application_operations"]
        operations["populations"] = [{"id": "api", "adapter": "python_module_exports", "source": "api.py", "symbol": "__all__", "public_only": True}]
        operations["operations"][0]["entrypoints"] = ["api.py::query"]
    if projection:
        assert language == "typescript"
        write(root, "generate.mjs", "#!/usr/bin/env node\nimport { mkdirSync, readFileSync, writeFileSync } from 'node:fs';\nmkdirSync('generated', { recursive: true });\nwriteFileSync('generated/value.ts', readFileSync('src/value.ts'));\n")
        (root / "generate.mjs").chmod(0o755)
        generated = subprocess.run(["./generate.mjs"], cwd=root, capture_output=True, text=True)
        assert generated.returncode == 0, generated.stderr
        registry["source_authority"]["generated_mirror_roots"] = ["generated"]
        registry["secondary_representations"] = [{
            "id": "example.value-projection.v1", "classification": "derived", "canonical_semantic_id": "example.value.v1",
            "derivation_kind": "exact_generated_projection", "source_inputs": ["src/value.ts"],
            "outputs": ["generated/value.ts"], "recipe": {"kind": "tracked_command", "argv": ["./generate.mjs"]},
            "migration_owner": "fixture-maintainer", "direct_edit_policy": "prohibited",
        }]
        payload["contracts"]["semantic_families"]["families"][0]["material_selectors"]["secondary_paths"] = ["generated/value.ts"]
    _contracts(root, payload)
    git(root, "add", "-A")
    git(root, "commit", "--quiet", "-m", "Single-language semantic consumer")


def _snapshot(root: Path, *, managed: bool) -> dict:
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    selected = commands.MANAGED_PATHS if managed else [path for path in paths if path and path not in commands.MANAGED_PATHS]
    return {relative: ((root / relative).read_bytes(), (root / relative).stat().st_mode)
            for relative in selected if (root / relative).is_file()}


@pytest.mark.parametrize("language,projection", [("typescript", False), ("typescript", True), ("python", False)])
def test_single_language_lock_adoption_and_full_scan(tmp_path: Path, language: str, projection: bool) -> None:
    root = tmp_path
    _single_language(root, language, projection)
    inventory, python, typescript, _ = discover_source(root)
    if language == "typescript":
        assert python["files"] == [] and python["functions"] == [] and python["types"] == []
        assert typescript["compiler_version"] == "6.0.3"
        assert "src/value.ts::Value" in inventory["types"]
        assert not subprocess.check_output(["git", "ls-files", "--", "*.py"], cwd=root).strip()
    else:
        assert typescript["files"] == [] and typescript["functions"] == []
        assert {row["path"] for row in python["files"]} == {"api.py", "model.py"}
        assert not (root / "node_modules").exists()
        assert not subprocess.check_output(["git", "ls-files", "--", "*.ts", "*.tsx"], cwd=root).strip()
    product = _snapshot(root, managed=False)
    locked = commands._lock(root, apply=True)
    assert len(locked["projection_outputs"]) == int(projection)
    original = _snapshot(root, managed=True)
    commands._lock(root, apply=False)
    commands._adopt(root, root / "adopt.yml", apply=False)
    assert _snapshot(root, managed=True) == original
    assert _snapshot(root, managed=False) == product
    commands._adopt(root, root / "adopt.yml", apply=True)
    commands._lock(root, apply=False)
    report = run_scan(root)
    assert report["verdict"] == "conformant"
    assert report["semantic_authority"]["operation_count"] == 1
    assert _snapshot(root, managed=False) == product
    actual = yaml.safe_load((root / "governance/semantic-lock.yml").read_text())
    if not projection:
        assert actual["projection_outputs"] == []
        return
    row, = actual["projection_outputs"]
    source = (root / "src/value.ts").read_bytes()
    assert row == {
        "path": "generated/value.ts", "canonical_source": "src/value.ts",
        "recipe_sha256": hashlib.sha256(json.dumps(["./generate.mjs"], separators=(",", ":")).encode() + (root / "generate.mjs").read_bytes()).hexdigest(),
        "source_sha256": hashlib.sha256(source).hexdigest(), "output_sha256": hashlib.sha256(source).hexdigest(),
    }
    generated = root / row["path"]
    generated.write_bytes(source + b"// direct edit\n")
    original = _snapshot(root, managed=True)
    with pytest.raises(SemanticAuthorityError, match="representation_provenance.*cannot reproduce"):
        commands._adopt(root, root / "adopt.yml", apply=True)
    assert _snapshot(root, managed=True) == original
    assert generated.read_bytes() == source + b"// direct edit\n"

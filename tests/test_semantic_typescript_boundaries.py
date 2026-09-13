from __future__ import annotations

import json
from pathlib import Path

import pytest

from bcf_governance.tooling import semantic_authority_commands as commands
from bcf_governance.tooling.semantic_ownership_scan import run_scan
from semantic_typescript_fixture import dump, repository, write


@pytest.mark.parametrize("failure", ["diagnostic", "untracked", "compiler-drift"])
def test_real_compiler_failure_is_typed_and_cannot_write_lock(tmp_path: Path, failure: str, capsys) -> None:
    repository(tmp_path)
    if failure == "diagnostic":
        write(tmp_path, "src/api.ts", "export function query(): number { return 'wrong'; }\n")
        diagnostic = "compiler diagnostic"
    elif failure == "untracked":
        write(tmp_path, "src/hidden.ts", "export function hidden(): number { return 1; }\n")
        write(tmp_path, "src/api.ts", "export { hidden as query } from './hidden.js';\n")
        diagnostic = "not a tracked repository file"
    else:
        path = tmp_path / "node_modules/typescript/package.json"
        payload = json.loads(path.read_text())
        payload["version"] = "6.0.4"
        path.write_text(json.dumps(payload))
        diagnostic = "does not match the package lock"
    with pytest.raises(SystemExit) as stopped:
        commands.main(["lock", "--apply", "--repo-root", str(tmp_path)])
    assert stopped.value.code == 1
    assert diagnostic in capsys.readouterr().out
    assert not (tmp_path / "governance/semantic-lock.yml").exists()


def test_missing_typescript_authoritative_owner_is_a_real_scan_violation(tmp_path: Path) -> None:
    payload = repository(tmp_path)
    registry = payload["contracts"]["canonical_representations"]
    entry = registry["representations"][0]
    entry["authoritative_owner"]["symbol"] = "src/value.ts::missing"
    entry["authorized_constructors_and_factories"].append("src/value.ts::missing")
    dump(tmp_path, "governance/canonical-representations.yml", registry)
    report = run_scan(tmp_path)
    assert report["verdict"] == "non_conformant"
    assert any(row["kind"] == "registry_owner_not_discovered" for row in report["violations"])


@pytest.mark.parametrize("statement,passes", [("export {type Shape} from './side.js';", True), ("import {} from './side.js';", False)])
def test_type_only_reexports_and_empty_runtime_imports_have_distinct_effects(tmp_path: Path, statement: str, passes: bool) -> None:
    from bcf_governance.tooling.semantic_authority_contracts import SemanticAuthorityError
    from semantic_typescript_fixture import git
    repository(tmp_path)
    write(tmp_path, "src/side.ts", "export interface Shape { value: number; }\nconst state = { value: 0 }; state.value++;\n")
    write(tmp_path, "src/api.ts", statement + "\nexport function query(): number { return 1; }\n")
    git(tmp_path, "add", "src")
    if passes:
        commands._lock(tmp_path, apply=True)
    else:
        with pytest.raises(SemanticAuthorityError, match="undeclared write"):
            commands._lock(tmp_path, apply=True)


def test_intrinsic_purity_requires_the_actual_selected_compiler_library(tmp_path: Path) -> None:
    from bcf_governance.tooling.semantic_authority_contracts import SemanticAuthorityError
    from semantic_typescript_fixture import git
    repository(tmp_path)
    write(tmp_path, "src/typescript/lib/lib.fixture.d.ts", "declare const impostor: { get(): number; };\n")
    write(tmp_path, "src/api.ts", "export function query(): number { return impostor.get(); }\n")
    git(tmp_path, "add", "src")
    with pytest.raises(SemanticAuthorityError, match="unresolved effect"):
        commands._lock(tmp_path, apply=True)


@pytest.mark.parametrize("kind", ["package-directory", "package-json", "compiler-js"])
def test_real_compiler_and_adoption_preserve_safe_internal_dependency_links(tmp_path: Path, kind: str) -> None:
    repository(tmp_path)
    compiler = tmp_path / "node_modules/typescript"
    if kind == "package-directory":
        target = tmp_path / "node_modules/.store/compiler"
        target.parent.mkdir()
        compiler.rename(target)
        compiler.symlink_to(".store/compiler", target_is_directory=True)
    elif kind == "package-json":
        (compiler / "package.json").rename(compiler / "package-metadata.json")
        (compiler / "package.json").symlink_to("package-metadata.json")
    else:
        (compiler / "lib/typescript.js").rename(compiler / "lib/compiler-runtime.js")
        (compiler / "lib/typescript.js").symlink_to("compiler-runtime.js")
    commands._lock(tmp_path, apply=True)
    commands._adopt(tmp_path, tmp_path / "adopt.yml", apply=True)
    assert run_scan(tmp_path)["verdict"] == "conformant"


def test_empty_combined_source_and_default_empty_python_remain_errors(tmp_path: Path) -> None:
    from bcf_governance.tooling.semantic_ownership_inventory import SemanticInventoryError, discover_python_source
    from bcf_governance.tooling.semantic_source_discovery import discover_source
    from semantic_typescript_fixture import git
    payload = repository(tmp_path, registry_engine=False, typescript_family=False)
    git(tmp_path, "rm", "model.py", "src/api.ts", "src/value.ts", "declared-types/index.d.ts")
    operations = payload["contracts"]["application_operations"]
    operations["populations"] = [{"id": "api", "adapter": "python_module_exports", "source": "absent.py", "symbol": "exports", "public_only": True}]
    dump(tmp_path, "governance/application-operations.yml", operations)
    with pytest.raises(SemanticInventoryError, match="Python discovery returned zero"):
        discover_python_source(tmp_path)
    with pytest.raises(SemanticInventoryError, match="zero analyzed files"):
        discover_source(tmp_path)

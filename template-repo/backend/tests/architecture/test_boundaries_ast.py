from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_ROOT = REPO_ROOT / "backend" / "src"

FORBIDDEN_DOMAIN_IMPORT_PREFIXES = (
    "fastapi",
    "sqlalchemy",
    "psycopg",
    "redis",
)


def _python_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)


def _domain_python_files() -> list[Path]:
    if not SRC_ROOT.exists():
        return []
    domain_roots = [path for path in SRC_ROOT.rglob("domain") if path.is_dir()]
    return sorted({path for domain_root in domain_roots for path in _python_files(domain_root)})


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    return imported


def test_domain_architecture_gate_has_files_to_check() -> None:
    assert SRC_ROOT.exists(), (
        f"{SRC_ROOT.relative_to(REPO_ROOT)} does not exist; update this test for the repo layout "
        "or create the backend source root before treating architecture-test as a release gate"
    )
    assert _domain_python_files(), (
        "no Python files were discovered under backend/src/**/domain; update this test for the "
        "repo layout or add domain files before treating architecture-test as a release gate"
    )


def test_domain_layer_does_not_import_frameworks_or_clients() -> None:
    domain_files = _domain_python_files()
    assert domain_files, "domain architecture gate has no Python files to check"
    violations: list[str] = []

    for path in domain_files:
        for imported in _imports(path):
            if imported.startswith(FORBIDDEN_DOMAIN_IMPORT_PREFIXES):
                violations.append(f"{path.relative_to(REPO_ROOT)} imports {imported}")

    assert not violations, "domain boundary violations:\n" + "\n".join(violations)

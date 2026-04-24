from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_ROOT = REPO_ROOT / "backend" / "src"

FORBIDDEN_INFRA_IMPORT_PREFIXES = (
    "fastapi",
    "sqlalchemy",
    "requests",
    "httpx",
    "psycopg",
    "redis",
    "pydantic_settings",
)
PORT_LAYER_NAMES = ("ports", "repositories", "repos")
USE_CASE_LAYER_NAMES = ("use_case", "use_cases", "commands", "queries", "handlers", "application")
ROUTER_LAYER_NAMES = ("router", "routers", "http", "api")
INFRA_LAYER_NAMES = ("infra", "infrastructure", "adapters")
DOMAIN_LAYER_NAMES = ("domain",)


def _has_layer_token(imported: str, *layer_names: str) -> bool:
    tokens = imported.split(".")
    return any(layer_name in tokens for layer_name in layer_names)


def _python_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)


def _layer_python_files(*layer_names: str) -> list[Path]:
    if not SRC_ROOT.exists():
        return []
    layer_roots = [path for path in SRC_ROOT.rglob("*") if path.is_dir() and path.name in layer_names]
    return sorted({path for layer_root in layer_roots for path in _python_files(layer_root)})


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.extend(f"{node.module}.{alias.name}" for alias in node.names)
    return imported


def test_cqrs_lite_architecture_gate_has_files_to_check() -> None:
    assert SRC_ROOT.exists(), (
        f"{SRC_ROOT.relative_to(REPO_ROOT)} does not exist; update this test for the repo layout "
        "or create the backend source root before treating architecture-test as a release gate"
    )
    discovered_layers = {
        "domain": _layer_python_files(*DOMAIN_LAYER_NAMES),
        "use_case": _layer_python_files(*USE_CASE_LAYER_NAMES),
        "ports": _layer_python_files(*PORT_LAYER_NAMES),
        "router": _layer_python_files(*ROUTER_LAYER_NAMES),
        "infra": _layer_python_files(*INFRA_LAYER_NAMES),
    }
    assert any(discovered_layers.values()), (
        "no Python files were discovered under the starter CQRS-lite boundary layer names; update "
        "this test for the repo layout or add boundary-owned modules before treating architecture-test "
        "as a release gate"
    )


def test_domain_layer_does_not_import_frameworks_clients_or_outer_layers() -> None:
    domain_files = _layer_python_files(*DOMAIN_LAYER_NAMES)
    assert domain_files, "domain architecture gate has no Python files to check"
    violations: list[str] = []

    for path in domain_files:
        for imported in _imports(path):
            if imported.startswith(FORBIDDEN_INFRA_IMPORT_PREFIXES) or _has_layer_token(
                imported, *USE_CASE_LAYER_NAMES, *ROUTER_LAYER_NAMES, *INFRA_LAYER_NAMES, *PORT_LAYER_NAMES
            ):
                violations.append(f"{path.relative_to(REPO_ROOT)} imports {imported}")

    assert not violations, "domain boundary violations:\n" + "\n".join(violations)


def test_use_cases_do_not_import_http_objects_or_infrastructure_clients() -> None:
    use_case_files = _layer_python_files(*USE_CASE_LAYER_NAMES)
    assert use_case_files, "use-case architecture gate has no Python files to check"
    violations: list[str] = []

    for path in use_case_files:
        for imported in _imports(path):
            if imported.startswith(FORBIDDEN_INFRA_IMPORT_PREFIXES) or _has_layer_token(
                imported, *ROUTER_LAYER_NAMES, *INFRA_LAYER_NAMES
            ):
                violations.append(f"{path.relative_to(REPO_ROOT)} imports {imported}")
            if imported.split(".")[-1] in {"Request", "Response"}:
                violations.append(f"{path.relative_to(REPO_ROOT)} imports {imported}")

    assert not violations, "use-case boundary violations:\n" + "\n".join(violations)


def test_ports_do_not_import_sqlalchemy_or_concrete_adapters() -> None:
    port_files = _layer_python_files(*PORT_LAYER_NAMES)
    assert port_files, "persistence contract architecture gate has no Python files to check"
    violations: list[str] = []

    for path in port_files:
        for imported in _imports(path):
            if imported.startswith(("fastapi", "sqlalchemy", "psycopg", "redis", "requests", "httpx")) or _has_layer_token(
                imported, *ROUTER_LAYER_NAMES, *INFRA_LAYER_NAMES
            ):
                violations.append(f"{path.relative_to(REPO_ROOT)} imports {imported}")

    assert not violations, "port boundary violations:\n" + "\n".join(violations)


def test_routers_do_not_import_persistence_models_or_external_clients_directly() -> None:
    router_files = _layer_python_files(*ROUTER_LAYER_NAMES)
    assert router_files, "router architecture gate has no Python files to check"
    violations: list[str] = []

    for path in router_files:
        for imported in _imports(path):
            if imported.startswith(("sqlalchemy", "psycopg", "redis", "requests", "httpx")) or _has_layer_token(
                imported, *DOMAIN_LAYER_NAMES, *PORT_LAYER_NAMES, *INFRA_LAYER_NAMES
            ):
                violations.append(f"{path.relative_to(REPO_ROOT)} imports {imported}")

    assert not violations, "router boundary violations:\n" + "\n".join(violations)

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIG_PATH = REPO_ROOT / "architecture-boundaries.yml"


DEFAULT_CONFIG: dict[str, Any] = {
    "architecture": {
        "source_roots": ["backend/src"],
        "layers": {
            "domain": {
                "path_tokens": ["domain"],
                "required": True,
                "forbidden_import_prefixes": [
                    "fastapi",
                    "sqlalchemy",
                    "requests",
                    "httpx",
                    "psycopg",
                    "redis",
                    "pydantic_settings",
                ],
                "forbidden_layer_imports": ["use_cases", "routers", "infrastructure", "ports"],
                "forbidden_import_names": [],
            },
            "use_cases": {
                "path_tokens": ["use_case", "use_cases", "commands", "queries", "handlers", "application"],
                "required": True,
                "forbidden_import_prefixes": [
                    "fastapi",
                    "sqlalchemy",
                    "requests",
                    "httpx",
                    "psycopg",
                    "redis",
                    "pydantic_settings",
                ],
                "forbidden_layer_imports": ["routers", "infrastructure"],
                "forbidden_import_names": ["Request", "Response"],
            },
            "ports": {
                "path_tokens": ["ports", "repositories", "repos"],
                "required": True,
                "forbidden_import_prefixes": ["fastapi", "sqlalchemy", "psycopg", "redis", "requests", "httpx"],
                "forbidden_layer_imports": ["routers", "infrastructure"],
                "forbidden_import_names": [],
            },
            "routers": {
                "path_tokens": ["router", "routers", "http", "api"],
                "required": True,
                "forbidden_import_prefixes": ["sqlalchemy", "psycopg", "redis", "requests", "httpx"],
                "forbidden_layer_imports": ["domain", "ports", "infrastructure"],
                "forbidden_import_names": [],
            },
            "infrastructure": {
                "path_tokens": ["infra", "infrastructure", "adapters"],
                "required": False,
                "forbidden_import_prefixes": [],
                "forbidden_layer_imports": [],
                "forbidden_import_names": [],
            },
        },
    }
}


def _architecture_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return DEFAULT_CONFIG["architecture"]
    payload = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError(f"{CONFIG_PATH.relative_to(REPO_ROOT)} must contain a mapping")
    architecture = payload.get("architecture")
    if not isinstance(architecture, dict):
        raise AssertionError(f"{CONFIG_PATH.relative_to(REPO_ROOT)} must define architecture")
    return architecture


def _layers() -> dict[str, dict[str, Any]]:
    layers = _architecture_config().get("layers")
    if not isinstance(layers, dict):
        raise AssertionError("architecture-boundaries.yml architecture.layers must be a mapping")
    return layers


def _source_roots() -> list[Path]:
    roots = _architecture_config().get("source_roots")
    if not isinstance(roots, list) or not roots:
        raise AssertionError("architecture-boundaries.yml architecture.source_roots must be a non-empty list")
    return [REPO_ROOT / str(root) for root in roots]


def _python_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)


def _layer_python_files(layer_name: str) -> list[Path]:
    layer = _layers()[layer_name]
    path_tokens = tuple(str(token) for token in layer.get("path_tokens", []))
    layer_roots = [
        path
        for source_root in _source_roots()
        for path in source_root.rglob("*")
        if path.is_dir() and path.name in path_tokens
    ]
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


def _has_layer_token(imported: str, layer_name: str) -> bool:
    layer = _layers()[layer_name]
    imported_tokens = imported.split(".")
    return any(str(token) in imported_tokens for token in layer.get("path_tokens", []))


def _assert_layer_rules(layer_name: str) -> None:
    layer = _layers()[layer_name]
    layer_files = _layer_python_files(layer_name)
    if layer.get("required", True):
        assert layer_files, f"{layer_name} architecture gate has no Python files to check"

    violations: list[str] = []
    forbidden_prefixes = tuple(str(prefix) for prefix in layer.get("forbidden_import_prefixes", []))
    forbidden_layers = tuple(str(name) for name in layer.get("forbidden_layer_imports", []))
    forbidden_import_names = {str(name) for name in layer.get("forbidden_import_names", [])}

    for path in layer_files:
        for imported in _imports(path):
            if imported.startswith(forbidden_prefixes):
                violations.append(f"{path.relative_to(REPO_ROOT)} imports {imported}")
            for forbidden_layer in forbidden_layers:
                if _has_layer_token(imported, forbidden_layer):
                    violations.append(f"{path.relative_to(REPO_ROOT)} imports {imported}")
            if imported.split(".")[-1] in forbidden_import_names:
                violations.append(f"{path.relative_to(REPO_ROOT)} imports {imported}")

    assert not violations, f"{layer_name} boundary violations:\n" + "\n".join(violations)


def test_cqrs_lite_architecture_gate_has_files_to_check() -> None:
    existing_roots = [root for root in _source_roots() if root.exists()]
    assert existing_roots, (
        "no configured architecture source roots exist; update architecture-boundaries.yml "
        "or create the source root before treating architecture-test as a release gate"
    )
    discovered_layers = {layer_name: _layer_python_files(layer_name) for layer_name in _layers()}
    assert any(discovered_layers.values()), (
        "no Python files were discovered under configured architecture boundary layer names; update "
        "architecture-boundaries.yml or add boundary-owned modules before treating architecture-test "
        "as a release gate"
    )


def test_domain_layer_does_not_import_frameworks_clients_or_outer_layers() -> None:
    _assert_layer_rules("domain")


def test_use_cases_do_not_import_http_objects_or_infrastructure_clients() -> None:
    _assert_layer_rules("use_cases")


def test_ports_do_not_import_sqlalchemy_or_concrete_adapters() -> None:
    _assert_layer_rules("ports")


def test_routers_do_not_import_persistence_models_or_external_clients_directly() -> None:
    _assert_layer_rules("routers")

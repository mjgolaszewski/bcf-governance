from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIG_PATH = REPO_ROOT / "architecture-boundaries.yml"


DEFAULT_CONFIG: dict[str, Any] = {
    "architecture": {
        "source_roots": ["backend/src"],
        "mandatory_rule_gate_policy": {
            "every_mandatory_rule_has_executable_gate": True,
            "human_review_only_allowed_with_rationale": True,
            "human_review_only_rules": [],
        },
        "production_module_policy": {
            "max_loc": 800,
            "excluded_path_tokens": [
                "generated",
                "migrations",
                "migration",
                "vendor",
                "fixtures",
                "snapshots",
                "testdata",
                "tests",
            ],
            "excluded_file_suffixes": ["_pb2.py", "_pb2_grpc.py"],
        },
        "bounded_contexts": {
            "required": True,
            "context_root_tokens": [
                "domain",
                "domains",
                "feature",
                "features",
                "context",
                "contexts",
                "bounded_context",
                "bounded_contexts",
                "infra",
                "infrastructure",
                "adapter",
                "adapters",
            ],
            "shared_context_tokens": ["shared", "shared_kernel"],
        },
        "layer_membership_policy": {"exactly_one_layer": True},
        "context_membership_policy": {"exactly_one_context": True},
        "cqrs_policy": {
            "command_path_tokens": ["command", "commands"],
            "query_path_tokens": ["query", "queries"],
            "read_model_tokens": [
                "read_model",
                "read_models",
                "view_model",
                "view_models",
                "projection",
                "projections",
            ],
            "write_method_names": [
                "bulk_save_objects",
                "commit",
                "create",
                "delete",
                "enqueue",
                "execute_write",
                "flush",
                "merge",
                "publish",
                "remove",
                "save",
                "update",
            ],
        },
        "thin_router_policy": {
            "max_branch_nodes": 4,
            "max_loop_nodes": 0,
            "delegate_call_name_tokens": ["command", "query", "handler", "use_case", "service"],
        },
        "duplication_policy": {
            "enabled": True,
            "min_duplicate_lines": 12,
            "scoped_to_bounded_context": True,
            "allowed_cross_context_duplication": True,
        },
        "shared_abstraction_policy": {
            "shared_path_tokens": ["common", "helpers", "shared", "utils"],
            "min_real_call_sites": 2,
            "required_metadata": [
                "owning_layer",
                "owning_context_or_shared_kernel",
                "rationale",
                "tests",
            ],
        },
        "layers": {
            "domain": {
                "path_tokens": ["domain"],
                "required": True,
                "forbidden_import_prefixes": [
                    "boto3",
                    "botocore",
                    "fastapi",
                    "google.cloud",
                    "grpc",
                    "httpx",
                    "opentelemetry",
                    "psycopg",
                    "requests",
                    "redis",
                    "sentry_sdk",
                    "sqlalchemy",
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
                    "opentelemetry",
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
                "forbidden_import_prefixes": [
                    "fastapi",
                    "sqlalchemy",
                    "psycopg",
                    "redis",
                    "requests",
                    "httpx",
                    "opentelemetry",
                ],
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


def _production_policy() -> dict[str, Any]:
    return dict(_architecture_config().get("production_module_policy", {}))


def _bounded_context_policy() -> dict[str, Any]:
    return dict(_architecture_config().get("bounded_contexts", {}))


def _cqrs_policy() -> dict[str, Any]:
    return dict(_architecture_config().get("cqrs_policy", {}))


def _thin_router_policy() -> dict[str, Any]:
    return dict(_architecture_config().get("thin_router_policy", {}))


def _duplication_policy() -> dict[str, Any]:
    return dict(_architecture_config().get("duplication_policy", {}))


def _python_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*.py") if "__pycache__" not in path.parts)


def _all_layer_tokens() -> set[str]:
    return {
        str(token)
        for layer in _layers().values()
        for token in layer.get("path_tokens", [])
    }


def _is_excluded_production_path(path: Path) -> bool:
    policy = _production_policy()
    excluded_tokens = {str(token) for token in policy.get("excluded_path_tokens", [])}
    excluded_suffixes = tuple(str(suffix) for suffix in policy.get("excluded_file_suffixes", []))
    relative_parts = path.relative_to(REPO_ROOT).parts
    return bool(excluded_tokens.intersection(relative_parts)) or path.name.endswith(excluded_suffixes)


def _production_python_files() -> list[Path]:
    return [
        path
        for source_root in _source_roots()
        for path in _python_files(source_root)
        if not _is_excluded_production_path(path)
    ]


def _layer_names_for_file(path: Path) -> set[str]:
    parent_parts = set(path.relative_to(REPO_ROOT).parent.parts)
    return {
        layer_name
        for layer_name, layer in _layers().items()
        if parent_parts.intersection(str(token) for token in layer.get("path_tokens", []))
    }


def _layer_python_files(layer_name: str) -> list[Path]:
    return sorted(path for path in _production_python_files() if layer_name in _layer_names_for_file(path))


def _context_names_for_file(path: Path) -> set[str]:
    policy = _bounded_context_policy()
    parent_parts = list(path.relative_to(REPO_ROOT).parent.parts)
    root_tokens = {str(token) for token in policy.get("context_root_tokens", [])}
    shared_tokens = {str(token) for token in policy.get("shared_context_tokens", [])}
    layer_tokens = _all_layer_tokens()

    if any(part in shared_tokens for part in parent_parts):
        return {"shared_kernel"}

    contexts: set[str] = set()
    for index, part in enumerate(parent_parts[:-1]):
        if part not in root_tokens:
            continue
        candidate = parent_parts[index + 1]
        if candidate in root_tokens or candidate in layer_tokens or candidate in shared_tokens:
            continue
        contexts.add(candidate)
    return contexts


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.extend(f"{node.module}.{alias.name}" for alias in node.names)
    return imported


def _tree(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"))


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


def _path_has_any_token(path: Path, tokens: list[str]) -> bool:
    return bool(set(path.relative_to(REPO_ROOT).parent.parts).intersection(str(token) for token in tokens))


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _symbol_text(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _symbol_text(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _symbol_text(node.func)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return " ".join(_symbol_text(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return " ".join(_symbol_text(value) for value in node.values)
    return ""


def _contains_any_token(value: str, tokens: list[str]) -> bool:
    lowered = value.lower()
    return any(str(token).lower() in lowered for token in tokens)


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


def test_production_modules_respect_loc_cap() -> None:
    max_loc = int(_production_policy().get("max_loc", 800))
    violations = [
        f"{path.relative_to(REPO_ROOT)} has {len(path.read_text(encoding='utf-8').splitlines())} LOC"
        for path in _production_python_files()
        if len(path.read_text(encoding="utf-8").splitlines()) > max_loc
    ]
    assert not violations, "production module LOC cap violations:\n" + "\n".join(violations)


def test_production_modules_map_to_exactly_one_layer() -> None:
    if not _architecture_config().get("layer_membership_policy", {}).get("exactly_one_layer", True):
        return
    violations = [
        f"{path.relative_to(REPO_ROOT)} maps to {sorted(_layer_names_for_file(path)) or 'no'} layers"
        for path in _production_python_files()
        if len(_layer_names_for_file(path)) != 1
    ]
    assert not violations, "layer membership violations:\n" + "\n".join(violations)


def test_production_modules_map_to_exactly_one_bounded_context() -> None:
    if not _architecture_config().get("context_membership_policy", {}).get("exactly_one_context", True):
        return
    violations = [
        f"{path.relative_to(REPO_ROOT)} maps to {sorted(_context_names_for_file(path)) or 'no'} contexts"
        for path in _production_python_files()
        if len(_context_names_for_file(path)) != 1
    ]
    assert not violations, "bounded context membership violations:\n" + "\n".join(violations)


def test_domain_layer_does_not_import_frameworks_clients_or_outer_layers() -> None:
    _assert_layer_rules("domain")


def test_use_cases_do_not_import_http_objects_or_infrastructure_clients() -> None:
    _assert_layer_rules("use_cases")


def test_ports_do_not_import_sqlalchemy_or_concrete_adapters() -> None:
    _assert_layer_rules("ports")


def test_routers_do_not_import_persistence_models_or_external_clients_directly() -> None:
    _assert_layer_rules("routers")


def test_cqrs_query_side_does_not_mutate_state() -> None:
    policy = _cqrs_policy()
    query_tokens = [str(token) for token in policy.get("query_path_tokens", [])]
    write_names = {str(name).lower() for name in policy.get("write_method_names", [])}
    violations: list[str] = []
    for path in _production_python_files():
        if not _path_has_any_token(path, query_tokens):
            continue
        for node in ast.walk(_tree(path)):
            if not isinstance(node, ast.Call):
                continue
            call_name = _call_name(node.func).lower()
            if call_name.split(".")[-1] in write_names:
                violations.append(f"{path.relative_to(REPO_ROOT)} calls mutating API {call_name}")
    assert not violations, "query-side mutation violations:\n" + "\n".join(violations)


def test_cqrs_command_side_does_not_return_read_model_shapes() -> None:
    policy = _cqrs_policy()
    command_tokens = [str(token) for token in policy.get("command_path_tokens", [])]
    read_model_tokens = [str(token) for token in policy.get("read_model_tokens", [])]
    violations: list[str] = []
    for path in _production_python_files():
        if not _path_has_any_token(path, command_tokens):
            continue
        for imported in _imports(path):
            if _contains_any_token(imported, read_model_tokens):
                violations.append(f"{path.relative_to(REPO_ROOT)} imports read-model shape {imported}")
        for node in ast.walk(_tree(path)):
            if isinstance(node, ast.Return) and node.value is not None:
                returned = _symbol_text(node.value)
                if _contains_any_token(returned, read_model_tokens):
                    violations.append(f"{path.relative_to(REPO_ROOT)} returns read-model shape {returned}")
    assert not violations, "command-side read-model return violations:\n" + "\n".join(violations)


def test_routers_remain_thin_transport_adapters() -> None:
    policy = _thin_router_policy()
    max_branch_nodes = int(policy.get("max_branch_nodes", 4))
    max_loop_nodes = int(policy.get("max_loop_nodes", 0))
    delegate_tokens = [str(token).lower() for token in policy.get("delegate_call_name_tokens", [])]
    violations: list[str] = []
    for path in _layer_python_files("routers"):
        tree = _tree(path)
        branch_nodes = sum(isinstance(node, (ast.If, ast.Match, ast.Try)) for node in ast.walk(tree))
        loop_nodes = sum(isinstance(node, (ast.For, ast.AsyncFor, ast.While)) for node in ast.walk(tree))
        if branch_nodes > max_branch_nodes:
            violations.append(f"{path.relative_to(REPO_ROOT)} has {branch_nodes} branch nodes")
        if loop_nodes > max_loop_nodes:
            violations.append(f"{path.relative_to(REPO_ROOT)} has {loop_nodes} loop nodes")
        for function in [
            node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]:
            calls = [_call_name(call.func).lower() for call in ast.walk(function) if isinstance(call, ast.Call)]
            if calls and not any(any(token in call for token in delegate_tokens) for call in calls):
                violations.append(f"{path.relative_to(REPO_ROOT)} {function.name} does not delegate")
    assert not violations, "router thinness violations:\n" + "\n".join(violations)


def test_bounded_context_duplication_is_explicit() -> None:
    policy = _duplication_policy()
    if not policy.get("enabled", True):
        return
    min_lines = int(policy.get("min_duplicate_lines", 12))
    blocks_by_context: dict[str, dict[tuple[str, ...], list[Path]]] = defaultdict(lambda: defaultdict(list))
    for path in _production_python_files():
        contexts = _context_names_for_file(path)
        if len(contexts) != 1:
            continue
        lines = [
            re.sub(r"\s+", " ", line.strip())
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        for index in range(0, max(len(lines) - min_lines + 1, 0)):
            block = tuple(lines[index : index + min_lines])
            blocks_by_context[next(iter(contexts))][block].append(path)

    violations: list[str] = []
    for context, blocks in blocks_by_context.items():
        for paths in blocks.values():
            unique_paths = sorted({path.relative_to(REPO_ROOT).as_posix() for path in paths})
            if len(unique_paths) > 1:
                violations.append(f"{context}: duplicate block in {', '.join(unique_paths)}")
    assert not violations, "bounded-context duplication violations:\n" + "\n".join(violations)

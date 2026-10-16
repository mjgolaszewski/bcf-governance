"""Closed semantic-family, application-operation, and provenance contracts.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from .semantic_ownership_registry import Registry, load_registry
from .semantic_operation_python import (
    _module_aliases, _expression_symbol, _function_for_entrypoint,
)
from .semantic_operation_typescript import (
    TypeScriptOperationPopulationError,
    discover_typescript_population,
)
from .semantic_derivations import (
    SemanticDerivationError,
    collect_provenance,
    legacy_generated_projections as _legacy_generated_projections,
    validate_explicit_provenance as _validate_explicit_provenance,
)
from .semantic_authority_migrations import (
    SemanticMigrationError,
    validate_exact_base_migrations,
)
from .semantic_locking import atomic_write, render_lock_yaml, sha256_bytes, stable_payload_digest
from .semantic_operation_effects import (
    SemanticOperationEffectError,
    validated_operation_effect_inventory,
)
from .semantic_yaml import SemanticYAMLError, load_unique_mapping, load_unique_mapping_text
from .semantic_authority_operations import _validate_operations


FAMILIES_PATH = Path("governance/semantic-families.yml")
OPERATIONS_PATH = Path("governance/application-operations.yml")
REPRESENTATIONS_PATH = Path("governance/canonical-representations.yml")
LOCK_PATH = Path("governance/semantic-lock.yml")
CAPABILITIES = (
    "semantic_family_completeness",
    "application_operation_inventory",
    "representation_provenance",
)
READ_ONLY_KINDS = {"query", "projection", "proposal", "validation"}
MUTATING_KINDS = {"command", "execution", "event_handler"}


class SemanticAuthorityError(ValueError):
    """Raised when a blocking semantic-authority contract is incomplete."""


@dataclass(frozen=True)
class SemanticAuthorityEvaluation:
    family_count: int
    operation_count: int
    derived_count: int
    exception_count: int
    projection_outputs: tuple[dict[str, str], ...]
    observations: tuple[dict[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "family_count": self.family_count,
            "operation_count": self.operation_count,
            "derived_count": self.derived_count,
            "exception_count": self.exception_count,
            "projection_outputs": list(self.projection_outputs),
            "observations": list(self.observations),
        }


@dataclass(frozen=True)
class SemanticFamilyRegistry:
    families: tuple[dict[str, Any], ...]
    migrations: tuple[dict[str, Any], ...]
    raw: dict[str, Any]


@dataclass(frozen=True)
class ApplicationOperationRegistry:
    populations: tuple[dict[str, Any], ...]
    operations: tuple[dict[str, Any], ...]
    migrations: tuple[dict[str, Any], ...]
    raw: dict[str, Any]


@dataclass(frozen=True)
class RepresentationProvenance:
    projection_outputs: tuple[dict[str, str], ...]
    derived_count: int
    exception_count: int


def _load_yaml(path: Path, *, expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str) or len(expected_sha256) != 64
        or any(value not in "0123456789abcdef" for value in expected_sha256)
    ):
        raise SemanticAuthorityError("protected registry digest is malformed")
    if not path.is_file() or path.is_symlink():
        raise SemanticAuthorityError(f"required semantic contract must be a regular file: {path}")
    try:
        if expected_sha256 is None:
            payload = load_unique_mapping(path)
        else:
            raw = path.read_bytes()
            if sha256_bytes(raw) != expected_sha256:
                raise SemanticAuthorityError("semantic registry differs from protected digest")
            payload = load_unique_mapping_text(raw.decode("utf-8"))
    except (OSError, UnicodeError, SemanticYAMLError) as exc:
        raise SemanticAuthorityError(f"cannot load {path}: {exc}") from exc
    return payload


def _schema(
    repo_root: Path, name: str, payload: dict[str, Any], *, consumer_owned: bool = False,
) -> None:
    schema_root = repo_root / "schemas"
    if consumer_owned:
        source = Path(__file__).resolve()
        schema_root = (
            source.parents[1] / "pack/template-repo/schemas"
            if source.parent.name == "tooling" else source.parents[2] / "schemas"
        )
    try:
        schema = json.loads((schema_root / name).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SemanticAuthorityError(f"cannot load schemas/{name}: {exc}") from exc
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda error: ([str(value) for value in error.absolute_path], error.message),
    )
    if errors:
        diagnostics = []
        for error in errors[:20]:
            location = ".".join(str(value) for value in error.absolute_path)
            diagnostics.append(
                f"{name}{'.' + location if location else ''}: {error.message}"
            )
        raise SemanticAuthorityError("; ".join(diagnostics))


def load_semantic_families(repo_root: Path) -> SemanticFamilyRegistry:
    payload = _load_yaml(repo_root / FAMILIES_PATH)
    _schema(repo_root, "semantic-families.schema.json", payload)
    return SemanticFamilyRegistry(
        families=tuple(payload["families"]),
        migrations=tuple(payload["migrations"]),
        raw=payload,
    )


def load_application_operations(
    repo_root: Path, *, expected_sha256: str | None = None,
) -> ApplicationOperationRegistry:
    payload = _load_yaml(repo_root / OPERATIONS_PATH, expected_sha256=expected_sha256)
    _schema(repo_root, "application-operations.schema.json", payload, consumer_owned=expected_sha256 is not None)
    if expected_sha256 is not None:
        _validate_operation_structure(payload)
    return ApplicationOperationRegistry(
        populations=tuple(payload["populations"]),
        operations=tuple(payload["operations"]),
        migrations=tuple(payload["migrations"]),
        raw=payload,
    )


def _safe_path(repo_root: Path, value: object, *, context: str, must_exist: bool = True) -> Path:
    if not isinstance(value, str) or not value:
        raise SemanticAuthorityError(f"{context} must be a non-empty repository path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise SemanticAuthorityError(f"{context} escapes the repository")
    target = repo_root / relative
    try:
        resolved = target.resolve(strict=must_exist)
    except OSError as exc:
        raise SemanticAuthorityError(f"{context} is unreadable: {exc}") from exc
    if not resolved.is_relative_to(repo_root.resolve()):
        raise SemanticAuthorityError(f"{context} resolves outside the repository")
    if target.is_symlink():
        raise SemanticAuthorityError(f"{context} must not be a symlink")
    if must_exist and not target.is_file():
        raise SemanticAuthorityError(f"{context} must identify a regular file")
    return target


def capability_states(repo_root: Path) -> dict[str, str]:
    profile_path = repo_root / "governance-profile.yml"
    if not profile_path.is_file():
        return {key: "disabled" for key in CAPABILITIES}
    profile = _load_yaml(profile_path)
    raw = profile.get("semantic_capabilities", {})
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise SemanticAuthorityError("governance-profile.yml semantic_capabilities must be a mapping")
    states: dict[str, str] = {}
    for key in CAPABILITIES:
        value = raw.get(key, "disabled")
        if value not in {"disabled", "advisory", "blocking", "not_applicable"}:
            raise SemanticAuthorityError(f"semantic_capabilities.{key} has an invalid state")
        states[key] = str(value)
    return states


def _unique(values: Iterable[str], *, context: str) -> list[str]:
    rows = list(values)
    duplicates = sorted({value for value in rows if rows.count(value) > 1})
    if duplicates:
        raise SemanticAuthorityError(f"{context} must be unique: {', '.join(duplicates)}")
    return rows


def _validate_family_coverage(
    families: list[dict[str, Any]], registry: Registry
) -> list[str]:
    """Own exact family-to-canonical-representation coverage."""
    family_ids = _unique(
        (str(row["id"]) for row in families), context="semantic family IDs"
    )
    registry_by_id = {entry.semantic_id: entry for entry in registry.entries}
    semantic_to_family: dict[str, str] = {}
    for family in families:
        family_id = str(family["id"])
        canonical_ids = [str(value) for value in family["canonical_semantic_ids"]]
        if family["ownership_required"] and not canonical_ids:
            raise SemanticAuthorityError(
                f"family {family_id} requires a canonical representation"
            )
        for semantic_id in canonical_ids:
            entry = registry_by_id.get(semantic_id)
            if entry is None:
                raise SemanticAuthorityError(
                    f"family {family_id} references orphaned {semantic_id}"
                )
            if entry.family != family_id:
                raise SemanticAuthorityError(
                    f"family {family_id} contradicts {semantic_id} registry family "
                    f"{entry.family}"
                )
            if semantic_id in semantic_to_family:
                raise SemanticAuthorityError(
                    f"material representation {semantic_id} belongs to both "
                    f"{semantic_to_family[semantic_id]} and {family_id}"
                )
            semantic_to_family[semantic_id] = family_id
            if family["ownership_required"] and (
                entry.lifecycle != "enforced" or not entry.blocking
            ):
                raise SemanticAuthorityError(
                    f"ownership-required family {family_id} must bind enforced "
                    f"blocking {semantic_id}"
                )
    missing_ids = sorted(set(registry_by_id) - set(semantic_to_family))
    if missing_ids:
        raise SemanticAuthorityError(
            "enforced canonical representations are outside semantic families: "
            + ", ".join(missing_ids)
        )
    return family_ids


def _validate_families(
    repo_root: Path, payload: dict[str, Any], registry: Registry, inventory: dict[str, Any]
) -> list[dict[str, Any]]:
    _schema(repo_root, "semantic-families.schema.json", payload)
    families = payload["families"]
    _validate_family_coverage(families, registry)
    registry_by_id = {entry.semantic_id: entry for entry in registry.entries}
    discovered_symbols = set(inventory.get("types", [])) | {
        str(row["symbol"]) for row in inventory.get("functions", [])
    }
    observations: list[dict[str, Any]] = []
    for family in families:
        family_id = str(family["id"])
        canonical_ids = [str(value) for value in family["canonical_semantic_ids"]]
        for semantic_id in canonical_ids:
            entry = registry_by_id[semantic_id]
        selectors = family["material_selectors"]
        symbols = [str(value) for value in selectors["symbols"]]
        if set(symbols) != {registry_by_id[value].canonical_symbol for value in canonical_ids}:
            raise SemanticAuthorityError(
                f"family {family_id} material symbols must exactly match its canonical representations"
            )
        for index, path in enumerate(selectors["source_paths"]):
            _safe_path(repo_root, path, context=f"family {family_id} source_paths[{index}]")
        for index, path in enumerate(selectors.get("secondary_paths", [])):
            _safe_path(
                repo_root,
                path,
                context=f"family {family_id} secondary_paths[{index}]",
            )
        missing = sorted(symbol for symbol in symbols if symbol not in discovered_symbols)
        if family["ownership_required"] and missing:
            raise SemanticAuthorityError(
                f"family {family_id} material symbols are absent from source inventory: {', '.join(missing)}"
            )
        observations.append(
            {"family": family_id, "significance": family["significance"], "canonical_count": len(canonical_ids)}
        )
    return observations


def _validate_secondary_coverage(
    families: dict[str, Any],
    registry: Registry,
    provenance: RepresentationProvenance,
) -> None:
    claims: dict[str, str] = {}
    for family in families["families"]:
        for path in family["material_selectors"].get("secondary_paths", []):
            previous = claims[path] if path in claims else None
            if previous is not None:
                raise SemanticAuthorityError(
                    f"material secondary representation {path} belongs to both "
                    f"{previous} and {family['id']}"
                )
            claims[str(path)] = str(family["id"])
    provenance_families: dict[str, str] = {}
    canonical_family = {entry.semantic_id: entry.family for entry in registry.entries}
    secondary = (
        registry.raw["secondary_representations"]
        if "secondary_representations" in registry.raw
        else []
    )
    for entry in secondary:
        if entry["classification"] == "derived":
            family = canonical_family[str(entry["canonical_semantic_id"])]
        else:
            family = "exception"
        locations = entry["outputs"] if "outputs" in entry else entry["locations"]
        for path in locations:
            provenance_families[str(path)] = family
    known = {str(row["path"]) for row in provenance.projection_outputs}
    for path, family in claims.items():
        if path not in known and path not in provenance_families:
            raise SemanticAuthorityError(
                f"material secondary representation {path} lacks derivation provenance"
            )
        declared_family = provenance_families[path] if path in provenance_families else None
        if declared_family not in {None, "exception", family}:
            raise SemanticAuthorityError(
                f"material secondary representation {path} claims {family} but derives "
                f"from {declared_family}"
            )
    unselected = sorted(set(provenance_families) - set(claims))
    if unselected:
        raise SemanticAuthorityError(
            "declared secondary representations are absent from semantic-family material "
            "selectors: " + ", ".join(unselected)
        )


def _python_mapping_population(repo_root: Path, population: dict[str, Any]) -> dict[str, str]:
    source = _safe_path(repo_root, population["source"], context=f"population {population['id']} source")
    try:
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(population["source"]))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise SemanticAuthorityError(f"population {population['id']} cannot parse source: {exc}") from exc
    aliases = _module_aliases(repo_root, tree, source)
    target_name = str(population["symbol"])
    found: list[ast.Dict] = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == target_name for target in node.targets
        ) and isinstance(node.value, ast.Dict):
            found.append(node.value)
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and (
            node.target.id == target_name and isinstance(node.value, ast.Dict)
        ):
            found.append(node.value)
    if len(found) != 1:
        raise SemanticAuthorityError(
            f"population {population['id']} must resolve exactly one closed Python mapping {target_name}"
        )
    result: dict[str, str] = {}
    for key, value in zip(found[0].keys, found[0].values, strict=True):
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            raise SemanticAuthorityError(f"population {population['id']} contains a dynamic key")
        symbol = _expression_symbol(value, aliases)
        if symbol == "<dynamic>":
            raise SemanticAuthorityError(f"population {population['id']} contains a dynamic entrypoint")
        if key.value in result:
            raise SemanticAuthorityError(f"population {population['id']} duplicates {key.value}")
        result[key.value] = symbol
    return result


def _python_decorator_population(repo_root: Path, population: dict[str, Any]) -> dict[str, str]:
    source = _safe_path(repo_root, population["source"], context=f"population {population['id']} source")
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(population["source"]))
    allowed = set(population.get("decorators", []))
    found: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        names = {
            decorator.id if isinstance(decorator, ast.Name) else decorator.func.id
            for decorator in node.decorator_list
            if isinstance(decorator, ast.Name) or (
                isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name)
            )
        }
        if names & allowed and (not population["public_only"] or not node.name.startswith("_")):
            if node.name in found:
                raise SemanticAuthorityError(f"population {population['id']} duplicates {node.name}")
            found[node.name] = f"{population['source']}::{node.name}"
    return found


def _python_exports_population(repo_root: Path, population: dict[str, Any]) -> dict[str, str]:
    source = _safe_path(repo_root, population["source"], context=f"population {population['id']} source")
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(population["source"]))
    explicit: list[str] | None = None
    definitions: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            definitions.append(node.name)
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == str(population["symbol"])
            for target in node.targets
        ) and isinstance(node.value, (ast.List, ast.Tuple)):
            if explicit is not None:
                raise SemanticAuthorityError(f"population {population['id']} defines its export catalogue more than once")
            explicit = [
                str(value.value) for value in node.value.elts
                if isinstance(value, ast.Constant) and isinstance(value.value, str)
            ]
    _unique(definitions, context=f"population {population['id']} public definitions")
    if explicit is not None:
        _unique(explicit, context=f"population {population['id']} exported names")
    names = explicit if explicit is not None else sorted(definitions)
    if population["public_only"]:
        names = [name for name in names if not name.startswith("_")]
    return {name: f"{population['source']}::{name}" for name in names}


def _yaml_population(repo_root: Path, population: dict[str, Any]) -> dict[str, str]:
    value: Any = _load_yaml(
        _safe_path(repo_root, population["source"], context=f"population {population['id']} source")
    )
    for component in population.get("catalog_path", []):
        if not isinstance(value, dict) or component not in value:
            raise SemanticAuthorityError(f"population {population['id']} catalog path is unresolved")
        value = value[component]
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items()}
    if isinstance(value, list):
        result = {}
        for item in value:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                raise SemanticAuthorityError(f"population {population['id']} catalog rows require id")
            if item["id"] in result:
                raise SemanticAuthorityError(f"population {population['id']} duplicates {item['id']}")
            result[item["id"]] = str(item.get("entrypoint", item["id"]))
        return result
    raise SemanticAuthorityError(f"population {population['id']} catalog must be a mapping or sequence")


def _typescript_population(repo_root: Path, population: dict[str, Any], inventory: dict[str, Any] | None = None) -> dict[str, str]:
    try:
        return discover_typescript_population(repo_root, population, inventory=inventory)
    except TypeScriptOperationPopulationError as exc:
        raise SemanticAuthorityError(str(exc)) from exc


def _discover_population(repo_root: Path, population: dict[str, Any], inventory: dict[str, Any] | None = None) -> dict[str, str]:
    if population["adapter"] == "typescript_exports":
        return _typescript_population(repo_root, population, inventory)
    adapters = {
        "python_mapping": _python_mapping_population,
        "python_decorators": _python_decorator_population,
        "python_module_exports": _python_exports_population,
        "canonical_yaml_catalog": _yaml_population,
        "typescript_exports": _typescript_population,
    }
    return adapters[str(population["adapter"])](repo_root, population)


def _validate_operation_structure(
    payload: dict[str, Any], family_ids: Iterable[str] | None = None
) -> list[str]:
    """Own operation/population identity and cross-family references."""
    population_ids = _unique(
        (str(row["id"]) for row in payload["populations"]),
        context="operation population IDs",
    )
    _unique(
        (str(row["id"]) for row in payload["operations"]), context="operation IDs"
    )
    known_families = set(family_ids) if family_ids is not None else None
    for operation in payload["operations"]:
        if operation["population"] not in population_ids:
            raise SemanticAuthorityError(
                f"operation {operation['id']} references unknown population "
                f"{operation['population']}"
            )
        if known_families is not None and operation["family"] not in known_families:
            raise SemanticAuthorityError(
                f"operation {operation['id']} references an unknown semantic family"
            )
    return population_ids


def collect_representation_provenance(
    repo_root: Path, registry: Registry, inventory: dict[str, Any]
) -> RepresentationProvenance:
    try:
        result = collect_provenance(repo_root, registry, inventory)
    except SemanticDerivationError as exc:
        raise SemanticAuthorityError(str(exc)) from exc
    return RepresentationProvenance(
        projection_outputs=result.projection_outputs,
        derived_count=result.derived_count,
        exception_count=result.exception_count,
    )


def _semantic_source_rows(repo_root: Path) -> list[tuple[str, str]]:
    """Derive the lock population from declared material sources, not repository churn."""
    families = load_semantic_families(repo_root)
    operations = load_application_operations(repo_root)
    registry = load_registry(repo_root)
    paths = {
        str(path)
        for family in families.families
        for path in family["material_selectors"]["source_paths"]
    }
    paths.update(str(population["source"]) for population in operations.populations)
    for entry in registry.entries:
        paths.add(entry.canonical_symbol.split("::", 1)[0])
        paths.update(
            str(value)
            for value in entry.raw["generated_source_authority"]["authoritative_roots"]
        )
    rows: list[tuple[str, str]] = []
    for relative in sorted(paths):
        path = _safe_path(repo_root, relative, context="semantic lock source")
        rows.append((relative, sha256_bytes(path.read_bytes())))
    return rows


def validate_semantic_contract_structure(repo_root: Path, registry: Registry) -> dict[str, int]:
    """Validate cross-file structure without performing a second source scan."""
    states = capability_states(repo_root)
    enabled = {
        key for key, value in states.items() if value in {"advisory", "blocking"}
    }
    adopted = {key for key, value in states.items() if value != "disabled"}
    if not adopted:
        return {"families": 0, "operations": 0}
    if adopted != set(CAPABILITIES):
        raise SemanticAuthorityError(
            "semantic authority capabilities must be adopted together to prevent partial authority"
        )
    if not enabled:
        return {"families": 0, "operations": 0}
    if (
        "application_operation_inventory" in enabled
        or "representation_provenance" in enabled
    ) and "semantic_family_completeness" not in enabled:
        raise SemanticAuthorityError(
            "operation inventory and provenance require semantic-family completeness"
        )
    families: dict[str, Any] = {"families": [], "migrations": []}
    operations: dict[str, Any] = {"operations": [], "migrations": []}
    family_ids: list[str] = []
    if "semantic_family_completeness" in enabled:
        families = load_semantic_families(repo_root).raw
        _schema(repo_root, "semantic-families.schema.json", families)
        family_ids = _validate_family_coverage(families["families"], registry)
    if "application_operation_inventory" in enabled:
        operations = load_application_operations(repo_root).raw
        _schema(repo_root, "application-operations.schema.json", operations)
        _validate_operation_structure(operations, family_ids)
    if "representation_provenance" in enabled:
        lock = _load_yaml(repo_root / LOCK_PATH)
        _schema(repo_root, "semantic-lock.schema.json", lock)
    if enabled == set(CAPABILITIES):
        try:
            validate_exact_base_migrations(repo_root, families, operations, registry)
        except SemanticMigrationError as exc:
            raise SemanticAuthorityError(str(exc)) from exc
    return {
        "families": len(families["families"]),
        "operations": len(operations["operations"]),
    }


def build_semantic_lock(
    repo_root: Path, inventory: dict[str, Any], projections: Iterable[dict[str, str]]
) -> dict[str, Any]:
    contracts = {
        "semantic_families": sha256_bytes((repo_root / FAMILIES_PATH).read_bytes()),
        "application_operations": sha256_bytes((repo_root / OPERATIONS_PATH).read_bytes()),
        "canonical_representations": sha256_bytes((repo_root / REPRESENTATIONS_PATH).read_bytes()),
    }
    source_rows = dict(_semantic_source_rows(repo_root))
    for row in inventory.get("typescript_inputs", []):
        source_rows[str(row["path"])] = str(row["sha256"])
    return {
        "schema_version": "1.0",
        "document": {"kind": "semantic_authority_lock", "version": "1.0.0", "status": "active", "path": LOCK_PATH.as_posix()},
        "contracts": contracts,
        "source_inventory_sha256": stable_payload_digest(sorted(source_rows.items())),
        "projection_outputs": sorted(projections, key=lambda row: row["path"]),
    }


def _validate_lock(repo_root: Path, expected: dict[str, Any]) -> None:
    current = _load_yaml(repo_root / LOCK_PATH)
    _schema(repo_root, "semantic-lock.schema.json", current)
    if current != expected:
        raise SemanticAuthorityError("governance/semantic-lock.yml is stale; run bcf semantic-ownership lock --apply")


def validate_semantic_authority(
    repo_root: Path,
    inventory: dict[str, Any],
    registry: Registry,
    *,
    require_lock: bool = True,
    validate_operations: bool = True,
) -> SemanticAuthorityEvaluation:
    """Validate all enabled semantic capabilities against one source inventory."""
    states = capability_states(repo_root)
    enabled = {
        key for key, value in states.items() if value in {"advisory", "blocking"}
    }
    if not enabled:
        return SemanticAuthorityEvaluation(0, 0, 0, 0, (), ())
    families = (
        _load_yaml(repo_root / FAMILIES_PATH)
        if "semantic_family_completeness" in enabled
        else {"families": []}
    )
    operations = (
        _load_yaml(repo_root / OPERATIONS_PATH)
        if "application_operation_inventory" in enabled
        else {"operations": []}
    )
    family_observations = (
        _validate_families(repo_root, families, registry, inventory)
        if "semantic_family_completeness" in enabled
        else []
    )
    operation_observations = (
        _validate_operations(repo_root, operations, inventory)
        if validate_operations and "application_operation_inventory" in enabled
        else []
    )
    provenance = (
        collect_representation_provenance(repo_root, registry, inventory)
        if "representation_provenance" in enabled
        else RepresentationProvenance((), 0, 0)
    )
    if "representation_provenance" in enabled:
        _validate_secondary_coverage(families, registry, provenance)
        expected_lock = build_semantic_lock(
            repo_root, inventory, provenance.projection_outputs
        )
        if require_lock:
            _validate_lock(repo_root, expected_lock)
    else:
        expected_lock = {"projection_outputs": []}
    observations = tuple([*family_observations, *operation_observations])
    return SemanticAuthorityEvaluation(
        family_count=len(families["families"]),
        operation_count=len(operations["operations"]),
        derived_count=provenance.derived_count,
        exception_count=provenance.exception_count,
        projection_outputs=tuple(expected_lock["projection_outputs"]),
        observations=observations,
    )


def validate_application_operations(
    repo_root: Path, inventory: dict[str, Any]
) -> list[dict[str, Any]]:
    """Validate the closed public-operation inventory against shared source facts."""
    states = capability_states(repo_root)
    if states["application_operation_inventory"] not in {"advisory", "blocking"}:
        return []
    return _validate_operations(
        repo_root, load_application_operations(repo_root).raw, inventory
    )


def required_application_operation_population(
    repo_root: Path, inventory: dict[str, Any], *, expected_registry_sha256: str,
) -> dict[str, Any]:
    """Observe required operations; caller authenticates digest and source scope.

    This explicit requirement is not waived by candidate capability switches.
    Existing population and effect owners retain all interpretation semantics.
    """
    if expected_registry_sha256 is None:
        raise SemanticAuthorityError("protected registry digest is required")
    registry = load_application_operations(repo_root, expected_sha256=expected_registry_sha256)
    return _required_operation_population(repo_root, registry.raw, inventory, expected_registry_sha256)


def _required_operation_population(
    repo_root: Path, payload: dict[str, Any], inventory: dict[str, Any], registry_sha256: str,
) -> dict[str, Any]:
    """Interpret a fresh factory capture; this internal query authenticates no inputs."""
    observations = _validate_operations(repo_root, payload, inventory, consumer_owned_schema=True)
    rows = tuple(sorted(
        (row["operation"], row["kind"], row["entrypoint"], tuple(sorted(
            (port["classification"], port["target_kind"], port["symbol"])
            for port in row["effect_ports"]
        ))) for row in observations
    ))
    return dict(authority=False, execution_qualified=False,
                scope="protected_registry_public_operations_only",
                registry_sha256=registry_sha256, operations=rows)


def required_committed_application_operation_population(
    repo_root: Path, inventory: dict[str, Any], *,
    policy_commit_sha: str, policy_tree_sha: str,
) -> dict[str, Any]:
    """Observe operations under a caller-authenticated committed policy subject.

    The consumer repository's protected policy subject is distinct from installed
    controller source. Object identity alone does not authenticate that subject.
    """
    registry, identity = load_committed_application_operations(
        repo_root, policy_commit_sha=policy_commit_sha, policy_tree_sha=policy_tree_sha,
    )
    result = _required_operation_population(repo_root, registry.raw, inventory, identity["registry_sha256"])
    result["policy_subject"] = identity["subject"]
    result["policy_blob_oid"] = identity["blob_oid"]
    return result


def load_committed_application_operations(
    repo_root: Path, *, policy_commit_sha: str, policy_tree_sha: str,
) -> tuple[ApplicationOperationRegistry, dict[str, Any]]:
    """Capture policy before source work; caller authenticates consumer custody."""
    from .semantic_source_paths import committed_application_registry_identity

    try:
        identity = committed_application_registry_identity(
            repo_root, commit_sha=policy_commit_sha, tree_sha=policy_tree_sha,
        )
    except (OSError, ValueError) as exc:
        raise SemanticAuthorityError(str(exc)) from exc
    registry = load_application_operations(repo_root, expected_sha256=identity["registry_sha256"])
    return registry, identity

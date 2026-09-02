"""Mechanical validation for BCF's frozen public contract registry."""

from __future__ import annotations

import ast
from dataclasses import dataclass
import json
from pathlib import Path
import tomllib
from typing import Any

from jsonschema import Draft202012Validator
import yaml

from .release_versions import ReleaseVersionError, parse_release_version
from .install_governance_pack import UPGRADE_PROJECT_OWNED_PATHS


class PublicContractError(ValueError):
    """Raised when implementation and declared public contracts diverge."""


@dataclass(frozen=True)
class PublicContractInventory:
    package_version: str
    command_count: int
    contract_count: int
    extension_point_count: int
    executor_kind_count: int

    def as_dict(self) -> dict[str, object]:
        return {
            "package_version": self.package_version,
            "command_count": self.command_count,
            "contract_count": self.contract_count,
            "extension_point_count": self.extension_point_count,
            "executor_kind_count": self.executor_kind_count,
        }


def _mapping(path: Path, *, yaml_document: bool = False) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise PublicContractError(f"missing safe contract path {path}")
    try:
        value = (
            yaml.safe_load(path.read_text(encoding="utf-8"))
            if yaml_document
            else json.loads(path.read_text(encoding="utf-8"))
        )
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise PublicContractError(f"invalid contract document {path}") from exc
    if not isinstance(value, dict):
        raise PublicContractError(f"contract document must be a mapping: {path}")
    return value


def _safe_path(repo_root: Path, value: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise PublicContractError(f"unsafe public contract path {value!r}")
    path = repo_root / relative
    if not path.is_file() or path.is_symlink():
        raise PublicContractError(f"public contract path is missing or unsafe: {value}")
    return path


def _assignment(source: Path, name: str) -> ast.AST:
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                return node.value
    raise PublicContractError(f"{source} has no canonical {name} assignment")


def _literal_assignment(source: Path, name: str) -> object:
    try:
        return ast.literal_eval(_assignment(source, name))
    except (TypeError, ValueError) as exc:
        raise PublicContractError(f"{source} {name} must be a literal") from exc


def _cli_commands(repo_root: Path) -> list[str]:
    value = _assignment(repo_root / "bcf_governance/cli.py", "COMMANDS")
    if not isinstance(value, ast.Dict):
        raise PublicContractError("bcf_governance.cli.COMMANDS must be one literal-key mapping")
    commands: list[str] = []
    for key in value.keys:
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            raise PublicContractError("bcf_governance.cli.COMMANDS keys must be literal strings")
        commands.append(key.value)
    return sorted(commands)


def _schema_versions(schema: dict[str, Any], field: str) -> list[str]:
    properties = schema.get("properties")
    declaration = properties.get(field) if isinstance(properties, dict) else None
    if not isinstance(declaration, dict):
        raise PublicContractError(f"schema has no top-level {field} declaration")
    if isinstance(declaration.get("const"), str):
        return [str(declaration["const"])]
    values = declaration.get("enum")
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise PublicContractError(f"schema {field} must use a string const or enum")
    return sorted(values)


def _executor_kinds(graph_schema: dict[str, Any]) -> list[str]:
    definitions = graph_schema.get("$defs")
    executor = definitions.get("executor") if isinstance(definitions, dict) else None
    variants = executor.get("oneOf") if isinstance(executor, dict) else None
    if not isinstance(variants, list):
        raise PublicContractError("CI graph schema executor must use oneOf")
    kinds: list[str] = []
    for variant in variants:
        properties = variant.get("properties") if isinstance(variant, dict) else None
        kind = properties.get("kind") if isinstance(properties, dict) else None
        value = kind.get("const") if isinstance(kind, dict) else None
        if not isinstance(value, str):
            raise PublicContractError("every CI graph executor variant needs one literal kind")
        kinds.append(value)
    if len(kinds) != len(set(kinds)):
        raise PublicContractError("CI graph executor kinds must be unique")
    return kinds


def validate_public_contracts(repo_root: Path) -> PublicContractInventory:
    """Recompute every frozen surface from its executable or schema owner."""

    repo_root = repo_root.resolve()
    registry_path = repo_root / "governance/public-contracts.yml"
    registry = _mapping(registry_path, yaml_document=True)
    registry_schema = _mapping(repo_root / "schemas/public-contracts.schema.json")
    errors = sorted(
        Draft202012Validator(registry_schema).iter_errors(registry),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        raise PublicContractError(f"public contract schema violation: {errors[0].message}")

    package = registry["package"]
    version = str(_literal_assignment(repo_root / "bcf_governance/_version.py", "__version__"))
    try:
        parse_release_version(version)
    except ReleaseVersionError as exc:
        raise PublicContractError(str(exc)) from exc
    if package["version"] != version:
        raise PublicContractError("public package version differs from bcf_governance._version")
    pyproject = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    if pyproject.get("project", {}).get("requires-python") != ">=3.11":
        raise PublicContractError("pyproject requires-python differs from the frozen runtime floor")

    commands = _cli_commands(repo_root)
    if sorted(registry["cli"]["top_level_commands"]) != commands:
        raise PublicContractError("public CLI command inventory differs from bcf_governance.cli.COMMANDS")
    if registry["cli"]["scope"] != "top_level_commands_and_exit_classes":
        raise PublicContractError("public CLI scope must identify the mechanically frozen surface")

    declared_owned = list(registry["compatibility"]["project_owned_paths"])
    if declared_owned != list(UPGRADE_PROJECT_OWNED_PATHS):
        raise PublicContractError(
            "public project-owned paths differ from the installer upgrade boundary"
        )

    contracts = registry["contracts"]
    for contract_id, contract in contracts.items():
        schema = _mapping(_safe_path(repo_root, str(contract["path"])))
        actual = _schema_versions(schema, str(contract["version_field"]))
        declared = sorted(str(value) for value in contract["readable_versions"])
        if actual != declared:
            raise PublicContractError(
                f"{contract_id} readable versions differ from {contract['path']}"
            )
        if contract["active_version"] not in declared:
            raise PublicContractError(f"{contract_id} active version is not readable")
        migration = set(str(value) for value in contract["migration_only_versions"])
        if not migration.issubset(set(declared)) or contract["active_version"] in migration:
            raise PublicContractError(f"{contract_id} migration-only versions are inconsistent")

    graph = registry["ci_graph"]
    graph_payload = _mapping(_safe_path(repo_root, graph["canonical_path"]), yaml_document=True)
    graph_schema = _mapping(repo_root / "schemas/ci-graph.schema.json")
    extension_schema = _mapping(repo_root / "schemas/ci-graph-extension.schema.json")
    attachment = extension_schema["properties"]["extension"]["properties"][
        "attachment_point"
    ]["enum"]
    if list(graph["extension_points"]) != list(attachment):
        raise PublicContractError("public extension points differ from the extension schema")
    if list(graph_payload["extension_points"]) != list(attachment):
        raise PublicContractError("canonical graph extension points differ from the public contract")
    executor_kinds = _executor_kinds(graph_schema)
    if list(graph["executor_kinds"]) != executor_kinds:
        raise PublicContractError("public executor kinds differ from the graph schema")
    header = _literal_assignment(
        repo_root / "bcf_governance/tooling/ci_graph_render.py", "GENERATED_HEADER"
    )
    if graph["generated_header"] != header:
        raise PublicContractError("generated workflow provenance header differs from its renderer")

    return PublicContractInventory(
        package_version=version,
        command_count=len(commands),
        contract_count=len(contracts),
        extension_point_count=len(attachment),
        executor_kind_count=len(executor_kinds),
    )

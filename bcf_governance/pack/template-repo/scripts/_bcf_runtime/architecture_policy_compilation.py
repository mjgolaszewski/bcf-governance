"""Source draft: bind the router/duplication observer to governed YAML bytes.

Ownership declarations are preserved for a separately qualified membership
producer. They do not override the observer's conservative membership failures.
This component neither imports application code nor executes a native gate.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from jsonschema import Draft202012Validator

from .architecture_policy_input import _read as _read_bounded
from .architecture_policy_input import _yaml_document
from .architecture_source_observation import Policy


@dataclass(frozen=True)
class MetadataOwnership:
    path: str
    layer: str
    context: str
    exports: tuple[str, ...]


@dataclass(frozen=True)
class PolicyInput:
    policy: Policy
    config_sha256: str
    schema_sha256: str
    metadata_ownership: tuple[MetadataOwnership, ...]
    membership_declarations_qualified: bool = False


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError("expected a mapping with string keys")
    return dict(value)


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError("expected nonempty string members")
    result = tuple(str(item) for item in value)
    if len(set(result)) != len(result):
        raise ValueError("duplicate policy members")
    return result


def _integer(value: object, minimum: int) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError("invalid policy integer")
    return value


def _relative(value: str) -> str:
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts or path.as_posix() != value:
        raise ValueError("policy paths must be canonical relative paths")
    return value




def _reject_references(value: object) -> None:
    if isinstance(value, dict):
        if {"$ref", "$dynamicRef", "$recursiveRef"}.intersection(value):
            raise ValueError("this finite schema adapter does not resolve references")
        for member in value.values():
            _reject_references(member)
    elif isinstance(value, list):
        for member in value:
            _reject_references(member)






def _read_exact(path: Path, expected: str) -> bytes:
    raw = _read_bounded(path)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("policy input does not match its admitted SHA256")
    return raw


def load_policy(config: Path, schema: Path, *, config_sha256: str, schema_sha256: str) -> PolicyInput:
    config_raw = _read_exact(config, config_sha256)
    schema_raw = _read_exact(schema, schema_sha256)
    schema_document = _mapping(json.loads(schema_raw))
    _reject_references(schema_document)
    Draft202012Validator.check_schema(schema_document)
    document = _mapping(_yaml_document(config_raw))
    Draft202012Validator(schema_document).validate(document)
    if _mapping(document["document"])["path"] != "architecture-boundaries.yml":
        raise ValueError("unexpected governed policy document")
    architecture = _mapping(document["architecture"])
    duplication = _mapping(architecture["duplication_policy"])
    for name in ["enabled", "scoped_to_bounded_context", "allowed_cross_context_duplication"]:
        if duplication[name] is not True:
            raise ValueError(f"unsupported duplication policy: {name}")
    for name in ["layer_membership_policy", "context_membership_policy"]:
        expected = "exactly_one_layer" if name.startswith("layer") else "exactly_one_context"
        if _mapping(architecture[name])[expected] is not True:
            raise ValueError("unsupported membership policy")
    production = _mapping(architecture["production_module_policy"])
    contexts = _mapping(architecture["bounded_contexts"])
    if contexts["required"] is not True:
        raise ValueError("optional bounded contexts are unsupported")
    routers = _mapping(architecture["thin_router_policy"])
    layers = _mapping(architecture["layers"])
    tokens = tuple((name, _strings(_mapping(value)["path_tokens"])) for name, value in layers.items())
    roots = tuple(_relative(value) for value in _strings(architecture["source_roots"]))
    declarations = architecture.get("package_metadata_ownership", [])
    if not isinstance(declarations, list):
        raise ValueError("invalid metadata ownership declarations")
    ownership = []
    for value in declarations:
        row = _mapping(value)
        if not all(isinstance(row[key], str) for key in ["path", "layer", "context"]):
            raise ValueError("invalid metadata owner")
        path, layer, context = (str(row[key]) for key in ["path", "layer", "context"])
        if layer not in layers or Path(path).name != "__init__.py":
            raise ValueError("unsupported metadata ownership target")
        ownership.append(MetadataOwnership(_relative(path), layer, context, _strings(row["exports"])))
    if len({row.path for row in ownership}) != len(ownership):
        raise ValueError("duplicate metadata ownership paths")
    policy = Policy(roots, _strings(production["excluded_path_tokens"]),
                    _strings(production["excluded_file_suffixes"]), tokens,
                    _strings(contexts["context_root_tokens"]), _strings(contexts["shared_context_tokens"]),
                    _integer(routers["max_branch_nodes"], 0), _integer(routers["max_loop_nodes"], 0),
                    _strings(routers["delegate_call_name_tokens"]),
                    _integer(duplication["min_duplicate_lines"], 1),
                    tuple((row.path, row.layer, row.context, row.exports) for row in ownership))
    if _read_exact(config, config_sha256) != config_raw or _read_exact(schema, schema_sha256) != schema_raw:
        raise ValueError("policy inputs changed before producer completion")
    return PolicyInput(policy, config_sha256, schema_sha256, tuple(ownership))

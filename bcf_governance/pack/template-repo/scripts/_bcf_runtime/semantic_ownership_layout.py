"""Closed local source layout for the canonical representation registry."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .semantic_yaml import SemanticYAMLError, load_unique_bytes

ROOT = Path("governance/canonical-representations.yml")
SOURCE_DIR = Path("governance/canonical-representations")
MAX_SOURCES = 512
MAX_TOTAL_BYTES = 8 * 1024 * 1024
SOURCE_PATTERN = re.compile(r"governance/canonical-representations/[a-z0-9][a-z0-9_-]*\.yml\Z")


class RegistryLayoutError(ValueError):
    """A registry source is unsafe, incomplete, or ambiguous."""


def _source_path(value: object) -> Path:
    if not isinstance(value, str) or SOURCE_PATTERN.fullmatch(value) is None:
        raise RegistryLayoutError(f"unsafe representation source: {value!r}")
    return Path(value)


def _metadata_budget(repo_root: Path) -> tuple[int, int]:
    try:
        manifest = yaml.safe_load((repo_root / "governance/artifact-manifest.yml").read_bytes())
        cap = manifest["context_budgets"]["agent_required_files"][ROOT.as_posix()]
        return int(cap["line_hard_cap"]), int(cap["kib_hard_cap"]) * 1024
    except (OSError, UnicodeError, yaml.YAMLError, KeyError, TypeError, ValueError) as exc:
        raise RegistryLayoutError("cannot determine inherited registry context budget") from exc


def expand_sources(
    repo_root: Path,
    payload: dict[str, Any],
    *,
    reader: Callable[[Path], bytes] | None = None,
    check_orphans: bool = True,
) -> tuple[dict[str, Any], tuple[tuple[str, str], ...]]:
    """Return a logical flat registry and ordered byte digests of closed source files."""
    if "representation_sources" not in payload:
        return payload, ()
    if reader is None and (repo_root / ROOT).is_symlink():
        raise RegistryLayoutError("indexed registry root cannot be a symlink")
    refs = payload["representation_sources"]
    if not isinstance(refs, list) or not 1 <= len(refs) <= MAX_SOURCES:
        raise RegistryLayoutError("representation_sources must contain 1..512 explicit paths")
    paths = tuple(_source_path(ref) for ref in refs)
    if len(set(paths)) != len(paths):
        raise RegistryLayoutError("duplicate representation source")
    if "representations" in payload or payload.get("secondary_representations"):
        raise RegistryLayoutError("indexed root cannot contain inline representations")
    if check_orphans:
        directory = repo_root / SOURCE_DIR
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise RegistryLayoutError("representation source directory must be real")
        actual = {p.relative_to(repo_root) for p in directory.iterdir()} if directory.exists() else set()
        if actual != set(paths):
            raise RegistryLayoutError("undeclared or missing representation source")
    line_cap, byte_cap = _metadata_budget(repo_root)
    try:
        schema = json.loads((repo_root / "schemas/canonical-representations.schema.json").read_text())
        child_schema = schema["$defs"]["representationSource"]
    except (OSError, UnicodeError, KeyError, ValueError) as exc:
        raise RegistryLayoutError("cannot load representation source schema") from exc
    # Resolve the local $defs references without resolving external schemas.
    validator = Draft202012Validator({"$defs": schema["$defs"], **child_schema})
    read = reader or (lambda path: (repo_root / path).read_bytes())
    total = 0
    primary: list[dict[str, Any]] = []
    secondary: list[dict[str, Any]] = []
    secondary_families: list[str] = []
    digests: list[tuple[str, str]] = []
    document_ids: set[str] = set()
    for path in paths:
        physical = repo_root / path
        if reader is None and (physical.is_symlink() or not physical.is_file()):
            raise RegistryLayoutError(f"unsafe or missing representation source: {path}")
        try:
            raw = read(path)
            text = raw.decode("utf-8")
        except (OSError, UnicodeError, ValueError) as exc:
            raise RegistryLayoutError(f"cannot read representation source: {path}") from exc
        total += len(raw)
        if total > MAX_TOTAL_BYTES or len(raw) > byte_cap or len(text.splitlines()) > line_cap:
            raise RegistryLayoutError(f"representation source exceeds context budget: {path}")
        try:
            document = load_unique_bytes(raw)
        except (SemanticYAMLError, yaml.YAMLError) as exc:
            raise RegistryLayoutError(f"invalid representation source: {path}") from exc
        if not isinstance(document, dict):
            raise RegistryLayoutError(f"representation source must be a mapping: {path}")
        errors = sorted(validator.iter_errors(document), key=lambda e: str(e.path))
        if errors:
            raise RegistryLayoutError(f"invalid representation source {path}: {errors[0].message}")
        declared = document["document"]
        if declared["id"] in document_ids:
            raise RegistryLayoutError("duplicate representation source document identity")
        document_ids.add(declared["id"])
        if declared["path"] != path.as_posix():
            raise RegistryLayoutError(f"representation source path mismatch: {path}")
        family = declared["family"]
        if family not in payload["enforcement"]["declared_families"]:
            raise RegistryLayoutError(f"undeclared source family: {family}")
        for row in document.get("representations", []):
            if row["family"] != family:
                raise RegistryLayoutError(f"representation family mismatch: {path}")
            primary.append(row)
        for row in document.get("secondary_representations", []):
            secondary.append(row)
            secondary_families.append(family)
        digests.append((path.as_posix(), hashlib.sha256(raw).hexdigest()))
    if not primary:
        raise RegistryLayoutError("indexed registry has no primary representations")
    primary_ids = {str(row["semantic_id"]): str(row["family"]) for row in primary}
    secondary_ids = [str(row["id"]) for row in secondary]
    if len(secondary_ids) != len(set(secondary_ids)) or set(secondary_ids) & set(primary_ids):
        raise RegistryLayoutError("duplicate representation identity across sources")
    for row, family in zip(secondary, secondary_families, strict=True):
        if row["classification"] == "derived" and row["canonical_semantic_id"] not in primary_ids:
            raise RegistryLayoutError("derived representation has no canonical source identity")
        if row["classification"] == "derived" and primary_ids[row["canonical_semantic_id"]] != family:
            raise RegistryLayoutError("derived representation source family mismatch")
    result = {key: value for key, value in payload.items() if key != "representation_sources"}
    result["representations"] = primary
    if secondary or "secondary_representations" in payload:
        result["secondary_representations"] = secondary
    return result, tuple(digests)


def registry_digest(root_bytes: bytes, source_digests: tuple[tuple[str, str], ...]) -> str:
    """Keep flat lock identity unchanged; bind all indexed source bytes in order."""
    if not source_digests:
        return hashlib.sha256(root_bytes).hexdigest()
    closure = {"root_sha256": hashlib.sha256(root_bytes).hexdigest(), "sources": source_digests}
    return hashlib.sha256(json.dumps(closure, separators=(",", ":"), sort_keys=True).encode()).hexdigest()

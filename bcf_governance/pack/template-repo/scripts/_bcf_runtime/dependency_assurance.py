"""Exact installed dependency inventory and advisory-result primitives."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
from pathlib import Path
import tomllib
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import InvalidName, canonicalize_name
from packaging.version import InvalidVersion, Version


class DependencyAssuranceError(ValueError):
    """Raised when exact dependency assurance cannot be constructed."""


@dataclass(frozen=True)
class InstalledDependencyInventory:
    roots: tuple[str, ...]
    components: tuple[dict[str, Any], ...]
    dependencies: tuple[dict[str, Any], ...]
    sha256: str

    def payload(self) -> dict[str, Any]:
        return json.loads(json.dumps({
            "roots": list(self.roots),
            "components": list(self.components),
            "dependencies": list(self.dependencies),
        }, allow_nan=False))


def _declared_requirements(repo_root: Path) -> list[Requirement]:
    project = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))
    values: list[str] = []
    values.extend(project.get("build-system", {}).get("requires", []))
    values.extend(project.get("project", {}).get("dependencies", []))
    for requirements in project.get("project", {}).get("optional-dependencies", {}).values():
        values.extend(requirements)
    for raw in (repo_root / "requirements-governance.txt").read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#"):
            values.append(stripped)
    try:
        return [Requirement(value) for value in values]
    except Exception as exc:
        raise DependencyAssuranceError(f"declared dependency is malformed: {exc}") from exc


def _installed() -> dict[str, metadata.Distribution]:
    result: dict[str, metadata.Distribution] = {}
    for distribution in metadata.distributions():
        name = distribution.metadata.get("Name")
        if not isinstance(name, str) or not name:
            raise DependencyAssuranceError("installed dependency name is missing or malformed")
        try:
            identity = canonicalize_name(name, validate=True)
        except InvalidName as exc:
            raise DependencyAssuranceError("installed dependency name is invalid") from exc
        if identity in result:
            raise DependencyAssuranceError(f"ambiguous installed dependency: {identity}")
        result[identity] = distribution
    return result


def _requirement_applies(requirement: Requirement, active_extras: set[str]) -> bool:
    if requirement.marker is None:
        return True
    return any(
        requirement.marker.evaluate({"extra": extra})
        for extra in ({""} | active_extras)
    )


def collect_installed_inventory(repo_root: Path) -> InstalledDependencyInventory:
    """Derive the exact installed closure of every declared build/runtime root."""

    installed = _installed()
    queue: list[tuple[Requirement, set[str]]] = []
    roots: set[str] = set()
    for requirement in _declared_requirements(repo_root):
        name = canonicalize_name(requirement.name)
        roots.add(name)
        queue.append((requirement, set(requirement.extras)))
    selected: dict[str, metadata.Distribution] = {}
    versions_by_name: dict[str, str] = {}
    extras_by_name: dict[str, set[str]] = {}
    edges: dict[str, set[str]] = {}
    while queue:
        requirement, extras = queue.pop()
        name = canonicalize_name(requirement.name)
        distribution = installed.get(name)
        if distribution is None:
            raise DependencyAssuranceError(f"declared dependency is not installed: {name}")
        installed_version = distribution.version
        if (not isinstance(installed_version, str) or not installed_version
                or installed_version != installed_version.strip()):
            raise DependencyAssuranceError(f"installed dependency version is invalid: {name}")
        try:
            Version(installed_version)
        except InvalidVersion as exc:
            raise DependencyAssuranceError(f"installed dependency version is invalid: {name}") from exc
        if not requirement.specifier.contains(installed_version, prereleases=True):
            raise DependencyAssuranceError(f"installed dependency {name} violates declared requirement {requirement.specifier}")
        if name in versions_by_name and versions_by_name[name] != installed_version:
            raise DependencyAssuranceError(f"installed dependency version changed during inventory: {name}")
        versions_by_name[name] = installed_version
        previous = extras_by_name.setdefault(name, set())
        if name in selected and extras <= previous:
            continue
        previous.update(extras)
        selected[name] = distribution
        required: set[str] = set()
        for raw in distribution.requires or []:
            try:
                requirement = Requirement(raw)
            except (InvalidRequirement, TypeError) as exc:
                raise DependencyAssuranceError(f"installed dependency requirement is malformed: {name}") from exc
            if not _requirement_applies(requirement, previous):
                continue
            dependency = canonicalize_name(requirement.name)
            required.add(dependency)
            queue.append((requirement, set(requirement.extras)))
        edges[name] = required
    components = tuple(
        {
            "type": "library",
            "name": name,
            "version": versions_by_name[name],
            "bom-ref": f"pkg:pypi/{name}@{versions_by_name[name]}",
        }
        for name, distribution in sorted(selected.items())
    )
    dependencies = tuple(
        {
            "ref": f"pkg:pypi/{name}@{versions_by_name[name]}",
            "dependsOn": [
                f"pkg:pypi/{dependency}@{versions_by_name[dependency]}"
                for dependency in sorted(required)
                if dependency in selected
            ],
        }
        for name, required in sorted(edges.items())
    )
    payload = {
        "roots": sorted(roots),
        "components": components,
        "dependencies": dependencies,
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return InstalledDependencyInventory(
        roots=tuple(sorted(roots)),
        components=components,
        dependencies=dependencies,
        sha256=digest,
    )



def _validated_inventory_snapshot(inventory: InstalledDependencyInventory) -> tuple[dict[str, Any], str]:
    """Admit one owned exact payload; stored hashes cannot bless changed rows."""
    try:
        canonical = json.dumps(inventory.payload(), sort_keys=True, separators=(",", ":"),
                               allow_nan=False).encode()
        snapshot = json.loads(canonical)
        if (not isinstance(snapshot, dict) or set(snapshot) != {"roots", "components", "dependencies"}
                or any(not isinstance(snapshot[key], list) for key in snapshot)):
            raise ValueError("inventory payload shape")
        identities = [_scanner_dependency_identity(item) for item in snapshot["components"]]
        if any(value is None for value in identities) or len(set(identities)) != len(identities):
            raise ValueError("inventory component identities")
        if type(inventory.sha256) is not str or hashlib.sha256(canonical).hexdigest() != inventory.sha256:
            raise ValueError("inventory digest")
    except (AttributeError, TypeError, ValueError) as exc:
        raise DependencyAssuranceError("dependency inventory payload or digest is not exact") from exc
    return snapshot, hashlib.sha256(canonical).hexdigest()


def write_frozen_requirements(
    inventory: InstalledDependencyInventory, output: Path
) -> None:
    snapshot, _ = _validated_inventory_snapshot(inventory)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "".join(
            f"{component['name']}=={component['version']}\n"
            for component in snapshot["components"]
        ),
        encoding="utf-8",
    )


def _scanner_dependency_identity(item: Any) -> tuple[str, str] | None:
    """Identify one selected or scanned distribution without accepting missing fields."""
    if not isinstance(item, dict):
        return None
    name, version = item.get("name"), item.get("version")
    if not isinstance(name, str) or not isinstance(version, str) or not version.strip():
        return None
    if version != version.strip():
        return None
    try:
        return canonicalize_name(name, validate=True), version
    except InvalidName:
        return None


def audit_envelope(
    *,
    inventory: InstalledDependencyInventory,
    scanner_version: str,
    service: str,
    returncode: int,
    raw: dict[str, Any] | None,
    diagnostic: str,
) -> dict[str, Any]:
    """Classify one complete scanner result; ambiguity never becomes clean."""

    inventory_valid = raw_valid = True
    try:
        snapshot, inventory_digest = _validated_inventory_snapshot(inventory)
    except DependencyAssuranceError as exc:
        snapshot, inventory_digest, inventory_valid = {"components": []}, inventory.sha256, False
        diagnostic = str(exc) + (": " + diagnostic if diagnostic else "")
    try:
        raw = json.loads(json.dumps(raw, sort_keys=True, separators=(",", ":"), allow_nan=False))
    except (TypeError, ValueError):
        raw, raw_valid = None, False
        diagnostic = "scanner JSON is malformed or nonfinite" + (": " + diagnostic if diagnostic else "")
    dependencies = raw.get("dependencies") if isinstance(raw, dict) else None
    findings = [
        {"name": item.get("name"), "version": item.get("version"), "vulnerabilities": vulns}
        for item in dependencies if isinstance(item, dict)
        and isinstance((vulns := item.get("vulns")), list) and vulns
    ] if isinstance(dependencies, list) else []
    selected = [_scanner_dependency_identity(item) for item in snapshot["components"]]
    complete = (inventory_valid and raw_valid and all(identity is not None for identity in selected)
                and len(set(selected)) == len(selected)
                and isinstance(dependencies, list))
    observed: set[tuple[str, str]] = set()
    if isinstance(dependencies, list):
        for item in dependencies:
            identity = _scanner_dependency_identity(item)
            if identity is None or identity in observed or not isinstance(item, dict):
                complete = False
                continue
            observed.add(identity)
            vulnerabilities = item.get("vulns")
            if "skip_reason" in item or not isinstance(vulnerabilities, list):
                complete = False
                continue
            if any(not isinstance(row, dict) or not isinstance(row.get("id"), str)
                   or not row["id"].strip() for row in vulnerabilities):
                complete = False
    complete = complete and observed == set(selected)
    if isinstance(raw, dict) and "fixes" in raw and raw["fixes"] != []:
        complete = False
    if type(returncode) is not int or returncode not in {0, 1} or not complete:
        status = "scanner_failure"
        diagnostic = diagnostic or "scanner result does not account for the exact selected inventory"
    elif returncode == 0 and not findings:
        status = "clean"
    elif returncode == 1 and findings:
        status = "vulnerable"
    else:
        status = "scanner_failure"
        diagnostic = diagnostic or "scanner exit and vulnerability population contradict each other"
    raw_digest = hashlib.sha256(
        json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
        if raw is not None
        else b""
    ).hexdigest()
    return {
        "kind": "dependency_advisory_observation",
        "schema_version": "1.0",
        "status": status,
        "scanner": {"name": "pip-audit", "version": scanner_version},
        "advisory_source": {"service": service, "observed_at": datetime.now(timezone.utc).isoformat()},
        "inventory_sha256": inventory_digest,
        "inventory_component_count": len(snapshot["components"]),
        "raw_result_sha256": raw_digest,
        "raw_result": raw,
        "findings": findings,
        "diagnostic": diagnostic,
    }


def cyclonedx_sbom(inventory: InstalledDependencyInventory) -> dict[str, Any]:
    snapshot, digest = _validated_inventory_snapshot(inventory)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"properties": [{"name": "bcf:inventory_sha256", "value": digest}]},
        "components": snapshot["components"],
        "dependencies": snapshot["dependencies"],
    }


def _native_scan_json(raw: bytes) -> dict[str, Any]:
    """Decode one unambiguous JSON document without accepting hidden fields."""
    def mapping(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate native scan JSON field")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=mapping,
                       parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite native JSON")))
    if not isinstance(value, dict):
        raise ValueError("native scan JSON must be an object")
    return value


def _native_component_identity(row) -> tuple[str, str, str]:
    values = tuple(row.get(key) for key in ("purl", "name", "version")) if isinstance(row, dict) else ()
    if (len(values) != 3 or any(type(value) is not str or not value or value != value.strip()
                              or "\0" in value for value in values) or not values[0].startswith("pkg:")):
        raise DependencyAssuranceError("native package identity is missing or malformed")
    return values


def _native_file_digest(path: Path, deadline: float) -> str:
    import stat
    import time
    try:
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            raise DependencyAssuranceError("native scan input must be a regular nonsymlink file")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while True:
                if time.monotonic() >= deadline:
                    raise DependencyAssuranceError("native scan admission budget exhausted")
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        raise DependencyAssuranceError("native scan input file is unavailable") from exc


def _native_database_binding(root: Path, expected, deadline: float) -> dict[str, str]:
    if type(expected) is not dict or not expected or root.is_symlink() or not root.is_dir():
        raise DependencyAssuranceError("native database requires an exact file inventory")
    if any(type(key) is not str or not key or key.startswith("/") or "\\" in key
           or any(part in {"", ".", ".."} for part in key.split("/"))
           or type(value) is not str or len(value) != 64
           or any(character not in "0123456789abcdef" for character in value)
           for key, value in expected.items()):
        raise DependencyAssuranceError("native database file inventory is malformed")
    actual = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise DependencyAssuranceError("native database member is not regular")
        if path.is_file():
            actual[path.relative_to(root).as_posix()] = _native_file_digest(path, deadline)
    if actual != expected:
        raise DependencyAssuranceError("native database file inventory differs")
    return actual


def capture_native_dependency_audit(
    *, sbom_bytes: bytes, expected_sbom_sha256: str, expected_image: dict[str, str],
    expected_inventory: tuple[tuple[str, str, str], ...], scanner: Path,
    expected_scanner_sha256: str, database_root: Path, expected_database_files: dict[str, str],
    expected_database_status: dict[str, Any], max_database_age_seconds: int,
    command_seconds: int, output_dir: Path,
) -> dict[str, Any]:
    """Capture one exact Grype input through the existing native execution owner.

    Independent subjects/pins are authenticated by the protected caller. This
    observation confers no runtime, security, phase or release authority.
    """
    import math
    import os
    import re
    import threading
    import subprocess
    import time
    from . import evidence_process_supervisor as commands
    from .release_runtime_verification import runtime_environment

    lease = commands._native_lease
    if lease is None or lease[1] != threading.get_ident():
        raise DependencyAssuranceError("native scan requires an existing execution owner")
    identity = os.fstat(lease[0])
    if (identity.st_dev, identity.st_ino) != lease[2:4]:
        raise DependencyAssuranceError("native execution owner identity differs")
    if type(command_seconds) is not int or command_seconds <= 0:
        raise DependencyAssuranceError("native scan requires a positive command budget")
    try:
        if not math.isfinite(float(command_seconds)):
            raise ValueError("unbounded native command budget")
        deadline = time.monotonic() + command_seconds
    except (ValueError, OverflowError) as exc:
        raise DependencyAssuranceError("native scan command budget is incompatible") from exc
    if type(sbom_bytes) is not bytes:
        raise DependencyAssuranceError("native SBOM input must be owned finite bytes")
    def hex_digest(value):
        return type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) is not None
    if not hex_digest(expected_sbom_sha256) or hashlib.sha256(sbom_bytes).hexdigest() != expected_sbom_sha256:
        raise DependencyAssuranceError("native SBOM byte digest differs")
    try:
        sbom = _native_scan_json(sbom_bytes)
        if sbom.get("schema", {}).get("version") != "16.1.13":
            raise ValueError("native SBOM schema is unsupported")
        if (type(expected_image) is not dict
                or set(expected_image) != {"manifestDigest", "imageID", "architecture", "os"}
                or any(type(value) is not str or not value for value in expected_image.values())
                or any(re.fullmatch(r"sha256:[a-f0-9]{64}", expected_image[key]) is None
                       for key in ("manifestDigest", "imageID"))):
            raise ValueError("native image subject is not exact")
        source = sbom["source"]
        if (source.get("type") != "image" or source.get("id") != expected_image["manifestDigest"][7:]
                or any(source["metadata"].get(key) != value for key, value in expected_image.items())):
            raise ValueError("native image manifest/config subject differs")
        if (type(expected_inventory) is not tuple or not expected_inventory
                or any(type(row) is not tuple or len(row) != 3 for row in expected_inventory)):
            raise ValueError("native independent inventory is missing")
        wanted = [_native_component_identity(dict(zip(("purl", "name", "version"), row))) for row in expected_inventory]
        artifacts = sbom["artifacts"]
        if not isinstance(artifacts, list) or not artifacts:
            raise ValueError("native SBOM inventory is missing")
        observed = [_native_component_identity(row) for row in artifacts]
        if (len(set(wanted)) != len(wanted) or len({row[0] for row in wanted}) != len(wanted)
                or len(set(observed)) != len(observed) or len({row[0] for row in observed}) != len(observed)):
            raise ValueError("native package inventory is ambiguous")
        if sorted(observed) != sorted(wanted):
            raise ValueError("native package inventory differs")
        artifact_ids = [row["id"] for row in artifacts]
        if any(type(value) is not str or not value for value in artifact_ids) or len(set(artifact_ids)) != len(artifact_ids):
            raise ValueError("native artifact IDs are ambiguous")
        if (type(max_database_age_seconds) is not int or max_database_age_seconds <= 0
                or max_database_age_seconds > (2**63 - 1) // 1_000_000_000
                or type(expected_database_status) is not dict
                or set(expected_database_status) != {"schemaVersion", "from", "built", "valid"}
                or expected_database_status["valid"] is not True
                or any(type(expected_database_status[key]) is not str or not expected_database_status[key]
                       for key in ("schemaVersion", "from", "built"))):
            raise ValueError("native database status is incomplete")
        built = datetime.fromisoformat(expected_database_status["built"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if built.tzinfo is None or not 0 <= (now - built).total_seconds() <= max_database_age_seconds:
            raise ValueError("native database is stale or future dated")
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise DependencyAssuranceError("native scan admission failed: " + str(exc)) from exc
    if not hex_digest(expected_scanner_sha256) or _native_file_digest(scanner, deadline) != expected_scanner_sha256:
        raise DependencyAssuranceError("native scanner executable digest differs")
    bound_database = _native_database_binding(database_root, expected_database_files, deadline)
    if output_dir.exists() or output_dir.is_symlink():
        raise DependencyAssuranceError("native scan output must be fresh")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DependencyAssuranceError("native scan admission budget exhausted")
    configuration = {"ignore": [], "exclude": [], "only-fixed": False, "only-notfixed": False,
                     "ignore-wontfix": "", "vex-documents": [], "check-for-app-update": False,
                     "include-matcher-suppressions": True, "match-upstream-kernel-headers": True,
                     "db": {"cache-dir": str(database_root.resolve()), "auto-update": False,
                            "validate-age": True, "max-allowed-built-age": str(max_database_age_seconds) + "s"}}
    config_bytes = json.dumps(configuration, sort_keys=True).encode()
    output_dir.mkdir(parents=True, mode=0o700)
    config_path = output_dir / "scanner-config.json"
    config_path.write_bytes(config_bytes)
    (output_dir / "scanner-input.json").write_bytes(sbom_bytes)
    environment = runtime_environment(home=output_dir)
    environment.update(GRYPE_DB_CACHE_DIR=str(database_root.resolve()), GRYPE_DB_AUTO_UPDATE="false",
                       GRYPE_DB_VALIDATE_AGE="true", GRYPE_DB_MAX_ALLOWED_BUILT_AGE=str(max_database_age_seconds) + "s",
                       GRYPE_CHECK_FOR_APP_UPDATE="false", GRYPE_EXTERNAL_SOURCES_ENABLE="false")
    stdout = stderr = b""
    returncode = None
    diagnostic = ""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DependencyAssuranceError("native scan admission budget exhausted before execution")
    try:
        result = commands.run_admitted_command(
            [str(scanner.resolve()), "--config", str(config_path.resolve()), "sbom:/proc/self/fd/0", "--output", "json"],
            unbound_runner=subprocess.run, cwd=output_dir, env=environment, input=sbom_bytes,
            capture_output=True, text=False, check=False, timeout=remaining,
        )
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = exc.output or b"", exc.stderr or b""
        diagnostic = "native scanner exhausted its command budget"
    except OSError:
        diagnostic = "native scanner could not start"
    (output_dir / "scanner.stdout").write_bytes(stdout)
    (output_dir / "scanner.stderr").write_bytes(stderr)
    findings = []
    status = "scanner_failure"
    try:
        if _native_file_digest(scanner, deadline) != expected_scanner_sha256:
            raise ValueError("native scanner changed during execution")
        _native_database_binding(database_root, bound_database, deadline)
        if (output_dir / "scanner-input.json").read_bytes() != sbom_bytes or config_path.read_bytes() != config_bytes:
            raise ValueError("native execution input capture changed")
        scan = _native_scan_json(stdout)
        for key in ("matches", "ignoredMatches"):
            rows = scan.get(key, [] if key == "ignoredMatches" else None)
            if not isinstance(rows, list):
                raise ValueError("native findings population is malformed")
            for row in rows:
                if not isinstance(row, dict):
                    raise ValueError("native finding is malformed")
                artifact, vulnerability = row["artifact"], row["vulnerability"]
                identity = _native_component_identity(artifact)
                if (dict(zip(artifact_ids, observed)).get(artifact.get("id")) != identity
                        or type(vulnerability.get("id")) is not str or not vulnerability["id"].strip()):
                    raise ValueError("native finding does not bind the selected inventory")
                findings.append({"id": vulnerability["id"], "purl": identity[0], "name": identity[1],
                                 "version": identity[2], "severity": vulnerability.get("severity"),
                                 "suppressed": key == "ignoredMatches"})
        descriptor = scan["descriptor"]
        if descriptor.get("name") != "grype" or descriptor.get("version") != "0.122.1":
            raise ValueError("native scanner profile is unsupported")
        target = scan["source"]
        if target.get("type") != "image" or any(target["target"].get(key) != value for key, value in expected_image.items()):
            raise ValueError("native result source subject differs")
        actual_db = descriptor["db"]["status"]
        if actual_db.get("valid") is not True or any(actual_db.get(key) != value for key, value in expected_database_status.items()):
            raise ValueError("native result database status differs")
        options = descriptor["configuration"]
        if (options.get("only-fixed") is not False or options.get("only-notfixed") is not False
                or options.get("ignore-wontfix") != "" or options.get("exclude") != []
                or options.get("vex-documents") != [] or options.get("include-matcher-suppressions") is not True
                or options.get("match-upstream-kernel-headers") is not True):
            raise ValueError("native scanner filtering or suppression retention is incompatible")
        if type(returncode) is not int or returncode != 0:
            raise ValueError("native scanner execution did not complete successfully")
        if not 0 <= (datetime.now(timezone.utc) - built).total_seconds() <= max_database_age_seconds:
            raise ValueError("native database expired during execution")
        status = "findings_present" if findings else "no_findings"
    except (DependencyAssuranceError, ValueError, TypeError, KeyError, AttributeError) as exc:
        diagnostic = diagnostic or str(exc)
    observation = {"kind": "dependency_advisory_observation", "schema_version": "1.1",
                   "authority": False, "execution_qualified": False, "security_qualified": False,
                   "scope": "exact_native_scan_input_only", "status": status, "diagnostic": diagnostic,
                   "scanner": {"name": "grype", "version": "0.122.1", "sha256": expected_scanner_sha256},
                   "subject": dict(expected_image), "inventory_component_count": len(observed),
                   "inventory_sha256": hashlib.sha256(json.dumps(sorted(observed), separators=(",", ":")).encode()).hexdigest(),
                   "sbom_sha256": expected_sbom_sha256, "configuration_sha256": hashlib.sha256(config_bytes).hexdigest(),
                   "database_files": bound_database, "database_status": dict(expected_database_status),
                   "observed_at": datetime.now(timezone.utc).isoformat(), "returncode": returncode,
                   "raw_result_sha256": hashlib.sha256(stdout).hexdigest(),
                   "stderr_sha256": hashlib.sha256(stderr).hexdigest(), "findings": findings}
    (output_dir / "native-audit.json").write_text(json.dumps(observation, indent=2, sort_keys=True) + "\n")
    return observation


def native_archive_subject(
    archive_bytes: bytes, *, expected_archive_sha256: str, expected_manifest_digest: str,
    max_archive_bytes: int, max_expanded_bytes: int, max_members: int,
    sbom_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Bind a single-image OCI archive without extracting or executing it.

    The protected caller authenticates pins and budgets. Optional Syft metadata
    binds config and ordered layer identities, not its normalized manifest label.
    Neither package completeness nor runtime/security authority follows.
    """
    import gzip
    import io
    import re
    import tarfile
    from pathlib import PurePosixPath

    def reject(message):
        raise DependencyAssuranceError("native archive " + message)

    def digest(value):
        return type(value) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", value) is not None

    def blob_path(value):
        if not digest(value):
            reject("descriptor digest is invalid")
        return "blobs/sha256/" + value[7:]

    try:
        if (any(type(value) is not int or not 0 < value < 2**63 - 1 for value in
                (max_archive_bytes, max_expanded_bytes, max_members))
                or type(archive_bytes) is not bytes or len(archive_bytes) > max_archive_bytes
                or type(expected_archive_sha256) is not str
                or re.fullmatch(r"[a-f0-9]{64}", expected_archive_sha256) is None
                or hashlib.sha256(archive_bytes).hexdigest() != expected_archive_sha256
                or not digest(expected_manifest_digest)):
            reject("input bytes, pins or bounds are invalid")
        files = {}
        names = set()
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
            for member in archive:
                if len(names) >= max_members or member.name in names:
                    reject("member population is duplicated or exceeds its bound")
                names.add(member.name)
                path = PurePosixPath(member.name)
                if (path.is_absolute() or ".." in path.parts or path.as_posix() != member.name
                        or member.pax_headers or member.issparse()
                        or not (member.isdir() or member.isfile())):
                    reject("member path or type is unsupported")
                if member.isdir():
                    continue
                with archive.extractfile(member) as stream:
                    raw = stream.read(max_archive_bytes + 1)
                if len(raw) != member.size or len(raw) > max_archive_bytes:
                    reject("member byte length differs")
                if member.name.startswith("blobs/sha256/"):
                    if (len(member.name) != len("blobs/sha256/") + 64
                            or hashlib.sha256(raw).hexdigest() != member.name.split("/")[-1]):
                        reject("blob bytes differ from their address")
                files[member.name] = raw
            end_offset = archive.offset
        if any(archive_bytes[end_offset:]):
            reject("nonzero trailing archive bytes are ambiguous")
        if _native_scan_json(files["oci-layout"]) != {"imageLayoutVersion": "1.0.0"}:
            reject("OCI layout is unsupported")
        index = _native_scan_json(files["index.json"])
        if (type(index.get("schemaVersion")) is not int or index["schemaVersion"] != 2
                or type(index.get("manifests")) is not list or len(index["manifests"]) != 1
                or index["manifests"][0].get("digest") != expected_manifest_digest):
            reject("index does not identify one exact admitted manifest")
        used = {"oci-layout", "index.json"}

        def descriptor(value, media_types):
            if (type(value) is not dict or value.get("mediaType") not in media_types
                    or type(value.get("size")) is not int or value["size"] < 0):
                reject("descriptor shape or media type is invalid")
            name = blob_path(value.get("digest"))
            raw = files[name]
            if len(raw) != value["size"]:
                reject("descriptor size differs from blob bytes")
            used.add(name)
            return raw

        manifest_raw = descriptor(index["manifests"][0], {"application/vnd.oci.image.manifest.v1+json"})
        manifest = _native_scan_json(manifest_raw)
        if (type(manifest.get("schemaVersion")) is not int or manifest["schemaVersion"] != 2
                or manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
                or type(manifest.get("layers")) is not list or not manifest["layers"]):
            reject("manifest shape is unsupported")
        config = _native_scan_json(descriptor(manifest["config"], {"application/vnd.oci.image.config.v1+json"}))
        if (any(type(config.get(key)) is not str or not config[key] for key in ("architecture", "os"))
                or config["os"] != "linux" or config.get("rootfs", {}).get("type") != "layers"):
            reject("config platform or rootfs is unsupported")
        diffs = config["rootfs"]["diff_ids"]
        if type(diffs) is not list or len(diffs) != len(manifest["layers"]) or any(not digest(v) for v in diffs):
            reject("ordered rootfs layer population differs")
        expanded = 0
        layers = []
        for layer, diff in zip(manifest["layers"], diffs):
            raw = descriptor(layer, {"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip"})
            stream = gzip.GzipFile(fileobj=io.BytesIO(raw)) if layer["mediaType"].endswith("+gzip") else io.BytesIO(raw)
            hashed = hashlib.sha256()
            size = 0
            with stream:
                while chunk := stream.read(min(1024 * 1024, max_expanded_bytes - expanded + 1)):
                    expanded += len(chunk)
                    size += len(chunk)
                    if expanded > max_expanded_bytes:
                        reject("expanded layer population exceeds its bound")
                    hashed.update(chunk)
            if "sha256:" + hashed.hexdigest() != diff:
                reject("expanded layer bytes differ from rootfs identity")
            layers.append({"digest": layer["digest"], "diff_id": diff, "size_bytes": len(raw), "expanded_bytes": size})
        if "manifest.json" in files:
            def compatibility_pairs(items):
                result = {}
                for key, value in items:
                    if key in result:
                        reject("Docker projection contains duplicate JSON keys")
                    result[key] = value
                return result
            compatibility = json.loads(files["manifest.json"], object_pairs_hook=compatibility_pairs)
            json.dumps(compatibility, allow_nan=False)
            if (type(compatibility) is not list or len(compatibility) != 1
                    or compatibility[0].get("Config") != blob_path(manifest["config"]["digest"])
                    or compatibility[0].get("Layers") != [blob_path(v["digest"]) for v in manifest["layers"]]):
                reject("Docker compatibility projection differs from OCI identity")
            used.add("manifest.json")
        if set(files) != used:
            reject("unreferenced or unknown archive files remain")
        binding = None
        if sbom_bytes is not None:
            if type(sbom_bytes) is not bytes:
                reject("SBOM must be immutable bytes")
            sbom = _native_scan_json(sbom_bytes)
            source = sbom["source"]
            metadata = source["metadata"]
            if (sbom.get("schema", {}).get("version") != "16.1.13" or source.get("type") != "image"
                    or metadata.get("imageID") != manifest["config"]["digest"]
                    or any(metadata.get(key) != config[key] for key in ("architecture", "os"))
                    or not digest(metadata.get("manifestDigest"))
                    or source.get("id") != metadata["manifestDigest"][7:]
                    or [v.get("digest") for v in metadata["layers"]] != diffs):
                reject("SBOM config, platform or ordered layer identity differs")
            binding = {"sbom_sha256": hashlib.sha256(sbom_bytes).hexdigest(),
                       "normalized_manifest_digest": metadata["manifestDigest"],
                       "normalized_manifest_independently_verified": False}
        return {"authority": False, "security_qualified": False,
                "archive_sha256": expected_archive_sha256, "archive_manifest_digest": expected_manifest_digest,
                "config_digest": manifest["config"]["digest"], "architecture": config["architecture"],
                "os": config["os"], "layers": layers, "sbom_binding": binding}
    except DependencyAssuranceError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OSError, EOFError, tarfile.TarError) as exc:
        raise DependencyAssuranceError("native archive is malformed or incomplete") from exc

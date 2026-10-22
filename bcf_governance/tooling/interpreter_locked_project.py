"""Compile a bounded selected uv lock graph; never resolve or inspect installed packages."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib
from typing import Any, NoReturn

from packaging.markers import Marker, InvalidMarker
from packaging.requirements import Requirement, InvalidRequirement
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.version import Version, InvalidVersion
import yaml  # type: ignore[import-untyped]

from .interpreter_environment_plan import InterpreterEnvironmentError, InterpreterEnvironmentPlan
from .python_runtime_selection import interpreter_subprocess_environment


MARKER_KEYS = frozenset({
    "implementation_name", "implementation_version", "os_name", "platform_machine",
    "platform_release", "platform_system", "platform_version", "python_full_version",
    "platform_python_implementation", "python_version", "sys_platform",
})


def normalize_locked_project_contract(value: object) -> dict[str, Any]:
    """Normalize the explicit selector without reading source or host defaults."""
    contract = _mapping(value)
    if set(contract) != {"lockfile", "dependency_groups", "optional_extras", "marker_environment", "runtime_platform"} or contract["lockfile"] != "uv.lock":
        _fail("contract fields are invalid")
    environment = _mapping(contract["marker_environment"])
    if set(environment) != MARKER_KEYS or any(not isinstance(v, str) or not v for v in environment.values()):
        _fail("requires a complete explicit marker environment")
    result: dict[str, Any] = {"lockfile": "uv.lock", "marker_environment": dict(sorted(environment.items()))}
    runtime_platform = _mapping(contract["runtime_platform"])
    if set(runtime_platform) != {"sysconfig_platform", "libc_name", "libc_version"} or any(
        not isinstance(value, str) for value in runtime_platform.values()
    ) or not runtime_platform["sysconfig_platform"]:
        _fail("runtime platform bindings are incomplete")
    result["runtime_platform"] = dict(sorted(runtime_platform.items()))
    for field in ("dependency_groups", "optional_extras"):
        names = [_name(name) for name in _rows(contract[field])]
        if len(set(names)) != len(names):
            _fail("selected groups or extras are duplicated")
        result[field] = names
    return result


def _fail(message: str) -> NoReturn:
    raise InterpreterEnvironmentError("locked project " + message)


def _name(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", value):
        _fail("name is invalid")
    return re.sub(r"[-_.]+", "-", value).lower()


def _mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("mapping is invalid")
    return value


def _rows(value: object) -> list[Any]:
    if not isinstance(value, list):
        _fail("dependency inventory is invalid")
    return value


def _named_mapping(value: object) -> dict[str, Any]:
    rows = _mapping(value)
    result = {_name(name): item for name, item in rows.items()}
    if len(result) != len(rows):
        _fail("names are ambiguous after normalization")
    return result


def _requirement(value: object) -> Requirement:
    if not isinstance(value, str):
        _fail("requirement is invalid")
    try:
        parsed = Requirement(value)
    except InvalidRequirement as exc:
        raise InterpreterEnvironmentError("locked project requirement is invalid") from exc
    if parsed.url:
        _fail("URL requirements are unsupported")
    return parsed


def _active(value: object, environment: dict[str, str], extra: str = "") -> bool:
    if value is None:
        return True
    if not isinstance(value, str) or re.search(r"\b(extras|dependency_groups)\b", value):
        _fail("marker uses unsupported applicability")
    try:
        return Marker(value).evaluate({**environment, "extra": extra})
    except (InvalidMarker, ValueError, KeyError) as exc:
        raise InterpreterEnvironmentError("locked project marker is invalid") from exc


def _metadata_requirement(value: object) -> Requirement:
    row = _mapping(value)
    if set(row) - {"name", "specifier", "extras", "marker"}:
        _fail("requirement metadata contains unsupported fields")
    name = _name(row.get("name"))
    extras = sorted(_name(item) for item in _rows(row.get("extras", [])))
    if len(set(extras)) != len(extras) or ("marker" in row and not isinstance(row["marker"], str)):
        _fail("requirement metadata is ambiguous or invalid")
    suffix = "[" + ",".join(extras) + "]" if extras else ""
    marker = "; " + row["marker"] if isinstance(row.get("marker"), str) else ""
    return _requirement(name + suffix + str(row.get("specifier", "")) + marker)


def _same_requirements(authored: list[str], metadata: object) -> None:
    def key(req: Requirement) -> tuple[str, tuple[str, ...], str, str]:
        return (_name(req.name), tuple(sorted(_name(x) for x in req.extras)),
                str(req.specifier), str(req.marker) if req.marker else "")
    expected = sorted(key(_requirement(value)) for value in authored)
    actual = sorted(key(_metadata_requirement(value)) for value in _rows(metadata))
    if expected != actual:
        _fail("lock metadata differs from authored requirements")


def _group_requirements(groups: dict[str, Any], name: str, stack: tuple[str, ...] = ()) -> list[str]:
    normalized = _name(name)
    if normalized in stack or normalized not in groups:
        _fail("dependency group is missing or cyclic")
    result: list[str] = []
    for item in _rows(groups[normalized]):
        if isinstance(item, str):
            _requirement(item)
            result.append(item)
        elif isinstance(item, dict) and set(item) == {"include-group"}:
            result.extend(_group_requirements(groups, item["include-group"], (*stack, normalized)))
        else:
            _fail("dependency group include is invalid")
    return result


def _read_sources(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    digest = hashlib.sha256()
    payloads: dict[str, bytes] = {}
    try:
        for relative in ("pyproject.toml", "uv.lock", "governance/gate-contracts.yml"):
            path = root / relative
            if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root) or any(
                parent.is_symlink() for parent in path.parents if parent != root and parent.is_relative_to(root)
            ):
                _fail("source is missing or unsafe")
            if path.stat().st_size > 16 * 1024**2:
                _fail("source exceeds bounded size")
            raw = path.read_bytes()
            if len(raw) > 16 * 1024**2:
                _fail("source exceeds bounded size")
            payloads[relative] = raw
            digest.update(relative.encode() + b"\0" + raw + b"\0")
        project = tomllib.loads(payloads["pyproject.toml"].decode())
        lock = tomllib.loads(payloads["uv.lock"].decode())
        registry = _mapping(yaml.safe_load(payloads["governance/gate-contracts.yml"]))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, yaml.YAMLError) as exc:
        raise InterpreterEnvironmentError("locked project source is unreadable") from exc
    return project, lock, registry, digest.hexdigest()


def compile_locked_project(root: Path, declared: object, installer: str) -> InterpreterEnvironmentPlan:
    """Select one reachable immutable graph under explicit authored marker bindings."""
    root = root.resolve()
    project, lock, registry, digest = _read_sources(root)
    if set(lock) - {"version", "revision", "requires-python", "resolution-markers", "package"}:
        _fail("unsupported lock configuration")
    uv = _mapping(_mapping(project.get("tool", {})).get("uv", {}))
    if set(uv) - {"required-version"}:
        _fail("unsupported uv resolution configuration")
    if "required-version" in uv:
        try:
            if not isinstance(uv["required-version"], str) or not uv["required-version"]:
                _fail("unsupported uv authoring configuration")
            SpecifierSet(uv["required-version"])
        except InvalidSpecifier as exc:
            raise InterpreterEnvironmentError("locked project unsupported uv authoring configuration") from exc
    contract = _mapping(declared)
    if _mapping(registry.get("interpreter_contract")) != {"locked_project": contract}:
        _fail("contract is ambiguous or changed")
    contract = normalize_locked_project_contract(contract)
    environment = _mapping(contract["marker_environment"])
    if set(environment) != MARKER_KEYS or any(not isinstance(v, str) or not v for v in environment.values()):
        _fail("requires a complete explicit marker environment")
    try:
        version = Version(environment["python_full_version"])
        if environment["python_version"] != ".".join(str(version).split(".")[:2]):
            _fail("Python marker bindings disagree")
        if type(lock.get("version")) is not int or lock.get("version") != 1 or lock.get("revision") != 5:
            _fail("lock format is unsupported")
        metadata = _mapping(project.get("project"))
        if not all(SpecifierSet(str(spec)).contains(version, prereleases=True)
                   for spec in (metadata.get("requires-python"), lock.get("requires-python"))):
            _fail("selected Python violates declared sources")
    except (InvalidVersion, InvalidSpecifier) as exc:
        raise InterpreterEnvironmentError("locked project Python contract is invalid") from exc
    forks = _rows(lock.get("resolution-markers", []))
    if forks and sum(_active(marker, environment) for marker in forks) != 1:
        _fail("selected lock fork is missing or ambiguous")
    records = [_mapping(item) for item in _rows(lock.get("package"))]
    if len(records) > 10000:
        _fail("lock graph exceeds bounded record count")
    project_name = _name(metadata.get("name"))
    roots = [row for row in records if _name(row.get("name")) == project_name
             and row.get("source") == {"editable": "."}]
    if len(roots) != 1 or roots[0].get("version") != metadata.get("version"):
        _fail("root identity is missing or ambiguous")
    local = roots[0]
    authored = list(_rows(metadata.get("dependencies")))
    optional_roots = _named_mapping(metadata.get("optional-dependencies", {}))
    metadata_authored = list(authored)
    for extra, rows in optional_roots.items():
        for raw in _rows(rows):
            req = _requirement(raw)
            if req.marker is not None:
                _fail("root optional requirements with nested markers are unsupported")
            metadata_authored.append(str(req) + "; extra == '" + extra + "'")
    _same_requirements(metadata_authored, _mapping(local.get("metadata")).get("requires-dist"))
    selected_groups = [_name(item) for item in _rows(contract["dependency_groups"])]
    selected_extras = [_name(item) for item in _rows(contract["optional_extras"])]
    if len(selected_groups) != len(set(selected_groups)) or len(selected_extras) != len(set(selected_extras)):
        _fail("selected groups or extras are duplicated")
    groups = _named_mapping(project.get("dependency-groups", {}))
    locked_groups = _named_mapping(local.get("dev-dependencies", {}))
    group_metadata = _named_mapping(_mapping(local.get("metadata")).get("requires-dev", {}))
    edges = list(_rows(local.get("dependencies", [])))
    locked_optional = _named_mapping(local.get("optional-dependencies", {}))
    for extra in selected_extras:
        if extra not in optional_roots or extra not in locked_optional:
            _fail("selected root optional extra is missing")
        authored.extend(_rows(optional_roots[extra]))
        edges.extend(_rows(locked_optional[extra]))
    for group in selected_groups:
        requirements = _group_requirements(groups, group)
        if group not in group_metadata or group not in locked_groups:
            _fail("selected dependency group is absent from lock")
        _same_requirements(requirements, group_metadata[group])
        authored.extend(requirements)
        edges.extend(_rows(locked_groups[group]))
    active_requirements = [req for raw in authored if (req := _requirement(raw))
                           and _active(str(req.marker) if req.marker else None, environment)]
    active_edges = [_mapping(edge) for edge in edges
                    if _active(_mapping(edge).get("marker"), environment)]
    expected_edges = {(_name(req.name), tuple(sorted(_name(x) for x in req.extras))) for req in active_requirements}
    observed_edges = {(_name(edge.get("name")), tuple(sorted(_name(x) for x in _rows(edge.get("extra", []))))) for edge in active_edges}
    if expected_edges != observed_edges:
        _fail("root locked edges differ from selected authored requirements")
    index: dict[str, list[dict[str, Any]]] = {}
    for row in records:
        index.setdefault(_name(row.get("name")), []).append(row)
    selected: dict[str, dict[str, Any]] = {}
    expanded: dict[str, set[str]] = {}
    queue = [(edge, "") for edge in active_edges]
    iterations = 0
    while queue:
        iterations += 1
        if iterations > 100000:
            _fail("graph traversal exceeds bounded edge count")
        edge, extra_context = queue.pop()
        if set(edge) - {"name", "version", "source", "marker", "extra"}:
            _fail("edge fields are unsupported")
        if not _active(edge.get("marker"), environment, extra_context):
            continue
        name = _name(edge.get("name"))
        candidates = [row for row in index.get(name, [])
                      if ("version" not in edge or row.get("version") == edge["version"])
                      and ("source" not in edge or row.get("source") == edge["source"])
                      and (not row.get("resolution-markers") or any(
                          _active(marker, environment) for marker in _rows(row["resolution-markers"])))]
        if len(candidates) != 1:
            _fail("selected dependency node is missing or ambiguous: " + name)
        row = candidates[0]
        if row.get("source") != {"registry": "https://pypi.org/simple"}:
            _fail("dependency source kind or registry is unsupported")
        try:
            selected_version = Version(str(row.get("version")))
        except InvalidVersion as exc:
            raise InterpreterEnvironmentError("locked project package version is invalid") from exc
        if name in selected and selected[name] != row:
            _fail("selected graph has conflicting versions")
        if name not in selected:
            selected[name] = row
            expanded[name] = set()
            queue.extend((_mapping(dep), "") for dep in _rows(row.get("dependencies", [])))
        extras = {_name(item) for item in _rows(edge.get("extra", []))}
        optional = _named_mapping(row.get("optional-dependencies", {}))
        if extras - optional.keys():
            _fail("requested dependency extra is absent from lock")
        for extra in extras - expanded[name]:
            expanded[name].add(extra)
            queue.extend((_mapping(dep), extra) for dep in _rows(optional[extra]))
        for requirement in active_requirements:
            if _name(requirement.name) == name and not requirement.specifier.contains(selected_version, prereleases=True):
                _fail("selected version violates authored requirement: " + name)
    installer_req = _requirement(installer)
    installer_pins = list(installer_req.specifier)
    if _name(installer_req.name) != "pip" or len(installer_pins) != 1 or installer_pins[0].operator != "==":
        _fail("canonical installer is invalid")
    if "pip" in selected and selected["pip"]["version"] != installer_pins[0].version:
        _fail("locked installer differs from canonical secure installer")
    requirements = {name: name + "==" + str(row["version"]) for name, row in selected.items()}
    requirements["pip"] = installer
    return InterpreterEnvironmentPlan(
        requirements=tuple(requirements[name] for name in sorted(requirements)),
        requires_python="==" + str(version), projection_path=None,
        source_kind="locked_project", source_path=root / "uv.lock", source_sha256=digest,
    )


def verify_locked_source(plan: InterpreterEnvironmentPlan, installer: str) -> dict[str, Any]:
    if plan.source_path is None:
        _fail("source identity is missing")
    root = plan.source_path.parent
    _, _, registry, _ = _read_sources(root)
    contract = _mapping(_mapping(registry.get("interpreter_contract")).get("locked_project"))
    observed = compile_locked_project(root, contract, installer)
    if observed != plan:
        _fail("source changed after derivation")
    return contract


def verify_locked_runtime(plan: InterpreterEnvironmentPlan, python: Path, installer: str) -> None:
    contract = verify_locked_source(plan, installer)
    code = (
        "import json,os,platform,sys,sysconfig;print(json.dumps(dict(markers=dict("
        "implementation_name=sys.implementation.name,implementation_version=platform.python_version(),"
        "os_name=os.name,platform_machine=platform.machine(),platform_release=platform.release(),"
        "platform_system=platform.system(),platform_version=platform.version(),"
        "python_full_version=platform.python_version(),platform_python_implementation=platform.python_implementation(),"
        "python_version='.'.join(platform.python_version_tuple()[:2]),sys_platform=sys.platform),"
        "runtime_platform=dict(sysconfig_platform=sysconfig.get_platform(),"
        "libc_name=platform.libc_ver()[0],libc_version=platform.libc_ver()[1]))))"
    )
    try:
        result = subprocess.run([str(python), "-I", "-c", code], capture_output=True, text=True,
                                timeout=30, check=False, env=interpreter_subprocess_environment(python))
        observed = json.loads(result.stdout) if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        raise InterpreterEnvironmentError("locked project selected runtime probe failed") from exc
    if observed != {"markers": contract["marker_environment"], "runtime_platform": contract["runtime_platform"]}:
        _fail("selected runtime marker environment differs from declared cohort")


def verify_locked_installed_closure(plan: InterpreterEnvironmentPlan, python: Path) -> None:
    """Check installed metadata against the source plan without granting it authority."""
    code = (
        "import importlib.metadata as m,json,re;"
        "rows=[(re.sub(r'[-_.]+','-',d.metadata['Name']).lower(),d.version) for d in m.distributions()];"
        "assert len(rows)==len(dict(rows));print(json.dumps(dict(rows)))"
    )
    try:
        checked = subprocess.run([str(python), "-m", "pip", "check"], capture_output=True,
                                 text=True, timeout=30, check=False,
                                 env=interpreter_subprocess_environment(python))
        if checked.returncode:
            _fail("installed dependency metadata is inconsistent")
        result = subprocess.run([str(python), "-I", "-c", code], capture_output=True,
                                text=True, timeout=30, check=False,
                                env=interpreter_subprocess_environment(python))
        observed = json.loads(result.stdout) if result.returncode == 0 else None
        expected = {_name(req.name): Version(next(iter(req.specifier)).version)
                    for raw in plan.requirements if (req := _requirement(raw))}
        if not isinstance(observed, dict) or set(observed) != set(expected) or any(
            not isinstance(value, str) or Version(value) != expected[name]
            for name, value in observed.items()
        ):
            _fail("installed inventory differs from exact selected lock closure")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, InvalidVersion) as exc:
        raise InterpreterEnvironmentError("locked project installed closure probe failed") from exc

"""Enforce typed governance environment ownership without subtree exemptions."""
from __future__ import annotations

import ast
from pathlib import Path

from ..bootstrap.ownership import CONSUMER_CAPABILITIES, LEGACY_CLI_MODULES, SETTING_READS

_FACTORY_PORTS = {
    "github_provider_settings": "provider", "workflow_settings": "workflow",
    "comparison_settings": "comparison", "evidence_settings": "evidence",
    "runtime_settings": "runtime", "custody_settings": "custody",
    "child_process_environment": "process", "invocation_environment": "invocation",
    "scoped_execution_environment": "scoped", "cli_required_variables": "cli",
}
_PROTOCOL_PORTS = {
    "GitHubProviderSettings": "provider", "WorkflowSettings": "workflow",
    "ComparisonSettings": "comparison", "EvidenceSettings": "evidence",
    "RuntimeSettings": "runtime", "CustodySettings": "custody",
    "ChildProcessEnvironment": "process", "InvocationEnvironment": "invocation",
    "ScopedExecutionEnvironment": "scoped", "CLIRequiredVariables": "cli",
}
_PORT_METHODS = {
    "provider": {"token", "api_url"},
    "workflow": {"actions", "repository", "repository_id", "run_id", "run_attempt", "job", "workflow_ref", "head_sha"},
    "comparison": {"declared_bases", "provider_event", "event_name", "optional_event_name", "invocation_kind", "base_sha", "origin_base_sha", "caller_base_sha", "pr_base_sha", "optional_pr_base_sha", "validation_lane", "enforce_pr_changelog"},
    "evidence": {"actions", "producer_kind", "producer_id", "actor", "user", "durable_input_bindings"},
    "runtime": {"virtual_env", "portable_sdist_test"},
    "custody": {"controller_execution_required", "protection_inspect_required", "controller_custody_path", "execution_inputs"},
    "process": {"snapshot", "live", "required_values"},
    "invocation": {"prior_splinter_root", "evidence_shard"},
    "scoped": {"comparison", "toolchain_path"}, "cli": {"value"},
}
_RAW_OWNERS = {"_ReadEnvironment._source", "_WriteEnvironment._target"}
_LEGACY_NAMES = {"ci_github_cli_io.required_environment", "break_glass_recovery._required", "evidence_storage_commands._required_tokens"}


class EnvironmentBoundaryError(ValueError):
    """A raw read, capability or compatibility route has no declared owner."""


def _canonical(name: str) -> str:
    for prefix in ("bcf_governance.tooling.", "scripts._bcf_runtime.", "_bcf_runtime."):
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def _module_for_import(module: str, node: ast.ImportFrom) -> str:
    if not node.level:
        return _canonical(node.module or "")
    parent = module.split(".")[:-1]
    keep = max(0, len(parent) - node.level + 1)
    return ".".join([*parent[:keep], *(node.module or "").split(".")]).strip(".")


def _resolve(node: ast.AST, bindings: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return bindings.get(node.id, node.id if node.id in {"getattr", "vars", "__import__"} else "")
    if isinstance(node, ast.Attribute):
        base = _resolve(node.value, bindings)
        return f"{base}.{node.attr}" if base else ""
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
        base = _resolve(node.value, bindings)
        if base == "os.__dict__" and isinstance(node.slice.value, str):
            return f"os.{node.slice.value}"
    if isinstance(node, ast.Call):
        function = _resolve(node.func, bindings)
        if function in {"__import__", "importlib.import_module"}:
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                return node.args[0].value
            return "<dynamic-module>"
        if function in {"getattr", "builtins.getattr"} and len(node.args) >= 2:
            base = _resolve(node.args[0], bindings)
            key = node.args[1]
            if base and isinstance(key, ast.Constant) and isinstance(key.value, str):
                return f"{base}.{key.value}"
            return f"{base}.<dynamic>" if base else ""
        if function in {"vars", "builtins.vars"} and len(node.args) == 1:
            base = _resolve(node.args[0], bindings)
            return f"{base}.__dict__" if base else ""
    return ""


def _bindings(tree: ast.Module, module: str) -> dict[str, str]:
    bindings = {node.name: f"{module}.{node.name}" for node in tree.body if isinstance(node, ast.FunctionDef)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bindings[alias.asname or alias.name.split(".")[0]] = _canonical(alias.name if alias.asname else alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            base = _module_for_import(module, node)
            for alias in node.names:
                bindings[alias.asname or alias.name] = f"{base}.{alias.name}"
    for _ in range(len(list(ast.walk(tree)))):
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = _canonical(_resolve(node.value, bindings)) if node.value is not None else ""
                if not value.startswith(("os", "bootstrap", "importlib")) and value not in _LEGACY_NAMES:
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and bindings.get(target.id) != value:
                        bindings[target.id] = value
                        changed = True
        if not changed:
            break
    return bindings


def _owners(tree: ast.Module) -> dict[ast.AST, str]:
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    result = {}
    for node in ast.walk(tree):
        current = node
        names = []
        while current in parents:
            current = parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.append(current.name)
        result[node] = ".".join(reversed(names))
    return result


def _capability(node: ast.AST, origins: dict[str, str], bindings: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return origins.get(node.id)
    if isinstance(node, ast.Call):
        resolved = _canonical(_resolve(node.func, bindings))
        if resolved.startswith("bootstrap.environment."):
            return _FACTORY_PORTS.get(resolved.rsplit(".", 1)[-1])
    if isinstance(node, ast.IfExp):
        left = _capability(node.body, origins, bindings)
        right = _capability(node.orelse, origins, bindings)
        return left if left is not None and left == right else None
    return None


def _import_findings(tree: ast.Module, module: str, bindings: dict[str, str], owners: dict[ast.AST, str]) -> list[str]:
    findings: list[str] = []
    known_module = any(owner.startswith(module + ".") for owner in CONSUMER_CAPABILITIES)
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, ast.ImportFrom):
            base = _module_for_import(module, node)
            targets = [(base, alias.name) for alias in node.names]
        elif isinstance(node, ast.Import):
            targets = [(_canonical(alias.name), "") for alias in node.names]
        for base, name in targets:
            if not base.startswith("bootstrap"):
                continue
            if module.startswith("bootstrap.") or (module == "governance_validation.environment_boundaries" and base == "bootstrap.ownership"):
                continue
            allowed_member = (base != "bootstrap.environment" or name in _FACTORY_PORTS or name == "")
            if not known_module or name.startswith("_") or name == "*" or not allowed_member:
                findings.append(f"{getattr(node, 'lineno', 0)}: inward or private bootstrap import has no consumer")
        reference = _canonical(_resolve(node, bindings))
        if reference.startswith("bootstrap.") and not known_module and not module.startswith("bootstrap.") and module != "governance_validation.environment_boundaries":
            findings.append(f"{getattr(node, 'lineno', 0)}: inward bootstrap reference has no consumer")
        if isinstance(node, ast.Call):
            resolved = _canonical(_resolve(node.func, bindings))
            if resolved in _LEGACY_NAMES and module not in LEGACY_CLI_MODULES:
                findings.append(f"{node.lineno}: legacy environment accessor is CLI-root-only")
            if resolved.startswith("bootstrap.environment."):
                member = resolved.rsplit(".", 1)[-1]
                family = _FACTORY_PORTS.get(member)
                owner = f"{module}.{owners[node]}"
                if family is None or family not in CONSUMER_CAPABILITIES.get(owner, ()):
                    findings.append(f"{node.lineno}: bootstrap capability has no declared owner")
        if isinstance(node, ast.Attribute) and _canonical(_resolve(node.value, bindings)) == "bootstrap.environment":
            if node.attr not in _FACTORY_PORTS:
                findings.append(f"{node.lineno}: bootstrap namespace exposes no such capability")
    return findings


def inspect_environment_imports(source: str, module: str) -> list[str]:
    """Reject application imports/callers of governance bootstrap capabilities."""
    tree = ast.parse(source)
    bindings = _bindings(tree, module)
    return sorted(set(_import_findings(tree, module, bindings, _owners(tree))))


def _adapter_findings(tree: ast.Module, owners: dict[ast.AST, str]) -> list[str]:
    findings: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            name = owners[node] + "." + node.name
            if name in _RAW_OWNERS:
                expected = ast.parse("return os.environ if self._provided is None else self._provided").body
                if ast.dump(ast.Module(body=node.body, type_ignores=[]), include_attributes=False) != ast.dump(ast.Module(body=expected, type_ignores=[]), include_attributes=False):
                    findings.append(f"{node.lineno}: OS owner must remain a pure point-of-use binding")
            if name in SETTING_READS:
                key, default = SETTING_READS[name]
                expected = ast.parse(f"return self._source.get({key!r}, {default})").body
                if ast.dump(ast.Module(body=node.body, type_ignores=[]), include_attributes=False) != ast.dump(ast.Module(body=expected, type_ignores=[]), include_attributes=False):
                    findings.append(f"{node.lineno}: typed setting key/default contract changed")
        if isinstance(node, ast.Attribute) and node.attr in {"_source", "_target"}:
            name = owners[node]
            allowed_reads = set(SETTING_READS) | {"_ComparisonSettings.declared_bases", "_CustodySettings.execution_inputs", "_ChildProcessEnvironment.snapshot", "_ChildProcessEnvironment.live", "_ChildProcessEnvironment.required_values", "_CLIRequiredVariables.value"}
            allowed_writes = {"_InvocationEnvironment.prior_splinter_root", "_InvocationEnvironment.evidence_shard", "_ScopedExecutionEnvironment.comparison", "_ScopedExecutionEnvironment.toolchain_path"}
            if name not in (allowed_reads if node.attr == "_source" else allowed_writes):
                findings.append(f"{node.lineno}: unregistered environment view consumer")
    return findings


def inspect_environment_source(source: str, module: str) -> list[str]:
    """Inspect source only; never import a scanned consumer or its configuration."""
    tree = ast.parse(source)
    bindings = _bindings(tree, module)
    owners = _owners(tree)
    findings = _import_findings(tree, module, bindings, owners) if module != "bootstrap.environment" else []
    raw_owners = []
    for node in ast.walk(tree):
        resolved = _resolve(node, bindings)
        if resolved in {"os.environ", "os.getenv", "os.<dynamic>", "<dynamic-module>"}:
            raw_owners.append(owners[node])
            if module != "bootstrap.environment" or owners[node] not in _RAW_OWNERS or resolved != "os.environ":
                findings.append(f"{getattr(node, 'lineno', 0)}: raw or unresolved environment access outside bootstrap owner")
        if isinstance(node, ast.ImportFrom) and node.module == "os" and any(alias.name in {"environ", "getenv", "*"} for alias in node.names):
            findings.append(f"{node.lineno}: raw environment import has no owner")
    if module == "bootstrap.environment":
        if sorted(raw_owners) != sorted(_RAW_OWNERS):
            findings.append("0: exact two OS environment ownership bindings required")
        findings.extend(_adapter_findings(tree, owners))
    if not module.startswith("bootstrap."):
        for function in ast.walk(tree):
            if not isinstance(function, ast.FunctionDef):
                continue
            origins: dict[str, str] = {}
            owner = f"{module}.{owners[function] + '.' if owners[function] else ''}{function.name}"
            for argument in [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]:
                names = [n.id for n in ast.walk(argument.annotation) if isinstance(n, ast.Name)] if argument.annotation else []
                names = [_canonical(bindings.get(name, name)).rsplit(".", 1)[-1] for name in names]
                families = {_PROTOCOL_PORTS[name] for name in names if name in _PROTOCOL_PORTS}
                if len(families) == 1:
                    port_family = next(iter(families))
                    origins[argument.arg] = port_family
                    if port_family not in CONSUMER_CAPABILITIES.get(owner, ()):
                        findings.append(f"{argument.lineno}: injected environment capability has no declared owner")
            for _ in range(len(list(ast.walk(function)))):
                changed = False
                for node in ast.walk(function):
                    if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                        family = _capability(node.value, origins, bindings)
                        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                        for target in targets:
                            if family and isinstance(target, ast.Name) and origins.get(target.id) != family:
                                origins[target.id] = family
                                changed = True
                if not changed:
                    break
            for node in ast.walk(function):
                if isinstance(node, ast.Attribute):
                    family = _capability(node.value, origins, bindings)
                    if family and node.attr not in _PORT_METHODS[family]:
                        findings.append(f"{node.lineno}: unknown or private setting capability")
                if isinstance(node, ast.Call) and _resolve(node.func, bindings) in {"getattr", "builtins.getattr"} and len(node.args) >= 2:
                    family = _capability(node.args[0], origins, bindings)
                    key = node.args[1]
                    if family and (not isinstance(key, ast.Constant) or key.value not in _PORT_METHODS[family]):
                        findings.append(f"{node.lineno}: dynamic or unknown setting alias")
    return sorted(set(findings))


def validate_environment_boundaries(tooling_root: Path) -> None:
    """Validate the entire managed tooling population against narrow ownership."""
    findings: list[str] = []
    for path in sorted(tooling_root.rglob("*.py")):
        module = ".".join(path.relative_to(tooling_root).with_suffix("").parts)
        findings.extend(f"{path.relative_to(tooling_root)}:{issue}" for issue in inspect_environment_source(path.read_text(encoding="utf-8"), module))
    if findings:
        raise EnvironmentBoundaryError("governance environment ownership failed: " + "; ".join(findings))

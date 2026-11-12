"""Call-graph enforcement for declared application-operation effect ports.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

import json

from jsonschema import Draft202012Validator
from typing import Any

from .semantic_python_method_identity import SOURCE_CONSTRUCTION_BODY_HOOKS
from .semantic_ownership_protocols import IMPLICIT_PROTOCOL_KIND_VERSIONS
from .ci_github_authority import packaged_repo_root


WRITE_CALLS = {
    "chmod", "mkdir", "rename", "rmdir", "symlink_to", "touch", "unlink",
    "write_bytes", "write_text",
}
SHUTIL_WRITE_CALLS = {"copy", "copy2", "move", "rmtree"}
AUTHORITY_CALL_PREFIXES = (
    "approve", "authorize", "build_release_receipt", "certify", "emit_release_receipt",
    "merge", "publish", "set_status",
)
MUTATION_CALL_PREFIXES = (
    "adopt_", "allocate_", "apply_", "attest_", "capture_", "install_",
    "migrate_", "pin_", "project_", "remove_", "scaffold_", "update_",
)


class SemanticOperationEffectError(ValueError):
    """Raised when an operation bypasses its declared effect boundary."""




def _implicit_protocol(call: dict[str, Any], caller: str) -> bool:
    """Validate versioned neutral observations before any port can be credited."""
    marker = call.get("implicit_protocol")
    implicit = str(call.get("called_symbol", "")).startswith("python-implicit::")
    if marker is None and not implicit:
        return False
    def reject() -> None:
        raise SemanticOperationEffectError("operation implicit protocol population is incompatible or ambiguous")
    if not isinstance(marker, dict) or set(marker) != {
        "version", "authority", "execution_qualified", "kind", "expression_sha256", "occurrence"
    }:
        reject()
    kinds = {"attribute_read", "subscript_read", "collection", "iteration", "operator", "truth", "context_manager", "format", *IMPLICIT_PROTOCOL_KIND_VERSIONS}
    digest = marker["expression_sha256"]
    occurrence = marker["occurrence"]
    if (not isinstance(marker["kind"], str) or marker["version"] != IMPLICIT_PROTOCOL_KIND_VERSIONS.get(marker["kind"], "1.0") or marker["authority"] is not False
            or marker["execution_qualified"] is not False or not isinstance(marker["kind"], str) or marker["kind"] not in kinds
            or not isinstance(digest, str) or len(digest) != 64
            or any(value not in "0123456789abcdef" for value in digest)
            or isinstance(occurrence, bool) or not isinstance(occurrence, int) or occurrence < 0
            or call.get("caller") != caller or call.get("call_name") != "<implicit>"
            or call.get("called_symbol") != "python-implicit::" + marker["kind"]
            or call.get("dispatch_resolution") != "unresolved"
            or call.get("dispatch_port_eligible") is not False):
        reject()
    contract = call.get("call_contract")
    if contract is not None and (not isinstance(contract, dict)
            or contract.get("expression_sha256") != digest
            or contract.get("occurrence") != occurrence or contract.get("authority") is not False
            or contract.get("arguments") != []):
        reject()
    return True


def _runtime_target_origins(call: dict[str, Any], function: dict[str, Any]) -> tuple[str, ...]:
    """Parameter-derived runtime targets cannot supply source authority."""
    if "runtime_target_origins" not in call:
        return ()
    origins = call["runtime_target_origins"]
    parameters = function.get("parameters", {})
    closures = function.get("closure_parameters", {})
    if not isinstance(closures, dict):
        raise SemanticOperationEffectError("operation runtime target population is incompatible or ambiguous")
    if isinstance(parameters, dict):
        parameters = {**closures, **parameters}
    if (not isinstance(origins, list) or not origins or not isinstance(parameters, dict)
            or any(not isinstance(value, str) or not value.startswith("parameter:")
                   or value[len("parameter:"):] not in parameters for value in origins)
            or len(set(origins)) != len(origins) or sorted(origins) != origins):
        raise SemanticOperationEffectError("operation runtime target population is incompatible or ambiguous")
    return tuple(origins)

def _lexical_scalar_cells(function: dict[str, Any]) -> tuple[str, ...]:
    """Validate neutral eligibility for one closed literal-int parent frame."""
    if "lexical_scalar_region" not in function:
        return ()
    row = function["lexical_scalar_region"]
    if not isinstance(row, dict):
        raise SemanticOperationEffectError("operation lexical scalar region is incompatible or ambiguous")
    cells = row.get("cells")
    digest = row.get("expression_sha256")
    if (set(row) != {"authority", "execution_qualified", "owner", "expression_sha256", "cells"}
            or row.get("authority") is not False or row.get("execution_qualified") is not False
            or row.get("owner") != function.get("symbol") or function.get("lexical_parent") is not None
            or function.get("parameters") or not isinstance(digest, str) or len(digest) != 64
            or any(value not in "0123456789abcdef" for value in digest)
            or not isinstance(cells, list) or not cells
            or any(not isinstance(value, str) or not value.isidentifier() for value in cells)
            or cells != sorted(set(cells))):
        raise SemanticOperationEffectError("operation lexical scalar region is incompatible or ambiguous")
    return tuple(cells)


def _source_store_rows(function: dict[str, Any]) -> tuple[tuple[str, int, str], ...]:
    """Validate neutral store observations and their unresolved effect pairing."""
    def reject() -> None:
        raise SemanticOperationEffectError("operation source store population is incompatible or ambiguous")

    observations = function.get("source_store_observations", [])
    effects = function.get("effects", [])
    if not isinstance(observations, list) or not isinstance(effects, list):
        reject()
    marked = [effect for effect in effects if isinstance(effect, dict) and "source_store_key" in effect]
    pairs: dict[str, dict[str, Any]] = {}
    for effect in marked:
        key = effect.get("source_store_key")
        if not isinstance(key, str) or key in pairs or effect.get("kind") != "unresolved":
            reject()
        pairs[key] = effect
    rows: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int]] = set()
    unresolved: set[str] = set()
    for row in observations:
        if not isinstance(row, dict):
            reject()
        digest, occurrence = row.get("expression_sha256"), row.get("occurrence")
        disposition = row.get("disposition")
        if (row.get("authority") is not False or row.get("execution_qualified") is not False
                or row.get("caller") != function.get("symbol")
                or row.get("phase") != "operation_eager"
                or row.get("kind") not in {"subscript_store", "subscript_delete", "attribute_store", "attribute_delete"}
                or not isinstance(digest, str) or len(digest) != 64
                or any(value not in "0123456789abcdef" for value in digest)
                or isinstance(occurrence, bool) or not isinstance(occurrence, int) or occurrence < 0
                or disposition not in {"closed_native_literal_region", "unresolved_object_binding"}
                or (row.get("kind", "").startswith("attribute_") and disposition != "unresolved_object_binding")):
            reject()
        for field in ("line", "column", "end_line", "end_column"):
            value = row.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < (0 if "column" in field else 1):
                reject()
        if (row["end_line"], row["end_column"]) <= (row["line"], row["column"]):
            reject()
        identity = (digest, occurrence)
        if identity in seen:
            reject()
        seen.add(identity)
        key = digest + ":" + str(occurrence)
        if disposition == "unresolved_object_binding":
            effect = pairs.get(key)
            if effect is None or effect.get("scope") != "object_binding" or effect.get("line") != row["line"] or effect.get("column") != row["column"]:
                reject()
            unresolved.add(key)
        elif key in pairs:
            reject()
        rows.append((digest, occurrence, disposition))
    if set(pairs) != unresolved:
        reject()
    return tuple(rows)


def _source_function_population(inventory: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Reject ambiguous function identities before any consumer resolves a root."""
    functions: dict[str, dict[str, Any]] = {}
    rows = inventory.get("functions")
    if not isinstance(rows, list):
        raise SemanticOperationEffectError("operation source function population is incompatible or ambiguous")
    for row in rows:
        symbol = row.get("symbol") if isinstance(row, dict) else None
        if not isinstance(symbol, str) or not symbol or symbol in functions:
            raise SemanticOperationEffectError("operation source function population is incompatible or ambiguous")
        functions[symbol] = row
    return functions


def source_operation_call_population(
    entrypoint: str, inventory: dict[str, Any], *, include_initialization: bool = False,
) -> dict[str, Any]:
    """Observe discovered Python calls through ports without interpreting effects.

    The protected caller must authenticate parser inputs and their complete scope.
    Optional initialization facts conservatively retain every discovered module.
    Initialization execution, external/native behavior and dynamic dispatch remain
    unqualified. Unknown calls cannot justify suppression.
    """
    def reject() -> None:
        raise SemanticOperationEffectError("operation source call population is incompatible or ambiguous")

    def digest(value: Any) -> bool:
        return isinstance(value, str) and len(value) == 64 and all(
            character in "0123456789abcdef" for character in value
        )

    if not isinstance(include_initialization, bool):
        raise SemanticOperationEffectError("initialization population option must be boolean")
    if inventory.get("call_contracts_version") != "1.0" or inventory.get("authority") is not False:
        reject()
    functions = _source_function_population(inventory)
    if not isinstance(inventory.get("files"), list):
        reject()
    if not isinstance(entrypoint, str) or entrypoint not in functions:
        reject()
    files: dict[str, str] = {}
    for row in inventory.get("files", []):
        path = row.get("path") if isinstance(row, dict) else None
        sha = row.get("sha256") if isinstance(row, dict) else None
        if not isinstance(path, str) or not path or path in files or not digest(sha):
            reject()
        files[path] = sha
    if not files:
        reject()
    classes = _construction_source_classes(inventory)
    initialization = _initialization_population(inventory, files) if include_initialization else {}
    calls: list[tuple[str, str, str, int, str]] = []
    stores: list[tuple[str, str, int, str]] = []
    identities: set[tuple[str, str, int]] = set()
    visited: set[str] = set()
    pending = [entrypoint]
    while pending:
        caller = pending.pop()
        if caller in visited:
            continue
        visited.add(caller)
        function = functions[caller]
        if caller.partition("::")[0] not in files:
            reject()
        if function.get("language", "python") != "python" or not isinstance(function.get("calls"), list):
            reject()
        _lexical_scalar_cells(function)
        stores.extend((caller, *row) for row in _source_store_rows(function))
        for call in function["calls"]:
            if not isinstance(call, dict):
                reject()
            implicit = _implicit_protocol(call, caller)
            callee = call.get("called_symbol")
            fact = call.get("call_contract")
            if not isinstance(fact, dict):
                reject()
            expression = fact.get("expression_sha256")
            occurrence = fact.get("occurrence")
            if (
                not isinstance(callee, str) or not callee
                or call.get("caller") != caller or fact.get("authority") is not False
                or not digest(expression) or isinstance(occurrence, bool)
                or not isinstance(occurrence, int) or occurrence < 0
            ):
                reject()
            identity = (caller, expression, occurrence)
            if identity in identities:
                reject()
            identities.add(identity)
            runtime_origins = _runtime_target_origins(call, function)
            resolved = (
                callee in functions and not implicit and call.get("dispatch_resolution") != "unresolved"
                and not runtime_origins
                and call.get("call_name") not in {"__import__", "eval", "exec", "<dynamic>"}
            )
            calls.append((caller, callee, expression, occurrence, "source" if resolved else "unresolved"))
            construction_targets, _ = _construction_source_targets(call, functions, classes, function)
            pending.extend(sorted(construction_targets))
            if resolved:
                pending.append(callee)
    result = {
        "authority": False,
        "execution_qualified": False,
        "scope": "discovered_python_functions_only",
        "source_files": tuple(sorted(files.items())),
        "functions": tuple(sorted(visited)),
        "calls": tuple(sorted(calls)),
        "unresolved_calls": sum(row[4] == "unresolved" for row in calls),
    }
    if stores:
        result["source_stores"] = tuple(sorted(stores))
        result["unresolved_source_stores"] = sum(row[3] == "unresolved_object_binding" for row in stores)
    result.update(initialization)
    return result


def _initialization_population(inventory: dict[str, Any], files: dict[str, str]) -> dict[str, Any]:
    """Validate only with the executing distribution's schema, never candidate policy."""
    try:
        schema = json.loads((packaged_repo_root() / "schemas/semantic-initialization-contracts.schema.json").read_text())
        errors = list(Draft202012Validator(schema).iter_errors(inventory))
    except (OSError, UnicodeError, ValueError) as exc:
        raise SemanticOperationEffectError("initialization schema is unavailable or invalid") from exc
    if errors:
        raise SemanticOperationEffectError("initialization population facts are incompatible")
    modules: dict[str, tuple[Any, ...]] = {}
    for row in inventory["module_initializers"]:
        path = row["path"]
        if path not in files or path in modules:
            raise SemanticOperationEffectError("initialization module population is duplicated or unbound")
        identities: set[tuple[str, str, int]] = set()
        sites = []
        for site in row["sites"]:
            identity = (site["kind"], site["expression_sha256"], site["occurrence"])
            if identity in identities:
                raise SemanticOperationEffectError("initialization site population is duplicated")
            identities.add(identity)
            sites.append((*identity, site["line"], site.get("call_name", "")))
        modules[path] = (tuple(sorted(sites)), tuple(sorted(
            (unknown["reason"], unknown["line"]) for unknown in row["unresolved"]
        )), tuple(row["limitations"]))
    if modules.keys() != files.keys():
        raise SemanticOperationEffectError("initialization module population is incomplete")
    return {
        "scope": "discovered_python_functions_and_possible_initialization",
        "completeness_qualified": False,
        "module_initializers": tuple((path, *modules[path]) for path in sorted(modules)),
    }


def _resolve_function(
    symbol: str, functions: dict[str, dict[str, Any]]
) -> str | None:
    if symbol in functions:
        return symbol
    module, separator, function = symbol.partition("::")
    if not separator:
        return None
    if not module.endswith(".py"):
        return None
    module_name = module.removesuffix(".py").rsplit("/", 1)[-1]
    candidates = [
        candidate
        for candidate in functions
        if candidate.endswith(f"/{module_name}.py::{function}")
        or candidate == f"{module_name}.py::{function}"
    ]
    return candidates[0] if len(candidates) == 1 else None


def _port_identity(
    value: str, functions: dict[str, dict[str, Any]]
) -> tuple[str, str]:
    resolved = _resolve_function(value, functions)
    return ("function", resolved) if resolved is not None else ("call", value)



def _construction_source_classes(inventory: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Derive expected constructor identities from the actual class population."""
    rows = inventory.get("classes", [])
    if not isinstance(rows, (list, tuple)):
        raise SemanticOperationEffectError("construction source class population is invalid")
    symbols = [row.get("symbol") if isinstance(row, dict) else None for row in rows]
    if any(not isinstance(value, str) or not value for value in symbols) or len(set(symbols)) != len(symbols):
        raise SemanticOperationEffectError("construction source class population is ambiguous")
    if inventory.get("language") == "python" and "types" in inventory:
        types = inventory["types"]
        if not isinstance(types, list) or any(not isinstance(value, str) for value in types):
            raise SemanticOperationEffectError("construction source type population is invalid")
        if len(types) != len(set(types)) or set(types) != set(symbols):
            raise SemanticOperationEffectError("construction source class/type population is incomplete")
    for function in inventory.get("functions", []):
        if not isinstance(function, dict) or function.get("language", "python") != "python":
            continue
        owner = function.get("class_symbol")
        if owner is not None and (not isinstance(owner, str) or owner not in symbols):
            raise SemanticOperationEffectError("construction source method class population is incomplete")
    return {row["symbol"]: row for row in rows}


def _construction_source_targets(
    call: dict[str, Any], functions: dict[str, dict[str, Any]],
    classes: dict[str, dict[str, Any]], function: dict[str, Any],
) -> tuple[set[str], tuple[str, ...]]:
    """Verify neutral facts against independently derived class/call membership."""
    target = call.get("called_symbol")
    known_class = target in classes
    observation = call.get("construction_effect_observation")
    if observation is None:
        if known_class:
            raise SemanticOperationEffectError("construction source observation is missing")
        return set(), ()
    if (
        not isinstance(observation, dict)
        or observation.get("authority") is not False
        or not isinstance(observation.get("source_class_resolved"), bool)
        or observation["source_class_resolved"] != known_class
        or any(
            not isinstance(observation.get(key), list)
            or any(not isinstance(value, str) or not value for value in observation[key])
            or len(observation[key]) != len(set(observation[key]))
            for key in ("class_candidates", "function_candidates", "unresolved")
        )
        or target not in observation.get("class_candidates", [])
    ):
        raise SemanticOperationEffectError("construction source identity or observations are incompatible")
    if not known_class:
        return set(), ()
    constructors = function.get("constructors", [])
    keys = ("line", "column", "end_line", "end_column")
    position = tuple(call.get(key) for key in keys)
    if (
        not isinstance(constructors, list)
        or any(isinstance(value, bool) or not isinstance(value, int) for value in position)
        or call.get("caller") != function.get("symbol")
    ):
        raise SemanticOperationEffectError("construction source call association is invalid")
    matches = [
        fact for fact in constructors if isinstance(fact, dict)
        and tuple(fact.get(key) for key in keys) == position
    ]
    if (
        len(matches) != 1 or matches[0].get("caller") != call["caller"]
        or matches[0].get("called_symbol") != target
        or matches[0].get("constructed_symbol") != target
        or matches[0].get("construction_effect_observation") != observation
    ):
        raise SemanticOperationEffectError("construction source fact association is missing or ambiguous")
    # Class-method rows and constructor observations cannot jointly hide a body
    # independently retained in the function population.
    ancestry: set[str] = set()
    pending = [(target, frozenset())]
    runtime_unknown = False
    declared_methods: set[str] = set()
    while pending:
        identity, lineage = pending.pop()
        if identity in lineage:
            raise SemanticOperationEffectError("construction source ancestry is cyclic")
        if identity in ancestry:
            continue
        ancestry.add(identity)
        row = classes.get(identity)
        if row is None:
            runtime_unknown = True
            continue
        runtime_unknown = runtime_unknown or any(row.get(key) for key in (
            "class_decorators", "metaclass_keywords", "descriptor_bindings",
        ))
        methods = row.get("methods", [])
        if not isinstance(methods, list):
            raise SemanticOperationEffectError("construction source method population is invalid")
        for method in methods:
            name = method.get("name") if isinstance(method, dict) else None
            body = method.get("symbol") if isinstance(method, dict) else None
            if not isinstance(name, str) or not name or body != identity + "." + name:
                raise SemanticOperationEffectError("construction source method identity is incompatible")
            special = name.startswith("__") and name.endswith("__")
            if special or method.get("decorators"):
                declared_methods.add(body)
                runtime_unknown = runtime_unknown or bool(method.get("decorators")) or (
                    special and name not in SOURCE_CONSTRUCTION_BODY_HOOKS
                )
        bases = row.get("bases", [])
        if not isinstance(bases, list):
            raise SemanticOperationEffectError("construction source bases are invalid")
        for base in bases:
            parent = base.get("called_symbol") if isinstance(base, dict) else None
            if not isinstance(parent, str) or not parent:
                raise SemanticOperationEffectError("construction source base identity is missing")
            pending.append((parent, lineage | {identity}))
    expected: set[str] = set(declared_methods)
    for symbol, body in functions.items():
        owner, _, name = symbol.rpartition(".")
        special = name.startswith("__") and name.endswith("__")
        if owner in ancestry and (special or body.get("decorators")):
            expected.add(symbol)
            runtime_unknown = runtime_unknown or bool(body.get("decorators")) or (
                special and name not in SOURCE_CONSTRUCTION_BODY_HOOKS
            )
    if not expected <= functions.keys():
        raise SemanticOperationEffectError("construction source declared method body is absent")
    if not ancestry <= set(observation["class_candidates"]):
        raise SemanticOperationEffectError("construction source ancestry population is incomplete")
    if not expected <= set(observation["function_candidates"]):
        raise SemanticOperationEffectError("construction source hook body population is incomplete")
    if runtime_unknown and not observation["unresolved"]:
        raise SemanticOperationEffectError("construction source runtime provenance is missing")
    targets = set(observation["function_candidates"])
    if not targets <= functions.keys():
        raise SemanticOperationEffectError("construction source body is absent or ambiguous")
    return targets, tuple(observation["unresolved"])


def validated_operation_effect_inventory(
    operation: dict[str, Any],
    entrypoint_symbol: str,
    inventory: dict[str, Any],
    *, source_modules: tuple[str, ...] = (), require_runtime_context: bool = True,
) -> tuple[tuple[str, str, str], ...]:
    """Trace effects; explicit source-only views retain unknown context as data."""
    if not isinstance(require_runtime_context, bool):
        raise SemanticOperationEffectError("runtime effect context requirement must be boolean")
    functions = _source_function_population(inventory)
    classes = _construction_source_classes(inventory)
    entrypoint = _resolve_function(entrypoint_symbol, functions)
    if entrypoint is None:
        raise SemanticOperationEffectError(
            f"operation {operation['id']} entrypoint is absent from the shared source inventory"
        )
    if functions[entrypoint].get("lexical_parent") is not None:
        raise SemanticOperationEffectError("operation contains an unresolved effect lexical invocation context")
    mutation_ports = {
        _port_identity(str(value), functions)
        for value in operation["allowed_mutation_ports"]
    }
    authority_ports = {
        _port_identity(str(value), functions)
        for value in operation["allowed_authority_ports"]
    }
    non_authoritative_ports = {
        _port_identity(str(value), functions)
        for value in operation["non_authoritative_output_effects"]
    }
    declared_ports = mutation_ports | authority_ports | non_authoritative_ports
    reached: set[tuple[str, str]] = set()
    unresolved: set[tuple[str, str, str]] = set()
    writes: set[str] = set()
    authority: set[str] = set()
    pending = [(entrypoint, True), *((path + "::<module>", True) for path in source_modules if path + "::<module>" in functions)]
    visited: set[tuple[str, bool]] = set()
    while pending:
        symbol, credit = pending.pop()
        if (symbol, credit) in visited:
            continue
        visited.add((symbol, credit))
        function = functions[symbol]
        _source_store_rows(function)
        _lexical_scalar_cells(function)
        if function.get("language") == "typescript":
            module = symbol.split("::", 1)[0] + "::<module>"
            if module in functions and module != symbol:
                pending.append((module, credit))
        for effect in function.get("effects", []):
            target = f"{symbol}:{effect.get('line')}:{effect.get('target')}"
            if (effect.get("kind") == "write" and effect.get("scope") == "nonlocal"
                    and function.get("lexical_parent") == entrypoint
                    and effect.get("target") in _lexical_scalar_cells(functions[entrypoint])):
                continue
            if effect.get("kind") == "write":
                writes.add(target)
            elif effect.get("kind") == "authority":
                authority.add(target)
            else:
                raise SemanticOperationEffectError(f"operation {operation['id']} contains an unresolved effect at {symbol}")
        if function.get("unresolved"):
            raise SemanticOperationEffectError(
                f"operation {operation['id']} contains an unresolved dynamic call path at {symbol}"
            )
        if any(
            failure.get("port_eligible") is not True
            for failure in function.get("effect_unresolved", [])
        ):
            raise SemanticOperationEffectError(
                f"operation {operation['id']} contains an unresolved effect call path at {symbol}"
            )
        for call in function.get("calls", []):
            if _implicit_protocol(call, symbol):
                if require_runtime_context:
                    raise SemanticOperationEffectError(f"operation {operation['id']} contains an unresolved effect runtime protocol at {symbol}")
                marker = call["implicit_protocol"]
                identity = f"{symbol}:{marker['kind']}:{marker['expression_sha256']}:{marker['occurrence']}"
                unresolved.add(("unresolved", "implicit_protocol", identity))
                continue
            if _runtime_target_origins(call, function):
                raise SemanticOperationEffectError(f"operation {operation['id']} contains an unresolved effect runtime target at {symbol}")
            raw = str(call.get("called_symbol", ""))
            callee = _resolve_function(raw, functions)
            identity = ("function", callee) if callee is not None else ("call", raw)
            hard_dispatch_failure = (
                call.get("dispatch_resolution") == "unresolved"
                and call.get("dispatch_port_eligible") is not True
            )
            if hard_dispatch_failure:
                raise SemanticOperationEffectError(
                    f"operation {operation['id']} contains an unresolved effect call path at {symbol}"
                )
            construction_targets, construction_missing = _construction_source_targets(call, functions, classes, function)
            if construction_missing:
                raise SemanticOperationEffectError(
                    "source construction requires unresolved runtime provenance: "
                    + ", ".join(construction_missing)
                )
            pending.extend((target, False) for target in sorted(construction_targets))
            if identity in declared_ports:
                if credit:
                    reached.add(identity)
                continue
            if call.get("dispatch_resolution") == "unresolved":
                raise SemanticOperationEffectError(
                    f"operation {operation['id']} contains an unresolved effect call path at {symbol}"
                )
            if call.get("language") == "typescript":
                if call.get("effect") == "write":
                    writes.add(raw)
                if call.get("authority_effect") is True:
                    authority.add(raw)
                if callee is not None:
                    pending.append((callee, credit))
                continue
            name = str(call.get("call_name", ""))
            receiver = raw.rsplit("::", 1)[-1].rsplit(".replace", 1)[0]
            file_replace = name == "replace" and (
                raw.startswith("os::")
                or receiver in {"destination", "path", "staged", "target"}
            )
            shutil_write = name in SHUTIL_WRITE_CALLS and raw.startswith("shutil::")
            unresolved_mutation = callee is None and name.startswith(
                MUTATION_CALL_PREFIXES
            )
            if name in WRITE_CALLS or file_replace or shutil_write or unresolved_mutation:
                writes.add(raw)
            if name.lower().startswith(AUTHORITY_CALL_PREFIXES):
                authority.add(raw)
            # Follow every source-resolved call until a declared effect port.
            # Module boundaries are organizational, not effect boundaries; a
            # query cannot conceal a write in an imported helper.
            if callee is not None:
                pending.append((callee, credit))
    missing = declared_ports - reached
    if missing:
        rendered = ", ".join(sorted(value for _, value in missing))
        raise SemanticOperationEffectError(
            f"operation {operation['id']} declares unreachable effect ports: {rendered}"
        )
    if writes:
        raise SemanticOperationEffectError(
            f"operation {operation['id']} has undeclared write effects: "
            + ", ".join(sorted(writes))
        )
    if authority:
        raise SemanticOperationEffectError(
            f"operation {operation['id']} has undeclared authority effects: "
            + ", ".join(sorted(authority))
        )
    ports = {
        (classification, target_kind, symbol)
        for classification, ports in (
            ("mutation", mutation_ports), ("authority", authority_ports),
            ("observation", non_authoritative_ports),
        )
        for target_kind, symbol in ports & reached
    }
    return tuple(sorted(ports | unresolved))


def validate_operation_effects(
    operation: dict[str, Any],
    entrypoint_symbol: str,
    inventory: dict[str, Any],
    *, source_modules: tuple[str, ...] = (), require_runtime_context: bool = True,
) -> tuple[int, int]:
    """Count declared ports; opt-in source-only counts never certify runtime closure."""

    ports = validated_operation_effect_inventory(
        operation, entrypoint_symbol, inventory, source_modules=source_modules,
        require_runtime_context=require_runtime_context,
    )
    return (
        sum(classification == "mutation" for classification, _, _ in ports),
        sum(classification == "authority" for classification, _, _ in ports),
    )

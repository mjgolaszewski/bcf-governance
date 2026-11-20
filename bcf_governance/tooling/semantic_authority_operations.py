"""Closed operation validation delegated by the semantic authority owner.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any


def _validate_operation_semantics(operation: dict[str, Any]) -> str:
    from .semantic_authority_contracts import SemanticAuthorityError, READ_ONLY_KINDS, MUTATING_KINDS

    kind = str(operation["semantic_kind"])
    if operation.get("allowed_read_ports") and not operation["authoritative_read"]:
        raise SemanticAuthorityError("operation read ports require authoritative_read")
    mutates = bool(operation["authoritative_mutation"])
    confers = bool(operation["authority_conferral"])
    if kind in READ_ONLY_KINDS and (mutates or confers):
        raise SemanticAuthorityError(f"{kind} operation {operation['id']} cannot mutate or confer authority")
    if kind == "projection" and not operation["produces_projection"]:
        raise SemanticAuthorityError(f"projection operation {operation['id']} must construct a read model")
    if kind not in MUTATING_KINDS and (operation["allowed_mutation_ports"] or operation["allowed_authority_ports"]):
        raise SemanticAuthorityError(f"non-mutating operation {operation['id']} cannot declare mutation or authority ports")
    if mutates and not operation["allowed_mutation_ports"]:
        raise SemanticAuthorityError(f"mutating operation {operation['id']} requires a declared mutation port")
    if confers and not operation["allowed_authority_ports"]:
        raise SemanticAuthorityError(f"authority operation {operation['id']} requires a declared authority port")
    if operation["model_callable"] and confers:
        raise SemanticAuthorityError(f"model-callable operation {operation['id']} cannot confer authority")
    return kind


def _validate_python_call_source_coverage(repo_root, inventory, functions, source_subject):
    """Reconcile explicit call syntax independently of FunctionVisitor extraction.

    The caller authenticates scope and policy. This checks source coverage, not
    runtime dispatch or the semantics of deferred lambda/initialization bodies.
    """
    import ast
    from collections import Counter
    import hashlib
    from pathlib import PurePosixPath

    from .semantic_operation_python import _operation_source_text
    from .semantic_python_method_identity import runtime_function_contexts
    from .semantic_ownership_inventory import _imports, _module_name
    from .semantic_source_paths import committed_python_source_population
    from .semantic_authority_contracts import SemanticAuthorityError

    def reject():
        raise SemanticAuthorityError("Python source call coverage contradicts exact source")

    rows = inventory.get("files")
    if not isinstance(rows, list):
        reject()
    files = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            reject()
        relative = row["path"]
        if not relative.endswith(".py"):
            continue
        path = PurePosixPath(relative)
        sha = row.get("sha256")
        if (path.is_absolute() or not path.parts or path.as_posix() != relative
                or ".." in path.parts or relative in files
                or not isinstance(sha, str) or len(sha) != 64
                or any(value not in "0123456789abcdef" for value in sha)):
            reject()
        files[relative] = sha
    if source_subject is not None:
        try:
            committed = committed_python_source_population(repo_root, **source_subject)
        except (OSError, TypeError, ValueError):
            reject()
        if committed["unresolved_entries"] or set(files) != {row[0] for row in committed["python_blobs"]}:
            reject()
    module_index = {_module_name(repo_root, repo_root / path): path for path in files}
    expected_functions = set()

    class Calls(ast.NodeVisitor):
        def __init__(self, root, postponed):
            self.root = root
            self.postponed = postponed
            self.nodes = []

        def visit_FunctionDef(self, node):  # noqa: N802
            for field, value in ast.iter_fields(node):
                if field == "body" and node is not self.root:
                    continue
                if field == "returns" and self.postponed:
                    continue
                for child in value if isinstance(value, list) else [value]:
                    if isinstance(child, ast.AST):
                        self.visit(child)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_arg(self, node):
            if node.annotation is not None and not self.postponed:
                self.visit(node.annotation)

        def visit_Lambda(self, node):  # noqa: N802
            self.visit(node.args)

        def visit_Call(self, node):  # noqa: N802
            self.nodes.append(node)
            self.generic_visit(node)

    fields = ("line", "column", "end_line", "end_column")
    for relative, sha in files.items():
        path = repo_root / relative
        try:
            if source_subject is None and any((repo_root.joinpath(*PurePosixPath(relative).parts[:i])).is_symlink()
                                             for i in range(1, len(PurePosixPath(relative).parts) + 1)):
                reject()
            text = _operation_source_text(repo_root, path, source_subject)
            if hashlib.sha256(text.encode("utf-8")).hexdigest() != sha:
                reject()
            tree = ast.parse(text, filename=relative)
            contexts, missing = runtime_function_contexts(tree, path=relative,
                imports=_imports(tree, module_index, _module_name(repo_root, path)))
        except (OSError, UnicodeError, SyntaxError, ValueError):
            reject()
        if missing:
            reject()
        postponed = any(isinstance(node, ast.ImportFrom) and node.module == "__future__"
            and any(alias.name == "annotations" for alias in node.names) for node in tree.body)
        for context in contexts:
            symbol = relative + "::" + context["qualified_name"]
            if symbol in expected_functions or symbol not in functions:
                reject()
            expected_functions.add(symbol)
            visitor = Calls(context["function"], postponed)
            visitor.visit(context["function"])
            expected = {(node.lineno, node.col_offset, node.end_lineno, node.end_col_offset): node
                        for node in visitor.nodes}
            if len(expected) != len(visitor.nodes):
                reject()
            actual = []
            for call in functions[symbol]["calls"]:
                if "implicit_protocol" in call:
                    continue
                if call.get("caller") != symbol:
                    reject()
                site = tuple(call.get(field) for field in fields)
                if any(type(value) is not int for value in site) or site not in expected:
                    reject()
                actual.append(site)
                contract = call.get("call_contract")
                if inventory.get("call_contracts_version") == "1.0" and contract is None:
                    reject()
                if contract is not None:
                    node = expected[site]
                    def digest(value):
                        return hashlib.sha256(ast.dump(value, include_attributes=False).encode()).hexdigest()
                    arguments = [dict(kind="starred" if isinstance(value, ast.Starred) else "positional",
                        slot=slot, expression_sha256=digest(value)) for slot, value in enumerate(node.args)]
                    arguments.extend(dict(kind="keyword" if value.arg is not None else "double_starred",
                        slot=value.arg if value.arg is not None else slot,
                        expression_sha256=digest(value.value)) for slot, value in enumerate(node.keywords))
                    if (not isinstance(contract, dict) or contract.get("authority") is not False
                            or contract.get("expression_sha256") != digest(node)
                            or contract.get("arguments") != arguments):
                        reject()
            if Counter(actual) != Counter(expected.keys()):
                reject()
    actual_functions = {symbol for symbol, row in functions.items()
                        if symbol.partition("::")[0].endswith(".py") and row.get("language", "python") == "python"}
    if actual_functions != expected_functions:
        reject()


def _validate_operations(
    repo_root: Path, payload: dict[str, Any], inventory: dict[str, Any], *,
    consumer_owned_schema: bool = False, source_language: str | None = None,
    require_runtime_context: bool = True, collect_effect_obligations: bool = False,
) -> list[dict[str, Any]]:
    from .semantic_authority_contracts import (
        SemanticAuthorityError,
        _schema, _validate_operation_structure, _discover_population,
        _function_for_entrypoint, validated_operation_effect_inventory,
        SemanticOperationEffectError,
    )
    from .semantic_operation_python import _inventory_source_subject
    from .semantic_operation_effects import _source_function_population

    if not isinstance(collect_effect_obligations, bool):
        raise SemanticAuthorityError("operation effect diagnostic option must be boolean")
    if not isinstance(require_runtime_context, bool) or (consumer_owned_schema and not require_runtime_context):
        raise SemanticAuthorityError("required operations cannot waive runtime effect context")
    _schema(repo_root, "application-operations.schema.json", payload, consumer_owned=consumer_owned_schema)
    _validate_operation_structure(payload)
    try:
        source_subject = _inventory_source_subject(inventory)
        functions = _source_function_population(inventory)
    except ValueError as exc:
        raise SemanticAuthorityError(str(exc)) from exc
    python_sources = {
        str(row["path"]) for row in inventory.get("files", [])
        if str(row["path"]).endswith(".py")
    }
    populations = []
    discovered: dict[str, dict[str, str]] = {}
    for row in payload["populations"]:
        if source_language == "python" and row["adapter"] == "typescript_exports":
            continue
        entries = _discover_population(repo_root, row, inventory, source_subject=source_subject)
        if source_language == "python" and row["adapter"] == "canonical_yaml_catalog":
            targets = [_function_for_entrypoint(repo_root, symbol, functions, source_subject=source_subject) for symbol in entries.values()]
            if any(
                (target is None and symbol.split("::", 1)[0] not in python_sources)
                or (target is not None and target.get("language", "python") != "python")
                for symbol, target in zip(entries.values(), targets)
            ):
                continue
        populations.append(row)
        discovered[str(row["id"])] = entries
    classified: dict[tuple[str, str], str] = {}
    admitted: list[tuple[dict[str, Any], str, str, dict[str, Any]]] = []
    for operation in payload["operations"]:
        population_id = str(operation["population"])
        key = str(operation["population_key"])
        slot = (population_id, key)
        if slot in classified:
            raise SemanticAuthorityError(
                f"public operation {population_id}:{key} is multiply classified by {classified[slot]} and {operation['id']}"
            )
        classified[slot] = str(operation["id"])
        if population_id not in discovered:
            _validate_operation_semantics(operation)
            continue
        actual_symbol = discovered[population_id].get(key)
        if actual_symbol is None:
            raise SemanticAuthorityError(f"operation {operation['id']} is stale; {population_id}:{key} is not discovered")
        if operation["entrypoints"] != [actual_symbol]:
            raise SemanticAuthorityError(
                f"operation {operation['id']} entrypoints must exactly match discovered {actual_symbol}"
            )
        kind = _validate_operation_semantics(operation)
        function = _function_for_entrypoint(repo_root, actual_symbol, functions, source_subject=source_subject)
        if function is None:
            raise SemanticAuthorityError(
                f"operation {operation['id']} entrypoint is absent from the shared source inventory"
            )
        admitted.append((operation, kind, actual_symbol, function))
    missing = sorted(
        f"{population_id}:{key}"
        for population_id, entries in discovered.items()
        for key in entries
        if (population_id, key) not in classified
    )
    if missing:
        raise SemanticAuthorityError("unclassified public application operations: " + ", ".join(missing))

    # Effects can be traversed only after the entire operation population admits.
    _validate_python_call_source_coverage(repo_root, inventory, functions, source_subject)
    observations: list[dict[str, Any]] = []
    first_effect_error: SemanticOperationEffectError | None = None
    effect_blockers: list[tuple[str, str, str, str, str]] = []
    for operation, kind, actual_symbol, function in admitted:
        population_id = str(operation["population"])
        try:
            effect_ports = validated_operation_effect_inventory(
                operation, str(function["symbol"]), inventory,
                source_modules=tuple(str(row["source"]) for row in populations if row["id"] == population_id),
                require_runtime_context=require_runtime_context,
            )
        except SemanticOperationEffectError as exc:
            if not collect_effect_obligations or not exc.effect_obligations:
                raise SemanticAuthorityError(str(exc)) from exc
            if first_effect_error is None:
                first_effect_error = exc
            effect_blockers.extend((str(operation["id"]), *row) for row in exc.effect_obligations)
            continue
        observations.append({
            "operation": operation["id"], "kind": kind, "entrypoint": actual_symbol,
            "write_effect_count": sum(role == "mutation" for role, _, _ in effect_ports),
            "authority_effect_count": sum(role == "authority" for role, _, _ in effect_ports),
            "effect_ports": [
                {"classification": role, "target_kind": kind, "symbol": symbol}
                for role, kind, symbol in effect_ports
            ],
        })
        if not require_runtime_context:
            observations[-1].update(
                effect_context_scope='source_only_runtime_unqualified',
                unresolved_effect_context_count=sum(role == 'unresolved' for role, _, _ in effect_ports),
            )
    if first_effect_error is not None:
        error = SemanticAuthorityError(str(first_effect_error))
        error.operation_effect_population = tuple(sorted(str(row[0]["id"]) for row in admitted))
        error.operation_effect_obligations = tuple(sorted(effect_blockers))
        error.effect_context_scope = "admitted_operations_strict_validator_blockers"
        error.authority = error.execution_qualified = error.completeness_qualified = False
        error.require_runtime_context = require_runtime_context
        raise error from first_effect_error
    return observations

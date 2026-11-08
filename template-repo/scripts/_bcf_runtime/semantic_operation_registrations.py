"""Closed Python frozen-spec registration discovery and executable binding.

This opt-in adapter observes source, never executes it. Each operation binds an
actual lexical handler to one literal frozen instance and its concrete factory.
It does not grant an effect-port exemption or substitute a DTO for a handler.
"""
from __future__ import annotations

import ast
import copy
import hashlib
from pathlib import Path
from typing import Any, Never

from .semantic_operation_python import _expression_symbol, _module_aliases


class TypedRegistrationError(ValueError):
    """Unsupported or ambiguous registration must fail closed."""


def _refuse(detail: str) -> Never:
    raise TypedRegistrationError("typed registration: " + detail)


def _tree(root: Path, relative: str, inventory: dict[str, Any]) -> ast.Module:
    path = root / relative
    if (not relative or Path(relative).is_absolute() or ".." in Path(relative).parts
            or path.resolve(strict=True) != path or not path.is_file()):
        raise TypedRegistrationError("typed registration: canonical source required")
    raw = path.read_bytes()
    rows = [row for row in inventory["files"] if row["path"] == relative]
    if len(rows) != 1 or rows[0]["sha256"] != hashlib.sha256(raw).hexdigest():
        raise TypedRegistrationError("typed registration: source differs from shared inventory")
    return ast.parse(raw, filename=relative)


def _one(values: list[Any], label: str) -> Any:
    if len(values) != 1:
        raise TypedRegistrationError("typed registration: exactly one " + label + " required")
    return values[0]


def _body(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.stmt]:
    return [item for item in node.body if not (
        isinstance(item, ast.Expr) and isinstance(item.value, ast.Constant)
        and isinstance(item.value.value, str))]


def _resolve(root: Path, expression: ast.expr, tree: ast.Module, source: str) -> str:
    aliases = _module_aliases(root, tree, root / source)
    symbol = _expression_symbol(expression, aliases)
    if symbol == "<dynamic>" or "::" not in symbol:
        raise TypedRegistrationError("typed registration: direct source identity required")
    name = expression.id if isinstance(expression, ast.Name) else None
    if name is None:
        raise TypedRegistrationError("typed registration: direct named binding required")
    definitions = sum(
        isinstance(item, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name
        for item in tree.body)
    imports = sum(
        (alias.asname or alias.name) == name
        for item in tree.body if isinstance(item, ast.ImportFrom) for alias in item.names)
    stores = [item for item in ast.walk(tree) if isinstance(item, ast.Name)
              and isinstance(item.ctx, ast.Store) and item.id == name]
    if definitions + imports != 1 or stores:
        raise TypedRegistrationError("typed registration: ambiguous or rebound source alias")
    return symbol


def _forwarding_owner(root: Path, symbol: str, inventory: dict[str, Any]) -> tuple[str, str, frozenset[str], frozenset[str]]:
    source, name = symbol.split("::", 1)
    tree = _tree(root, source, inventory)
    cls = _one([row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == name], "spec class")
    if cls.bases:
        _refuse("inherited specs are unsupported")
    frozen = [row for row in cls.decorator_list if isinstance(row, ast.Call)
              and _resolve(root, row.func, tree, source) == "dataclasses.py::dataclass"]
    # Import identities use the same source-first convention as the operation owner.
    if not frozen:
        frozen = [row for row in cls.decorator_list if isinstance(row, ast.Call)
                  and _resolve(root, row.func, tree, source) == "dataclasses::dataclass"]
    decorator = _one(frozen, "frozen dataclass decorator")
    if not any(row.arg == "frozen" and isinstance(row.value, ast.Constant)
               and row.value.value is True for row in decorator.keywords):
        _refuse("spec must be frozen")
    dispatch = _one([row.value.value for row in cls.body if isinstance(row, ast.AnnAssign)
                     and isinstance(row.target, ast.Name) and row.target.id == "dispatch"
                     and isinstance(row.value, ast.Constant)], "literal dispatch")
    if dispatch not in {"ask", "send"}:
        _refuse("unsupported dispatch direction")
    method = _one([row for row in cls.body if isinstance(row, ast.FunctionDef)
                   and row.name == "register"], "register method")
    if [row.arg for row in method.args.args] != ["self", "server", "context"]:
        _refuse("register signature must forward one current instance")
    statement = _one(_body(method), "register forwarding statement")
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        _refuse("register must directly forward")
    call = statement.value
    if call.keywords or [ast.unparse(row) for row in call.args] != ["server", "context", "self"]:
        _refuse("cross-instance register forwarding")
    fields = {row.target.id: row for row in cls.body if isinstance(row, ast.AnnAssign)
              and isinstance(row.target, ast.Name) and row.target.id != "dispatch"}
    required = frozenset(name for name, row in fields.items() if row.value is None)
    return _resolve(root, call.func, tree, source), dispatch, frozenset(fields), required


def discover_typed_registrations(root: Path, population: dict[str, Any],
                                 inventory: dict[str, Any]) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Derive the complete literal table and specialize actual handler call facts."""
    source, table = str(population["source"]), str(population["symbol"])
    tree = _tree(root, source, inventory)
    assignments = [row for row in tree.body if (
        isinstance(row, ast.Assign) and any(isinstance(t, ast.Name) and t.id == table for t in row.targets)
        or isinstance(row, ast.AnnAssign) and isinstance(row.target, ast.Name) and row.target.id == table)]
    assignment = _one(assignments, "registration table")
    if not isinstance(assignment.value, (ast.Tuple, ast.List)) or not assignment.value.elts:
        _refuse("nonempty literal registration sequence required")
    loops = [row for row in ast.walk(tree) if isinstance(row, ast.For)
             and isinstance(row.iter, ast.Name) and row.iter.id == table]
    loop = _one(loops, "table registration loop")
    if not isinstance(loop.target, ast.Name) or loop.orelse or len(loop.body) != 1:
        _refuse("registration loop must directly register each instance")
    statement = loop.body[0]
    if (not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call)
            or ast.unparse(statement.value.func) != loop.target.id + ".register"
            or [ast.unparse(row) for row in statement.value.args] != ["server", "context"]
            or statement.value.keywords):
        _refuse("registration loop must forward current server and context")
    # Refuse mutations, aliasing and a second use of the table, not just duplicate declarations.
    loads = [row for row in ast.walk(tree) if isinstance(row, ast.Name)
             and row.id == table and isinstance(row.ctx, ast.Load)]
    if len(loads) != 1:
        _refuse("registration table alias or mutation is unsupported")
    discovered: dict[str, str] = {}
    bound: list[dict[str, Any]] = []
    functions = {row["symbol"]: row for row in inventory["functions"]}
    for instance in assignment.value.elts:
        if not isinstance(instance, ast.Call) or instance.args:
            _refuse("literal keyword-only spec instance required")
        keywords = {row.arg: row.value for row in instance.keywords}
        if None in keywords or len(keywords) != len(instance.keywords):
            _refuse("duplicate or expanded instance keyword")
        name_node = keywords.get("name")
        if not isinstance(name_node, ast.Constant) or not isinstance(name_node.value, str) or not name_node.value:
            _refuse("literal operation name required")
        key = name_node.value
        if key in discovered:
            _refuse("duplicate operation name: " + key)
        spec = _resolve(root, instance.func, tree, source)
        owner, direction, fields, required = _forwarding_owner(root, spec, inventory)
        if not set(keywords) <= fields or not required <= set(keywords):
            _refuse("instance fields differ from frozen spec constructor")
        factory_field = "query_factory" if direction == "ask" else "command_factory"
        factory_node = keywords.get(factory_field)
        if factory_node is None:
            _refuse("concrete factory required")
        factory = _resolve(root, factory_node, tree, source)
        _tree(root, factory.split("::", 1)[0], inventory)
        if factory not in functions:
            _refuse("concrete factory absent from shared executable inventory")
        for field, value in keywords.items():
            if field != factory_field:
                try:
                    ast.literal_eval(value)
                except (ValueError, TypeError):
                    _refuse("instance metadata must be closed literals")
        owner_source, owner_name = owner.split("::", 1)
        owner_tree = _tree(root, owner_source, inventory)
        register = _one([row for row in owner_tree.body if isinstance(row, ast.FunctionDef)
                         and row.name == owner_name], "registration adapter")
        if [row.arg for row in register.args.args] != ["server", "context", "spec"]:
            _refuse("unsupported registration adapter signature")
        annotation = register.args.args[2].annotation
        if annotation is None or _resolve(root, annotation, owner_tree, owner_source) != spec:
            _refuse("registration adapter belongs to a different spec instance type")
        handler = _one([row for row in register.body if isinstance(row, (ast.FunctionDef, ast.AsyncFunctionDef))],
                       "lexical handler")
        if _body(register) != [handler]:
            _refuse("registration adapter must only bind its lexical handler")
        if any(row.arg in {"spec", "context", "server"} for row in (
                *handler.args.posonlyargs, *handler.args.args, *handler.args.kwonlyargs)):
            _refuse("handler shadows captured registration bindings")
        tools = [row for row in handler.decorator_list if isinstance(row, ast.Call)
                 and ast.unparse(row.func) == "server.tool"
                 and any(k.arg == "name" and ast.unparse(k.value) == "spec.name" for k in row.keywords)]
        _one(tools, "current instance tool decorator")
        dispatches = [row for row in ast.walk(handler) if isinstance(row, ast.Call)
                      and ast.unparse(row.func) in {"context.services.mediator.ask", "context.services.mediator.send"}]
        call = _one(dispatches, "actual mediator dispatch")
        if (ast.unparse(call.func) != "context.services.mediator." + direction or len(call.args) != 1
                or not isinstance(call.args[0], ast.Call)
                or ast.unparse(call.args[0].func) != "spec." + factory_field):
            _refuse("dispatch/factory direction or current-instance binding differs")
        if any(isinstance(row, ast.Name) and isinstance(row.ctx, (ast.Store, ast.Del))
               and row.id in {"spec", "context", "server"} for row in ast.walk(register)):
            _refuse("captured registration binding is reassigned")
        if owner not in functions or handler.end_lineno is None:
            _refuse("registration owner absent from shared executable inventory")
        symbol = f"{owner_source}::{owner_name}.{handler.name}[{source}::{table}:{key}]"
        fact = copy.deepcopy(functions[owner])
        fact["symbol"] = symbol
        fact["calls"] = [row for row in fact["calls"] if handler.lineno <= row["line"] <= handler.end_lineno]
        replaced = 0
        for row in fact["calls"]:
            row["caller"] = symbol
            if row["called_symbol"] == owner_source + "::spec." + factory_field:
                row["called_symbol"] = factory
                row["call_name"] = factory.split("::", 1)[1]
                for field in ("method_dispatch", "dispatch_resolution", "dispatch_port_eligible", "import_reference"):
                    row.pop(field, None)
                replaced += 1
        if replaced != 1:
            _refuse("factory call does not resolve to this exact instance")
        # Dynamic calls anywhere in the registration owner remain fail-closed.
        fact["registration_binding"] = {
            "source": source, "table": table, "name": key, "spec": spec,
            "factory": factory, "dispatch": direction,
            "lexical_handler": f"{owner_source}::{owner_name}.{handler.name}",
            "instance_sha256": hashlib.sha256(ast.dump(instance, include_attributes=False).encode()).hexdigest(),
            "factory_arguments": [ast.unparse(row) for row in call.args[0].args],
            "factory_keywords": {row.arg: ast.unparse(row.value) for row in call.args[0].keywords},
        }
        discovered[key] = symbol
        bound.append(fact)
    return discovered, bound

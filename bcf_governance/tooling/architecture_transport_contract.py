"""Closed source-resolved call boundaries for thin Python transport adapters.

Names are not proof of delegation. A call must reach a real inward source
boundary, a checked local helper, or a bounded technical transport operation.
This structural gate complements business-rule review; it never executes source.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

import ast
from collections.abc import Mapping

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_PURE = frozenset({"str", "int", "float", "bool", "bytes", "dict", "list", "tuple", "set",
                   "frozenset", "len", "isinstance", "issubclass", "type", "sorted",
                   "min", "max", "abs", "round", "enumerate", "zip", "range", "repr"})
_RESPONSES = frozenset({f"{module}.{name}" for module in ("starlette.responses", "fastapi.responses")
                        for name in ("Response", "JSONResponse", "RedirectResponse", "HTMLResponse",
                                     "PlainTextResponse", "StreamingResponse", "FileResponse")})
_TECHNICAL = frozenset({"json.dumps", "json.loads", "html.escape", "html.unescape", "typing.cast",
                        "urllib.parse.urlencode", "urllib.parse.urlsplit", "urllib.parse.urlunsplit",
                        "urllib.parse.parse_qsl", "urllib.parse.quote", "urllib.parse.unquote",
                        "logging.getLogger", "structlog.get_logger"})
_LOG_METHODS = frozenset({"bind", "unbind", "debug", "info", "warning", "error", "exception", "critical", "log"})
_RESPONSE_METHODS = frozenset({"set_cookie", "delete_cookie"})
_STRING_METHODS = frozenset({"strip", "lstrip", "rstrip", "lower", "upper", "casefold", "split",
                            "rsplit", "join", "replace", "startswith", "endswith", "encode", "decode"})
_PROTOCOL_ERRORS = frozenset({f"mcp.server.auth.provider.{name}" for name in
                              ("RegistrationError", "AuthorizeError", "TokenError")})
_PROTOCOL_MODELS = frozenset({f"mcp.shared.auth.{name}" for name in
                              ("OAuthClientInformationFull", "OAuthToken")})


def _operation_count(node: ast.AST, costs: Mapping[int, int]) -> int:
    if isinstance(node, (ast.If, ast.IfExp)):
        body: list[ast.AST] = list(node.body) if isinstance(node, ast.If) else [node.body]
        other: list[ast.AST] = list(node.orelse) if isinstance(node, ast.If) else [node.orelse]
        return _operation_count(node.test, costs) + max(
            sum(_operation_count(value, costs) for value in body),
            sum(_operation_count(value, costs) for value in other))
    if isinstance(node, ast.Match):
        return _operation_count(node.subject, costs) + max(
            (sum(_operation_count(value, costs) for value in case.body)
             + (_operation_count(case.guard, costs) if case.guard else 0)
             for case in node.cases), default=0)
    count = costs.get(id(node), 0) + sum(_operation_count(value, costs)
                                        for value in ast.iter_child_nodes(node))
    if isinstance(node, (ast.For, ast.AsyncFor, ast.While, ast.GeneratorExp,
                         ast.ListComp, ast.SetComp, ast.DictComp)):
        return 2 * count
    return count


class _Calls:
    def __init__(self, sources: Mapping[str, ast.Module], layers: Mapping[str, set[str]],
                 source_roots: tuple[str, ...]) -> None:
        self.sources, self.layers = sources, layers
        self.modules: dict[str, set[str]] = {}
        self.bindings: dict[str, dict[str, str]] = {}
        self.definitions: dict[str, ast.AST] = {}
        self.checked: dict[str, list[tuple[int, str]]] = {}
        self.operations: dict[str, int] = {}
        for path, tree in sources.items():
            parts = path.removesuffix(".py").removesuffix("/__init__").split("/")
            self.modules.setdefault(".".join(parts), set()).add(path)
            for root in source_roots:
                if root != "." and path.startswith(root.rstrip("/") + "/"):
                    module = path[len(root.rstrip("/")) + 1:].removesuffix(".py").removesuffix("/__init__")
                    self.modules.setdefault(module.replace("/", "."), set()).add(path)
            values: dict[str, str] = {}
            for node in tree.body:
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        values[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    if node.level:
                        parent = parts if path.endswith("/__init__.py") else parts[:-1]
                        module = ".".join([*parent[:len(parent) - node.level + 1], *module.split(".")]).rstrip(".")
                    for alias in node.names:
                        values[alias.asname or alias.name] = f"{module}.{alias.name}"
                elif isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
                    self.definitions[f"{path}::{node.name}"] = node
                    if isinstance(node, ast.ClassDef):
                        for member in node.body:
                            if isinstance(member, _FUNCTIONS):
                                self.definitions[f"{path}::{node.name}.{member.name}"] = member
                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name):
                            values[target.id] = "<module-rebinding>"
            self.bindings[path] = values

    def resolve(self, value: str, seen: frozenset[str] = frozenset()) -> str:
        if value in seen:
            return "<cyclic-import>"
        if "::" in value or value.startswith("<"):
            return value
        parts = value.split(".")
        for index in range(len(parts) - 1, 0, -1):
            matches = self.modules.get(".".join(parts[:index]), set())
            if len(matches) > 1:
                return "<ambiguous-import>"
            if not matches:
                continue
            path = next(iter(matches))
            tail = parts[index:]
            direct = f"{path}::{'.'.join(tail)}"
            if self.bindings[path].get(tail[0], "").startswith("<"):
                return "<rebound-source-definition>"
            if direct in self.definitions:
                return direct
            exported = self.bindings[path].get(tail[0])
            return self.resolve(".".join([exported, *tail[1:]]), seen | {value}) if exported else direct
        return value

    def target(self, node: ast.AST, path: str, locals_: dict[str, str], depth: int = 0) -> str:
        if depth > 24:
            return "<recursive-result>"
        if isinstance(node, ast.Name):
            if node.id in locals_:
                return locals_[node.id]
            if node.id in self.bindings[path]:
                return self.resolve(self.bindings[path][node.id])
            if "*" in self.bindings[path]:
                return "<unsupported-star-import>"
            local = f"{path}::{node.id}"
            return local if local in self.definitions else node.id
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return "<str>"
        if isinstance(node, ast.Attribute):
            return self.resolve(f"{self.target(node.value, path, locals_, depth + 1)}.{node.attr}")
        if isinstance(node, ast.Call):
            value = self.target(node.func, path, locals_, depth + 1)
            if value in {"logging.getLogger", "structlog.get_logger"} or value.startswith("<logger>."):
                return "<logger>"
            if value in _RESPONSES or value == "str" or value.startswith("<str>."):
                return "<str>" if value == "str" or value.startswith("<str>.") else value
            definition = self.definitions.get(value)
            if isinstance(definition, ast.ClassDef):
                return value
            if isinstance(definition, _FUNCTIONS):
                owner = value.split("::", 1)[0]
                returns = {self.target(member.value, owner, {}, depth + 1)
                           for member in ast.walk(definition) if isinstance(member, ast.Return) and member.value is not None}
                return next(iter(returns)) if len(returns) == 1 else "<unknown-result>"
        return "<unknown>"

    def check(self, symbol: str, pending: frozenset[str] = frozenset()) -> list[tuple[int, str]]:
        if symbol in self.checked:
            return self.checked[symbol]
        if symbol in pending:
            return [(0, "recursive transport helper requires an explicit bounded contract")]
        definition = self.definitions[symbol]
        if not isinstance(definition, _FUNCTIONS):
            return [(0, "unsupported helper definition")]
        path = symbol.split("::", 1)[0]
        locals_: dict[str, str] = {}
        for argument in [*definition.args.posonlyargs, *definition.args.args, *definition.args.kwonlyargs]:
            annotation = self.target(argument.annotation, path, {}) if argument.annotation else "<parameter>"
            locals_[argument.arg] = "<str>" if annotation == "str" else annotation
        failures: list[tuple[int, str]] = []
        operation_costs: dict[int, int] = {}
        for node in ast.walk(definition):
            if isinstance(node, ast.Assign):
                for assigned in node.targets:
                    if isinstance(assigned, ast.Name):
                        locals_[assigned.id] = self.target(node.value, path, locals_)
            if not isinstance(node, ast.Call):
                continue
            target = self.target(node.func, path, locals_)
            # Name tokens never grant delegation. Only discovered inward definitions do.
            location = target.split("::", 1)[0]
            if "::" in target and self.layers.get(location, set()) & {"use_cases", "application", "ports"}:
                if target not in self.definitions:
                    failures.append((node.lineno, f"unresolved inward operation {target}"))
                elif isinstance(self.definitions[target], _FUNCTIONS):
                    operation_costs[id(node)] = 1
                continue
            if target in _PURE or target in _RESPONSES or target in _TECHNICAL or target in _PROTOCOL_ERRORS:
                continue
            if any(target == f"{model}.{method}" for model in _PROTOCOL_MODELS
                   for method in ("model_dump", "model_validate")):
                continue
            if target.startswith("<logger>.") and target.removeprefix("<logger>.") in _LOG_METHODS:
                continue
            if target.startswith("<str>.") and target.removeprefix("<str>.") in _STRING_METHODS:
                continue
            if any(target == f"{response}.{method}" for response in _RESPONSES for method in _RESPONSE_METHODS):
                continue
            child = self.definitions.get(target)
            if isinstance(child, _FUNCTIONS):
                failures.extend(self.check(target, pending | {symbol}))
                operation_costs[id(node)] = self.operations.get(target, 0)
                continue
            if isinstance(child, ast.ClassDef):
                # Exception translation is technical; user-defined constructors are still checked.
                bases = {self.target(base, location, {}) for base in child.bases}
                if bases & {"Exception", "ValueError", "RuntimeError", "TypeError"}:
                    initializer = f"{target}.__init__"
                    if initializer in self.definitions:
                        failures.extend(self.check(initializer, pending | {symbol}))
                    continue
            failures.append((node.lineno, f"unresolved or non-transport call {target}"))
        operations = sum(_operation_count(statement, operation_costs) for statement in definition.body)
        if operations > 1:
            failures.append((definition.lineno, "multiple inward operations require an application orchestrator"))
        self.operations[symbol] = operations
        self.checked[symbol] = failures
        return failures


def transport_violations(
    sources: Mapping[str, ast.Module], layers: Mapping[str, set[str]],
    *, max_branch_nodes: int, max_loop_nodes: int,
    source_roots: tuple[str, ...] = (".",),
) -> list[tuple[str, int, str, str]]:
    """Preserve module complexity caps and prove every transport call boundary."""
    calls = _Calls(sources, layers, source_roots)
    violations: list[tuple[str, int, str, str]] = []
    for path, tree in sources.items():
        if "routers" not in layers.get(path, set()):
            continue
        branches = sum(isinstance(node, (ast.If, ast.Match, ast.Try, ast.TryStar)) for node in ast.walk(tree))
        loops = sum(isinstance(node, (ast.For, ast.AsyncFor, ast.While)) for node in ast.walk(tree))
        if branches > max_branch_nodes:
            violations.append((path, 1, "router_branches", str(branches)))
        if loops > max_loop_nodes:
            violations.append((path, 1, "router_loops", str(loops)))
        for symbol, definition in calls.definitions.items():
            if symbol.split("::", 1)[0] != path or not isinstance(definition, _FUNCTIONS):
                continue
            for line, detail in calls.check(symbol):
                violations.append((path, line, "router_delegation", f"{symbol}: {detail}"))
    return sorted(set(violations))

"""Closed source-resolved call boundaries for thin Python transport adapters.

Names are not proof of delegation. A call must reach a real inward source
boundary, a checked local helper, or a bounded technical transport operation.
This structural gate complements business-rule review; it never executes source.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

import ast
from collections.abc import Iterator, Mapping
from pathlib import Path

from .architecture_registration_contract import registration_factories
from .semantic_operation_effects import AUTHORITY_CALL_PREFIXES, MUTATION_CALL_PREFIXES, WRITE_CALLS

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_PURE = frozenset({"str", "int", "float", "bool", "bytes", "dict", "list", "tuple", "set",
                   "frozenset", "len", "isinstance", "issubclass", "type", "sorted",
                   "min", "max", "abs", "round", "enumerate", "zip", "range", "repr",
                   "RuntimeError", "ValueError", "TypeError"})
_RESPONSES = frozenset({f"{module}.{name}" for module in ("starlette.responses", "fastapi.responses")
                        for name in ("Response", "JSONResponse", "RedirectResponse", "HTMLResponse",
                                     "PlainTextResponse", "StreamingResponse", "FileResponse")})
_TECHNICAL = frozenset({"json.dumps", "json.loads", "html.escape", "html.unescape", "typing.cast",
                        "urllib.parse.urlencode", "urllib.parse.urlsplit", "urllib.parse.urlunsplit",
                        "urllib.parse.parse_qsl", "urllib.parse.quote", "urllib.parse.unquote", "urllib.parse.urlparse",
                        "mcp.server.auth.routes.build_resource_metadata_url", "mcp.server.auth.routes.cors_middleware",
                        "pydantic.AnyHttpUrl", "starlette.routing.Route",
                        "mcp.server.auth.provider.construct_redirect_uri", "time.time", "time.monotonic",
                        "fastapi.HTTPException", "starlette.exceptions.HTTPException",
                        "logging.getLogger", "structlog.get_logger"})
_LOG_METHODS = frozenset({"bind", "unbind", "debug", "info", "warning", "error", "exception", "critical", "log"})
_RESPONSE_METHODS = frozenset({"set_cookie", "delete_cookie"})
_STRING_METHODS = frozenset({"strip", "lstrip", "rstrip", "lower", "upper", "casefold", "split",
                            "rsplit", "join", "replace", "startswith", "endswith", "encode", "decode", "removeprefix", "removesuffix", "partition", "rpartition"})
_PROTOCOL_ERRORS = frozenset({f"mcp.server.auth.provider.{name}" for name in
                              ("RegistrationError", "AuthorizeError", "TokenError")})
_PROTOCOL_MODELS = frozenset({f"mcp.shared.auth.{name}" for name in
                              ("OAuthClientInformationFull", "OAuthToken")})

_INWARD = frozenset({"use_cases", "application", "ports", "composition"})
_BUSINESS_WRITES = WRITE_CALLS | {"save", "delete", "commit", "flush", "merge", "update", "create", "execute_write"}
_PROTOCOL_BINDINGS = frozenset({f"{owner}.{method}" for owner in
    ("mcp.server.fastmcp.FastMCP", "mcp.server.fastmcp.server.FastMCP")
    for method in ("tool", "resource", "prompt", "add_tool", "add_resource", "add_prompt", "custom_route", "streamable_http_app")})
_REQUEST_READS = frozenset({f"{owner}.{member}.get" for owner in
    ("starlette.requests.Request", "fastapi.Request")
    for member in ("headers", "cookies", "query_params", "path_params")})


def _body_nodes(definition: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[ast.AST]:
    pending: list[ast.AST] = list(reversed(definition.body))
    while pending:
        node = pending.pop()
        yield node
        if not isinstance(node, (*_FUNCTIONS, ast.ClassDef, ast.Lambda)):
            pending.extend(reversed(list(ast.iter_child_nodes(node))))


class _Calls:
    def __init__(self, sources: Mapping[str, ast.Module], layers: Mapping[str, set[str]],
                 source_roots: tuple[str, ...], bound_factories: Mapping[str, set[str]]) -> None:
        self.sources, self.layers = sources, layers
        self.bound_factories = bound_factories
        self.rebound_classes: set[str] = set()
        self.modules: dict[str, set[str]] = {}
        self.bindings: dict[str, dict[str, str]] = {}
        self.definitions: dict[str, ast.AST] = {}
        self.checked: dict[str, list[tuple[int, str]]] = {}
        self.effects: dict[str, list[tuple[int, str]]] = {}
        self.delegations: dict[str, bool] = {}
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
            def definitions(node: ast.AST, prefix: str = "", source_path: str = path) -> None:
                if isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
                    prefix += node.name
                    self.definitions[f"{source_path}::{prefix}"] = node
                    prefix += "."
                for child in ast.iter_child_nodes(node):
                    definitions(child, prefix, source_path)
            definitions(tree)
            for mutation in ast.walk(tree):
                targets = mutation.targets if isinstance(mutation, ast.Assign) else [mutation.target] if isinstance(mutation, (ast.AnnAssign, ast.AugAssign)) else []
                if isinstance(mutation, ast.Call) and isinstance(mutation.func, ast.Name) and mutation.func.id == "setattr" and mutation.args:
                    targets = [ast.Attribute(value=mutation.args[0], attr="<dynamic>", ctx=ast.Store())]
                for target in targets:
                    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                        symbol = f"{path}::{target.value.id}"
                        if isinstance(self.definitions.get(symbol), ast.ClassDef):
                            self.rebound_classes.add(symbol)
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

    def annotation_type(self, node: ast.AST, path: str) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            try:
                node = ast.parse(node.value, mode="eval").body
            except SyntaxError:
                return "<unknown>"
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            values = [value for value in (node.left, node.right)
                      if not (isinstance(value, ast.Constant) and value.value is None)]
            targets = {self.annotation_type(value, path) for value in values}
            return next(iter(targets)) if len(targets) == 1 else "<unknown>"
        if isinstance(node, ast.Subscript):
            base = self.target(node.value, path, {})
            if base in {"dict", "typing.Dict", "collections.abc.Mapping", "typing.Mapping"}:
                return "<mapping>"
            if base in {"list", "typing.List"}:
                return "<list>"
            if base in {"typing.Optional", "typing.Annotated"}:
                child = node.slice.elts[0] if isinstance(node.slice, ast.Tuple) else node.slice
                return self.annotation_type(child, path)
        value = self.target(node, path, {})
        return "<str>" if value in {"str", "bytes"} else value

    def field_type(self, symbol: str, name: str, seen: frozenset[str] = frozenset()) -> str | None:
        if symbol in seen:
            return None
        cls = self.definitions.get(symbol)
        if not isinstance(cls, ast.ClassDef):
            return None
        owner = symbol.split("::", 1)[0]
        for member in cls.body:
            if isinstance(member, ast.AnnAssign) and isinstance(member.target, ast.Name) and member.target.id == name:
                return self.annotation_type(member.annotation, owner)
            if (isinstance(member, _FUNCTIONS) and member.name == name and member.returns is not None
                    and any(isinstance(value, ast.Name) and value.id == "property" for value in member.decorator_list)):
                return self.annotation_type(member.returns, owner)
        inherited = {value for base in cls.bases if (value := self.field_type(
            self.annotation_type(base, owner), name, seen | {symbol})) is not None}
        return next(iter(inherited)) if len(inherited) == 1 else None

    def sdk_base(self, symbol: str) -> str | None:
        cls = self.definitions.get(symbol)
        if (not isinstance(cls, ast.ClassDef) or len(cls.bases) != 1 or cls.keywords
                or cls.decorator_list or symbol in self.rebound_classes):
            return None
        if any(isinstance(member, _FUNCTIONS) and member.name in {"__getattr__", "__getattribute__"}
               for member in cls.body):
            return None
        owner = symbol.split("::", 1)[0]
        base = self.target(cls.bases[0], owner, {})
        return base if base in {"mcp.server.fastmcp.FastMCP", "mcp.server.fastmcp.server.FastMCP"} else None

    def inherited_method(self, symbol: str, name: str, seen: frozenset[str] = frozenset()) -> str | None:
        cls = self.definitions.get(symbol)
        if not isinstance(cls, ast.ClassDef):
            return None
        if (symbol in seen or symbol in self.rebound_classes
                or cls.keywords or any(isinstance(member, _FUNCTIONS)
                and member.name in {"__getattr__", "__getattribute__"} for member in cls.body)):
            return "<ambiguous-source-method>"
        for member in cls.body:
            targets = member.targets if isinstance(member, ast.Assign) else [member.target] if isinstance(
                member, (ast.AnnAssign, ast.AugAssign)) else []
            if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                return "<rebound-source-method>"
        direct = f"{symbol}.{name}"
        if isinstance(self.definitions.get(direct), _FUNCTIONS):
            return direct
        owner = symbol.split("::", 1)[0]
        bases = [self.annotation_type(base, owner) for base in cls.bases]
        known = [base for base in bases if isinstance(self.definitions.get(base), ast.ClassDef)]
        candidates = {value for base in known if (value := self.inherited_method(
            base, name, seen | {symbol})) is not None}
        if candidates and any(base not in {"object", "typing.Protocol"} and base not in known for base in bases):
            return "<ambiguous-source-method>"
        return next(iter(candidates)) if len(candidates) == 1 else "<ambiguous-source-method>" if candidates else None

    def registration_result(self, symbol: str) -> bool:
        definition = self.definitions.get(symbol)
        if not isinstance(definition, ast.FunctionDef) or definition.decorator_list or definition.type_params:
            return False
        owner = symbol.split("::", 1)[0]
        locals_ = {argument.arg: self.annotation_type(argument.annotation, owner)
                   for argument in [*definition.args.posonlyargs, *definition.args.args,
                                    *definition.args.kwonlyargs] if argument.annotation is not None}
        nodes = list(_body_nodes(definition))
        if any(isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr,
                                 ast.Delete, ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal,
                                 ast.Yield, ast.YieldFrom, ast.Await, ast.For, ast.AsyncFor,
                                 ast.While, ast.With, ast.AsyncWith, ast.Try, ast.TryStar)) for node in nodes):
            return False
        if any(isinstance(node, ast.Call) and self.target(node.func, owner, locals_) not in _PROTOCOL_BINDINGS
               for node in nodes):
            return False
        identities = set()
        for child in definition.body:
            if not isinstance(child, ast.FunctionDef) or child.name in locals_:
                continue
            args = child.args
            parameters = [*args.posonlyargs, *args.args]
            annotations = [value for value in [*(argument.annotation for argument in parameters), child.returns]
                           if value is not None]
            annotation_nodes = [node for value in annotations for node in ast.walk(value)]
            safe_annotations = all(
                isinstance(node, (ast.Name, ast.Load, ast.Subscript, ast.Tuple, ast.Constant, ast.Attribute))
                and (not isinstance(node, ast.Name) or self.target(node, owner, locals_) in {
                    "typing", "collections", "typing.Callable", "collections.abc.Callable", "typing.Any"})
                and (not isinstance(node, ast.Attribute) or self.target(node, owner, locals_) in {
                    "typing.Callable", "collections.abc", "collections.abc.Callable", "typing.Any"})
                for node in annotation_nodes)
            if (not child.decorator_list and len(parameters) == 1 and not args.defaults
                    and not args.kwonlyargs and args.vararg is None and args.kwarg is None
                    and not child.type_params and safe_annotations
                    and len(child.body) == 1 and isinstance(child.body[0], ast.Return)
                    and isinstance(child.body[0].value, ast.Name)
                    and child.body[0].value.id == parameters[0].arg):
                identities.add(child.name)
        returns = [node.value for node in _body_nodes(definition) if isinstance(node, ast.Return)]
        protocol = False
        for value in returns:
            if isinstance(value, ast.Call) and self.target(value.func, owner, locals_) in _PROTOCOL_BINDINGS:
                protocol = True
            elif not isinstance(value, ast.Name) or value.id not in identities:
                return False
        # Actual helper effects remain checked by check(); only its returned decorator is proven here.
        return protocol

    def route_path(self, node: ast.Call, path: str, locals_: dict[str, str]) -> bool:
        if (self.target(node.func, path, locals_) != "getattr" or node.keywords
                or len(node.args) not in {2, 3} or not isinstance(node.args[0], ast.Name)
                or not isinstance(node.args[1], ast.Constant) or node.args[1].value != "path"
                or (len(node.args) == 3 and not (isinstance(node.args[2], ast.Constant)
                                               and node.args[2].value is None))):
            return False
        for scope in ast.walk(self.sources[path]):
            if (not isinstance(scope, (ast.ListComp, ast.SetComp, ast.GeneratorExp))
                    or len(scope.generators) != 1 or node not in ast.walk(scope)
                    or any(isinstance(value, ast.NamedExpr) for value in ast.walk(scope))):
                continue
            generator = scope.generators[0]
            target, iterator = generator.target, generator.iter
            if (isinstance(target, ast.Tuple) and len(target.elts) == 2
                    and isinstance(target.elts[1], ast.Name) and target.elts[1].id == node.args[0].id
                    and isinstance(iterator, ast.Call) and not iterator.keywords and len(iterator.args) == 1
                    and self.target(iterator.func, path, locals_) == "enumerate"
                    and isinstance(iterator.args[0], ast.Attribute) and iterator.args[0].attr == "routes"
                    and self.target(iterator.args[0].value, path, locals_) == "starlette.applications.Starlette"):
                return True
        return False

    def frozen_data(self, symbol: str) -> bool:
        cls = self.definitions.get(symbol)
        if not isinstance(cls, ast.ClassDef) or cls.bases or cls.keywords:
            return False
        owner = symbol.split("::", 1)[0]
        if "domain" in self.layers.get(owner, set()) or len(cls.decorator_list) != 1:
            return False
        decorator = cls.decorator_list[0]
        if (not isinstance(decorator, ast.Call) or self.target(decorator.func, owner, {}) != "dataclasses.dataclass"
                or not any(value.arg == "frozen" and isinstance(value.value, ast.Constant)
                           and value.value.value is True for value in decorator.keywords)):
            return False
        for member in cls.body:
            if isinstance(member, ast.Expr) and isinstance(member.value, ast.Constant) and isinstance(member.value.value, str):
                continue
            if not isinstance(member, ast.AnnAssign) or not isinstance(member.target, ast.Name):
                return False
            if member.value is not None:
                try:
                    ast.literal_eval(member.value)
                except (TypeError, ValueError):
                    return False
        return True

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
        if isinstance(node, ast.Await):
            return self.target(node.value, path, locals_, depth + 1)
        if isinstance(node, (ast.Dict, ast.DictComp)):
            return "<local_mapping>"
        if isinstance(node, (ast.List, ast.ListComp)):
            return "<local_list>"
        if isinstance(node, (ast.Set, ast.SetComp)):
            return "<local_set>"
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return "<str>"
        if isinstance(node, ast.Attribute):
            lexical = ast.unparse(node)
            if lexical in locals_:
                return locals_[lexical]
            receiver = self.target(node.value, path, locals_, depth + 1)
            field = self.field_type(receiver, node.attr)
            if field is not None:
                return field
            base = self.sdk_base(receiver)
            if base is not None and f"{receiver}.{node.attr}" not in self.definitions and f"{base}.{node.attr}" in _PROTOCOL_BINDINGS:
                return f"{base}.{node.attr}"
            inherited = self.inherited_method(receiver, node.attr)
            if inherited is not None:
                return inherited
            if receiver == "<urlparts>" and node.attr in {"scheme", "netloc", "path", "query", "fragment"}:
                return "<str>"
            return self.resolve(f"{receiver}.{node.attr}")
        if isinstance(node, ast.Call):
            value = self.target(node.func, path, locals_, depth + 1)
            if value == "super" and not node.args and not node.keywords:
                return locals_.get("<super>", "<unsupported-super>")
            if value in {"dict", "list", "set"}:
                return f"<local_{'mapping' if value == 'dict' else value}>"
            if value == "urllib.parse.parse_qsl":
                return "<local_list>"
            if value in {"urllib.parse.urlsplit", "urllib.parse.urlparse"}:
                return "<urlparts>"
            if value in _PROTOCOL_BINDINGS:
                return "<protocol-registration>"
            if value == "getattr" and self.route_path(node, path, locals_):
                return "<str>"
            if value in _REQUEST_READS:
                return "<str>"
            if value in {"logging.getLogger", "structlog.get_logger"} or value.startswith("<logger>."):
                return "<logger>"
            if value in _RESPONSES or value == "str" or value.startswith("<str>."):
                return "<str>" if value == "str" or value.startswith("<str>.") else value
            definition = self.definitions.get(value)
            if isinstance(definition, ast.ClassDef):
                return value
            if isinstance(definition, _FUNCTIONS):
                owner = value.split("::", 1)[0]
                if self.registration_result(value):
                    return "<protocol-registration>"
                if definition.returns is not None:
                    declared = self.annotation_type(definition.returns, owner)
                    if declared not in {"Any", "typing.Any", "object", "None", "<unknown>"}:
                        return declared
                returns = {self.target(member.value, owner, {}, depth + 1)
                           for member in ast.walk(definition) if isinstance(member, ast.Return) and member.value is not None}
                return next(iter(returns)) if len(returns) == 1 else "<unknown-result>"
        return "<unknown>"

    def locals_for(self, symbol: str) -> dict[str, str]:
        definition = self.definitions[symbol]
        assert isinstance(definition, _FUNCTIONS)
        path = symbol.split("::", 1)[0]
        parent = symbol.rsplit(".", 1)[0] if "." in symbol.split("::", 1)[1] else ""
        locals_: dict[str, str] = self.locals_for(parent) if isinstance(self.definitions.get(parent), _FUNCTIONS) else {}
        for argument in [*definition.args.posonlyargs, *definition.args.args, *definition.args.kwonlyargs]:
            annotation = self.annotation_type(argument.annotation, path) if argument.annotation else "<parameter>"
            locals_[argument.arg] = "<str>" if annotation == "str" else annotation
        class_symbol = symbol.rsplit(".", 1)[0] if "." in symbol.split("::", 1)[1] else ""
        class_definition = self.definitions.get(class_symbol)
        parameters = [*definition.args.posonlyargs, *definition.args.args]
        if isinstance(class_definition, ast.ClassDef) and parameters and not any(
            isinstance(value, ast.Name) and value.id == "staticmethod" for value in definition.decorator_list
        ):
            receiver = parameters[0].arg
            locals_[receiver] = class_symbol
            base = self.sdk_base(class_symbol)
            if base is not None:
                locals_["<super>"] = base
            for member in class_definition.body:
                if isinstance(member, ast.AnnAssign) and isinstance(member.target, ast.Name):
                    locals_[f"{receiver}.{member.target.id}"] = self.annotation_type(member.annotation, path)
            constructor = self.definitions.get(f"{class_symbol}.__init__")
            if isinstance(constructor, _FUNCTIONS):
                typed = {argument.arg: self.annotation_type(argument.annotation, path)
                         for argument in [*constructor.args.posonlyargs, *constructor.args.args,
                                          *constructor.args.kwonlyargs] if argument.annotation is not None}
                constructor_args = [*constructor.args.posonlyargs, *constructor.args.args]
                owner = constructor_args[0].arg if constructor_args else "self"
                for assignment in ast.walk(constructor):
                    if not isinstance(assignment, ast.Assign):
                        continue
                    for assigned in assignment.targets:
                        if (isinstance(assigned, ast.Attribute) and isinstance(assigned.value, ast.Name)
                                and assigned.value.id == owner):
                            locals_[f"{receiver}.{assigned.attr}"] = self.target(assignment.value, path, typed)
        for node in _body_nodes(definition):
            if isinstance(node, ast.Assign):
                for assigned in node.targets:
                    if isinstance(assigned, ast.Name):
                        locals_[assigned.id] = self.target(node.value, path, locals_)
            if isinstance(node, _FUNCTIONS):
                locals_[node.name] = f"{symbol}.{node.name}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    locals_[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and not node.level:
                for alias in node.names:
                    locals_[alias.asname or alias.name] = self.resolve(f"{node.module}.{alias.name}")
        return locals_

    def delegates(self, symbol: str, pending: frozenset[str] = frozenset()) -> bool:
        if symbol in self.delegations:
            return self.delegations[symbol]
        if symbol in pending:
            return False
        if symbol in self.bound_factories and all(
            (self.layers.get(factory.split("::", 1)[0], set()) & _INWARD
             or self.delegates(factory, pending | {symbol})) for factory in self.bound_factories[symbol]
        ):
            self.delegations[symbol] = True
            return True
        definition = self.definitions[symbol]
        if not isinstance(definition, _FUNCTIONS):
            return False
        path = symbol.split("::", 1)[0]
        locals_ = self.locals_for(symbol)
        for node in _body_nodes(definition):
            if isinstance(node, ast.Assign):
                for assigned in node.targets:
                    if isinstance(assigned, ast.Name):
                        locals_[assigned.id] = self.target(node.value, path, locals_)
                    elif isinstance(assigned, ast.Attribute):
                        locals_[ast.unparse(assigned)] = self.target(node.value, path, locals_)
            if not isinstance(node, ast.Call):
                continue
            target = self.target(node.func, path, locals_)
            location = target.split("::", 1)[0]
            if ((target in self.definitions and self.layers.get(location, set()) & _INWARD)
                    or target in _PROTOCOL_BINDINGS or target == "<protocol-registration>"):
                self.delegations[symbol] = True
                return True
            if isinstance(self.definitions.get(target), _FUNCTIONS) and self.delegates(target, pending | {symbol}):
                self.delegations[symbol] = True
                return True
        if not pending:
            self.delegations[symbol] = False
        return False

    def check(self, symbol: str, pending: frozenset[str] = frozenset()) -> list[tuple[int, str]]:
        if symbol in self.checked:
            return self.checked[symbol]
        if symbol in pending:
            return [(0, "recursive transport helper requires an explicit bounded contract")]
        definition = self.definitions[symbol]
        if not isinstance(definition, _FUNCTIONS):
            return [(0, "unsupported helper definition")]
        path = symbol.split("::", 1)[0]
        locals_ = self.locals_for(symbol)
        delegated = self.delegates(symbol)
        failures: list[tuple[int, str]] = []
        effects: list[tuple[int, str]] = []
        for node in _body_nodes(definition):
            if isinstance(node, ast.Assign):
                for assigned in node.targets:
                    if isinstance(assigned, ast.Name):
                        locals_[assigned.id] = self.target(node.value, path, locals_)
                    elif isinstance(assigned, ast.Attribute):
                        locals_[ast.unparse(assigned)] = self.target(node.value, path, locals_)
            if not isinstance(node, ast.Call):
                continue
            target = self.target(node.func, path, locals_)
            # Name tokens never grant delegation. Only discovered inward definitions do.
            location = target.split("::", 1)[0]
            if target in self.definitions and self.layers.get(location, set()) & _INWARD:
                continue
            if target == "super" and "<super>" in locals_:
                continue
            if target == "getattr" and self.route_path(node, path, locals_):
                continue
            if target in _PURE or target in _RESPONSES or target in _TECHNICAL or target in _PROTOCOL_ERRORS or target in _PROTOCOL_BINDINGS or target in _REQUEST_READS or target == "<protocol-registration>":
                continue
            if any(target == f"{model}.{method}" for model in _PROTOCOL_MODELS
                   for method in ("model_dump", "model_validate")):
                continue
            if target.startswith("<logger>.") and target.removeprefix("<logger>.") in _LOG_METHODS:
                continue
            container, _, method = target.partition(".")
            if container in {"<mapping>", "<local_mapping>", "<list>", "<local_list>", "<local_set>"}:
                if method in {"get", "items", "keys", "values", "copy", "count", "index"} or (
                    container.startswith("<local_") and method in {"append", "extend", "update", "add", "setdefault", "pop"}):
                    continue
            if target.startswith("<str>.") and target.removeprefix("<str>.") in _STRING_METHODS:
                continue
            if any(target == f"{response}.{method}" for response in _RESPONSES for method in _RESPONSE_METHODS):
                continue
            child = self.definitions.get(target)
            if isinstance(child, _FUNCTIONS):
                child_failures = self.check(target, pending | {symbol})
                effects.extend(self.effects.get(target, []))
                failures.extend(self.effects.get(target, []) if delegated else child_failures)
                continue
            if isinstance(child, ast.ClassDef):
                # Real delegation never conceals a local constructor's effects.
                for method in ("__init__", "__post_init__"):
                    initializer = f"{target}.{method}"
                    if initializer in self.definitions:
                        child_failures = self.check(initializer, pending | {symbol})
                        effects.extend(self.effects.get(initializer, []))
                        failures.extend(self.effects.get(initializer, []) if delegated else child_failures)
                if self.frozen_data(target):
                    continue
                bases = {self.target(base, location, {}) for base in child.bases}
                if bases & {"Exception", "ValueError", "RuntimeError", "TypeError"}:
                    continue
            name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else "<dynamic>"
            business_effect = (name in _BUSINESS_WRITES or name.startswith((*AUTHORITY_CALL_PREFIXES, *MUTATION_CALL_PREFIXES))
                               or target.startswith(("requests.", "httpx.", "sqlalchemy.", "psycopg.", "redis.", "subprocess.")))
            dynamic = (name in {"<dynamic>", "eval", "exec", "__import__"}
                       or target.startswith(("<rebound", "<ambiguous", "<cyclic"))
                       or (name == "super" and "<super>" not in locals_))
            if business_effect or dynamic:
                effect = (node.lineno, f"business effect or dynamic dispatch requires an inward boundary: {target}")
                effects.append(effect)
                failures.append(effect)
            elif not delegated:
                failures.append((node.lineno, f"unresolved or non-transport call {target}"))
        for factory in self.bound_factories.get(symbol, set()):
            self.check(factory, pending | {symbol})
            effects.extend(self.effects.get(factory, []))
            failures.extend(self.effects.get(factory, []))
        self.effects[symbol] = effects
        self.checked[symbol] = failures
        return failures


def transport_violations(
    sources: Mapping[str, ast.Module], layers: Mapping[str, set[str]],
    *, max_branch_nodes: int, max_loop_nodes: int,
    source_roots: tuple[str, ...] = (".",), root: Path | None = None,
) -> list[tuple[str, int, str, str]]:
    """Preserve module complexity caps and prove every transport call boundary."""
    bound, binding_failures = registration_factories(root, sources)
    calls = _Calls(sources, layers, source_roots, bound)
    violations: list[tuple[str, int, str, str]] = [
        (path, line, "router_delegation", detail) for path, line, detail in binding_failures]
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

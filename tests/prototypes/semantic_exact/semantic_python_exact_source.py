"""Source-body checking for exact guarded data; no opaque helper permissions.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

import ast
import hashlib
from typing import Any

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import _imports
from bcf_governance.tooling.semantic_python_value_origins import value_origins

from .inventory import native_builtin_names as container_builtin_names
from .semantic_python_exact_control import ExactFlow
from .semantic_python_exact_expressions import ExactExpressions
from .semantic_python_exact_guards import set_path, value_path
from .semantic_python_exact_values import (
    NONE,
    STR,
    UNKNOWN,
    ExactProtocolRefusal,
    ExactState,
    ExactValue,
    callback_free,
    union,
)


def literal_shape(value: object) -> ExactValue:
    """Describe only compiler literals; never inspect an arbitrary object."""
    if (value is None or type(value) is str or type(value) is int
            or type(value) is float or type(value) is bool or type(value) is bytes):
        return ExactValue("none" if value is None else type(value).__name__)
    if type(value) is dict:
        return ExactValue("dict", (union(*(literal_shape(key) for key in value)),
                                   union(*(literal_shape(item) for item in value.values()))),
                          fields=tuple((key, literal_shape(item)) for key, item in value.items() if type(key) is str))
    if type(value) is list or type(value) is tuple or type(value) is set or type(value) is frozenset:
        assert isinstance(value, (list, tuple, set, frozenset))
        items = [literal_shape(item) for item in value]
        return ExactValue(type(value).__name__, (union(*items),),
                          fields=tuple((str(index), item) for index, item in enumerate(items)) if type(value) is tuple else ())
    raise ExactProtocolRefusal("nonliteral module value")


def binding_member(subject: str, name: str) -> str:
    return subject.removesuffix("::module") + "::" + name if subject.endswith("::module") else subject + "." + name


class ExactSourceBodies:
    """Check actual method bodies from the shared inventory, not type hints.

    Resource methods deliberately remain unsupported here. A separate verified
    lifetime proof must provide those capabilities before an operation can use
    them; a protocol annotation or a matching method name cannot create one.
    """

    def __init__(self, inventory: dict[str, Any]) -> None:
        self.inventory = inventory
        self.functions = {str(row["symbol"]): row for row in
                          [*inventory.get("functions", []), *inventory.get("source_callable_frames", [])]}
        self.classes = {str(row["symbol"]): row for row in inventory.get("classes", [])}
        self.modules: dict[str, ast.Module] = {}
        for row in inventory.get("python_modules", []):
            tree = ast.parse(row["source"])
            digest = hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest()
            if digest != row["shape_sha256"]:
                raise ExactProtocolRefusal("module source does not match its inventory")
            self.modules[row["path"]] = tree
        module_index = {path.removesuffix(".py").removesuffix("/__init__").replace("/", "."): path
                        for path in self.modules}
        self.imports = {path: _imports(tree, module_index, path.removesuffix(".py").replace("/", "."))
                        for path, tree in self.modules.items()}
        self.active: list[str] = []
        self.checked: set[str] = set()
        self._literals: dict[tuple[str, str], ExactValue] = {}

    def _stable(self, path: str, name: str, *, definition: bool = False) -> bool:
        tree = self.modules.get(path)
        if tree is None:
            return False
        if any(isinstance(node, ast.Name) and node.id in {
            "globals", "locals", "vars", "eval", "exec", "setattr", "delattr", "__import__"
        } for node in ast.walk(tree)):
            return False
        stores = [node for node in ast.walk(tree) if isinstance(node, ast.Name)
                  and node.id == name and isinstance(node.ctx, (ast.Store, ast.Del))]
        declarations = [node for node in ast.walk(tree)
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name]
        if definition:
            return not stores and len(declarations) == 1
        if name in self.imports.get(path, {}):
            return not stores and not declarations and not any(
                isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                and node.value.id == name and isinstance(node.ctx, (ast.Store, ast.Del))
                for node in ast.walk(tree))
        return len(stores) == 1 and not declarations

    def _module_literal(self, path: str, name: str) -> ExactValue:
        key = (path, name)
        if key in self._literals:
            return self._literals[key]
        if not self._stable(path, name):
            raise ExactProtocolRefusal(f"module literal binding is not closed: {path}::{name}")
        tree = self.modules[path]
        candidates = [node.value for node in tree.body
                      if isinstance(node, ast.Assign) and len(node.targets) == 1
                      and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
        if len(candidates) != 1:
            raise ExactProtocolRefusal("module binding is not one literal assignment")
        value = candidates[0]
        frozen = isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "frozenset"
        if frozen:
            assert isinstance(value, ast.Call)
            if len(value.args) != 1 or value.keywords or "frozenset" in self.imports[path] or any(
                isinstance(node, ast.Name) and node.id == "frozenset" and isinstance(node.ctx, ast.Store)
                for node in ast.walk(tree)
            ):
                raise ExactProtocolRefusal("foreign frozenset construction")
            value = value.args[0]
        try:
            shape = literal_shape(ast.literal_eval(value))
        except (ValueError, TypeError, SyntaxError) as error:
            raise ExactProtocolRefusal("module binding is not literal native data") from error
        if frozen:
            shape = ExactValue("frozenset", shape.children)
        if shape.kind in {"dict", "list", "set"}:
            parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
            for node in ast.walk(tree):
                if not isinstance(node, ast.Name) or node.id != name or not isinstance(node.ctx, ast.Load):
                    continue
                parent = parents[id(node)]
                if isinstance(parent, ast.Compare) and any(isinstance(op, (ast.In, ast.NotIn)) for op in parent.ops):
                    continue
                if isinstance(parent, ast.Attribute) and parent.value is node and parent.attr in {"get", "items", "keys", "values"}:
                    call = parents.get(id(parent))
                    if isinstance(call, ast.Call) and call.func is parent:
                        continue
                raise ExactProtocolRefusal("mutable module literal escapes or is written")
            for other_path, other in self.modules.items():
                if other_path != path and any(isinstance(node, ast.Attribute) and node.attr == name for node in ast.walk(other)):
                    raise ExactProtocolRefusal("module literal has an external member reference")
                if other_path != path and any(isinstance(node, ast.ImportFrom)
                    and any(alias.name in {name, "*"} for alias in node.names) for node in ast.walk(other)):
                    raise ExactProtocolRefusal("module literal has an external import")
        self._literals[key] = shape
        return shape

    def record_fields(self, subject: str) -> set[str]:
        row = self.classes.get(subject, {})
        if not row.get("closed_class_binding") or not row.get("standard_dataclass_declaration") or row.get("bases") or row.get("metaclass_keywords"):
            raise ExactProtocolRefusal("record class binding or layout is not closed")
        path, _, name = subject.partition("::")
        declarations = [node for node in self.modules.get(path, ast.Module(body=[], type_ignores=[])).body
                        if isinstance(node, ast.ClassDef) and node.name == name]
        if len(declarations) != 1:
            raise ExactProtocolRefusal("record class source is absent")
        node = declarations[0]
        options = {item.arg: item.value.value for decorator in node.decorator_list if isinstance(decorator, ast.Call)
                   for item in decorator.keywords if isinstance(item.value, ast.Constant)}
        if options.get("frozen") is not True or options.get("slots") is not True or len(node.decorator_list) != 1:
            raise ExactProtocolRefusal("record is not a native frozen-slot dataclass")
        forbidden = {"__new__", "__init__", "__del__", "__getattr__", "__getattribute__", "__setattr__",
                     "__delattr__", "__bool__", "__len__", "__iter__", "__eq__", "__ne__", "__hash__"}
        if any(isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in forbidden for item in node.body):
            raise ExactProtocolRefusal("record has a foreign storage or comparison protocol")
        builtins = set(container_builtin_names(self.modules[path]))
        def stored(annotation: ast.AST) -> bool:
            if isinstance(annotation, ast.Constant):
                if annotation.value is None:
                    return True
                if type(annotation.value) is str:
                    try:
                        return stored(ast.parse(annotation.value, mode="eval").body)
                    except SyntaxError:
                        return False
            if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
                return stored(annotation.left) and stored(annotation.right)
            if isinstance(annotation, ast.Name):
                target = self.imports[path].get(annotation.id, path + "::" + annotation.id)
                return (annotation.id in builtins or target in {"typing::Any", "datetime::date", "datetime::datetime"}
                        or target in self.classes and bool(self.classes[target].get("closed_class_binding")))
            if isinstance(annotation, ast.Subscript) and isinstance(annotation.value, ast.Name):
                root = annotation.value.id
                target = self.imports[path].get(root, "")
                return (root in builtins and root in {"tuple", "list", "dict", "set", "frozenset"}
                        or target in {"typing::List", "typing::Dict", "typing::Tuple", "typing::Set",
                                      "typing::FrozenSet", "typing::Sequence", "typing::Mapping", "typing::Literal"})
            return False
        fields = {item.target.id for item in node.body if isinstance(item, ast.AnnAssign)
                  and isinstance(item.target, ast.Name) and stored(item.annotation)}
        if fields & {item.name for item in node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))}:
            raise ExactProtocolRefusal("record field collides with a descriptor")
        return fields

    def type_bindings(self, row: dict[str, Any]) -> dict[str, str]:
        result = {name: name for name in row.get("unshadowed_container_builtins", [])}
        path = str(row["symbol"]).partition("::")[0]
        for name, subject in self.imports.get(path, {}).items():
            if subject in self.classes and self._stable(path, name):
                try:
                    self.record_fields(subject)
                except ExactProtocolRefusal:
                    continue
                result[name] = "record:" + subject
            elif subject == "datetime::date" and self._stable(path, name):
                result[name] = "date"
        for subject in self.classes:
            if subject.partition("::")[0] == path:
                name = subject.partition("::")[2]
                try:
                    self.record_fields(subject)
                except ExactProtocolRefusal:
                    continue
                result[name] = "record:" + subject
        return result

    def binding(self, frame: ExactExpressions, name: str) -> ExactValue:
        path = str(frame.row["symbol"]).partition("::")[0]
        if name in frame.row.get("unshadowed_container_builtins", []):
            return ExactValue("binding", subject="builtins::" + name)
        subject = self.imports.get(path, {}).get(name)
        if subject is not None and self._stable(path, name):
            return ExactValue("binding", subject=subject)
        subject = path + "::" + name
        if subject in self.classes or subject in self.functions:
            if self._stable(path, name, definition=True):
                return ExactValue("binding", subject=subject)
        return self._module_literal(path, name)

    def attribute(self, frame: ExactExpressions, receiver: ExactValue, name: str) -> ExactValue:
        if receiver.kind == "record":
            if name in self.record_fields(receiver.subject):
                return receiver.member(name)
            method = next((row for row in self.classes[receiver.subject].get("methods", []) if row["name"] == name), None)
            if method and "property" in method.get("decorators", []):
                return self.call(str(method["symbol"]), [receiver], {}, frame.state)[0]
        if receiver.kind == "binding":
            return ExactValue("binding", subject=binding_member(receiver.subject, name))
        raise ExactProtocolRefusal("attribute has no exact native field or source getter proof")

    def comparable(self, left: ExactValue, right: ExactValue) -> bool:
        if left.kind != "record" or right.kind != "record" or left.subject != right.subject:
            return False
        fields = self.record_fields(left.subject)
        return all(callback_free(left.member(name)) and callback_free(right.member(name)) for name in fields)

    def invoke(self, frame: ExactExpressions, node: ast.Call, receiver: ExactValue | None,
               arguments: list[ExactValue], keywords: dict[str, ExactValue]) -> ExactValue:
        target = str(frame.calls.get(frame.positions[id(node)], {}).get("called_symbol", ""))
        source_receiver = None
        if isinstance(node.func, ast.Name):
            binding = frame.state.env.get(node.func.id)
            binding = self.binding(frame, node.func.id) if binding is None else binding
            if binding.kind != "binding":
                raise frame.refusal(node, "dynamic callable binding is not qualified")
            target = binding.subject
        if receiver is not None:
            receiver = frame.state.resolve(receiver)
            if receiver.kind == "legacy-instance" and isinstance(node.func, ast.Attribute):
                import json
                payload = json.loads(receiver.subject.removeprefix("source-instance:"))
                target = payload.get("methods", {}).get(node.func.attr, "")
                return self._legacy_call(str(target), [receiver, *arguments], keywords, frame.state)
            if receiver.kind == "record" and isinstance(node.func, ast.Attribute):
                self.record_fields(receiver.subject)
                method = next((row for row in self.classes[receiver.subject].get("methods", [])
                               if row["name"] == node.func.attr and row.get("binding") == "instance"), None)
                if method is None:
                    raise frame.refusal(node, "source record method binding is absent")
                target, source_receiver = str(method["symbol"]), receiver
            elif receiver.kind == "binding" and isinstance(node.func, ast.Attribute):
                target = binding_member(receiver.subject, node.func.attr)
            elif receiver.kind not in {"date", "datetime"}:
                raise frame.refusal(node, "foreign method receiver")
        if target == "typing::cast" and len(arguments) == 2 and not keywords and arguments[0].kind == "type_expression":
            return arguments[1]
        if target in {"datetime::date.fromisoformat", "datetime::datetime.fromisoformat"} and len(arguments) == 1 and not keywords and frame.state.resolve(arguments[0]).kind == "str":
            return ExactValue(target.split("::")[1].split(".")[0])
        if receiver is not None and receiver.kind in {"date", "datetime"} and isinstance(node.func, ast.Attribute) and not arguments and not keywords:
            if node.func.attr == "isoformat":
                return STR
            if node.func.attr == "date" and receiver.kind == "datetime":
                return ExactValue("date")
        if target == "re::fullmatch" and len(arguments) == 2 and not keywords and all(frame.state.resolve(value).kind == "str" for value in arguments):
            return union(NONE, ExactValue("match"))
        if target not in self.functions:
            raise frame.refusal(node, "unqualified source or library invocation: " + target)
        values = [source_receiver, *arguments] if source_receiver is not None else arguments
        if any(call.get("source_constructor_frame", {}).get("instance_methods") for call in self.functions[target].get("calls", [])):
            return self._legacy_call(target, values, keywords, frame.state)
        result, after, names = self.call(target, values, keywords, frame.state)
        if source_receiver is not None and isinstance(node.func, ast.Attribute) and (path := value_path(node.func.value)):
            set_path(frame.state, path, after.env[names[0]])
        offset = 1 if source_receiver is not None else 0
        for parameter, actual in zip(names[offset:], node.args, strict=False):
            if (path := value_path(actual)) is not None:
                set_path(frame.state, path, after.env.get(parameter, UNKNOWN))
        for keyword in node.keywords:
            if keyword.arg is not None and (path := value_path(keyword.value)) is not None:
                set_path(frame.state, path, after.env.get(keyword.arg, UNKNOWN))
        declaration = ast.parse(self.functions[target]["python_value_source"]).body[0]
        return ExactValue("awaitable", (result,)) if isinstance(declaration, ast.AsyncFunctionDef) else result

    def _legacy_call(self, symbol: str, arguments: list[ExactValue], keywords: dict[str, ExactValue], state: ExactState) -> ExactValue:
        row = self.functions.get(symbol, {})
        if not row.get("python_value_source"):
            raise ExactProtocolRefusal("legacy source invocation is absent")
        declaration = ast.parse(row["python_value_source"]).body[0]
        if not isinstance(declaration, (ast.FunctionDef, ast.AsyncFunctionDef)):
            raise ExactProtocolRefusal("legacy source invocation is not callable")
        names = [arg.arg for arg in [*declaration.args.posonlyargs, *declaration.args.args]]
        if len(arguments) > len(names) or set(names[:len(arguments)]) & keywords.keys():
            raise ExactProtocolRefusal("legacy invocation does not bind")
        def origin(value: ExactValue) -> str:
            resolved = state.resolve(value)
            if resolved.kind == "legacy-instance":
                return resolved.subject
            return "scalar" if resolved.kind in {"none", "bool", "int", "str", "float", "complex", "bytes"} else "unknown"
        bound = dict(zip(names, (origin(value) for value in arguments), strict=False))
        bound.update({name: origin(value) for name, value in keywords.items()})
        bound["$source_callable_proof"] = "true"
        context = tuple(sorted(bound.items()))
        operation = {"id": "native-source-composition", "authoritative_read": False,
                     "allowed_mutation_ports": [], "allowed_authority_ports": [], "non_authoritative_output_effects": []}
        try:
            validate_operation_effects(operation, symbol, self.inventory, experimental_protocols=False, _entry_arguments=context)
        except SemanticOperationEffectError as error:
            raise ExactProtocolRefusal(str(error)) from error
        result = value_origins(symbol, self.functions, context).get("return", "unknown")
        self.checked.add(symbol)
        return ExactValue("legacy-instance", subject=result) if str(result).startswith("source-instance:") else UNKNOWN

    def call(self, symbol: str, arguments: list[ExactValue], keywords: dict[str, ExactValue],
             caller: ExactState | None = None) -> tuple[ExactValue, ExactState, list[str]]:
        if symbol not in self.functions or symbol in self.active or len(self.active) >= 24:
            raise ExactProtocolRefusal("recursive, missing or over-budget source invocation")
        row = self.functions[symbol]
        declaration = ast.parse(row["python_value_source"]).body[0]
        if not isinstance(declaration, (ast.FunctionDef, ast.AsyncFunctionDef)) or declaration.args.vararg or declaration.args.kwarg:
            raise ExactProtocolRefusal("source invocation signature is not closed")
        names = [item.arg for item in [*declaration.args.posonlyargs, *declaration.args.args]]
        if len(arguments) > len(names) or set(names[:len(arguments)]) & keywords.keys():
            raise ExactProtocolRefusal("source invocation arguments do not bind")
        env = dict(zip(names, arguments, strict=False))
        env.update(keywords)
        defaults = list(zip(names[-len(declaration.args.defaults):], declaration.args.defaults, strict=True)) if declaration.args.defaults else []
        defaults.extend((item.arg, default) for item, default in zip(declaration.args.kwonlyargs, declaration.args.kw_defaults, strict=True) if default is not None)
        for name, default in defaults:
            if name not in env:
                try:
                    env[name] = literal_shape(ast.literal_eval(default))
                except (ValueError, TypeError, SyntaxError) as error:
                    raise ExactProtocolRefusal("source default requires an independent execution proof") from error
        expected = {*names, *(item.arg for item in declaration.args.kwonlyargs)}
        if env.keys() != expected:
            raise ExactProtocolRefusal("missing or extra source invocation arguments")
        state = ExactState(env, dict(caller.heap) if caller else {})
        identity = symbol + ":" + hashlib.sha256(repr(sorted(env.items())).encode()).hexdigest()[:16]
        frame = ExactFlow(row, state, self, self.type_bindings(row), identity)
        self.active.append(symbol)
        try:
            result, after = frame.run()
        finally:
            self.active.pop()
        if caller is not None:
            caller.heap.update(after.heap)
        self.checked.add(symbol)
        return result, after, names

    def enter_context(self, frame: ExactFlow, value: ExactValue, asynchronous: bool) -> ExactValue:
        raise ExactProtocolRefusal("resource lifetime proof is absent")

    def exit_context(self, frame: ExactFlow, value: ExactValue) -> None:
        raise ExactProtocolRefusal("resource exit proof is absent")

    def returned(self, frame: ExactFlow, value: ExactValue) -> None:
        if value.kind in {"resource", "context"}:
            raise ExactProtocolRefusal("resource escapes its admitted lifetime")

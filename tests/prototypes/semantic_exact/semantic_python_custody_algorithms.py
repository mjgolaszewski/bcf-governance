"""Complete structural proofs of bounded cancellation-custody algorithms.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.

These are lifetime facts, never callback purity or effect-port permissions.
Their native task/context input obligations must be proved by each caller.
"""
from __future__ import annotations

import ast
import copy
import hashlib
from dataclasses import dataclass
from typing import Any

from .semantic_python_exact_source import ExactSourceBodies
from .semantic_python_exact_values import ExactProtocolRefusal

TASK_DRAIN = '''
try:
    return await ASYNCIO.shield(TASK)
except ASYNCIO.CancelledError:
    if CANCELLED is not None:
        CANCELLED.set()
    while not TASK.done():
        try:
            await ASYNCIO.shield(TASK)
        except ASYNCIO.CancelledError:
            continue
        except Exception:
            break
    if TASK.done() and not TASK.cancelled():
        TASK.exception()
    raise
'''

FILE_IO = '''
TASK = ASYNCIO.create_task(ASYNCIO.to_thread(OPERATION, *ARGS, **KWARGS))
return await AWAITER(TASK)
'''

FILE_CONTEXT = '''
ENTERED = EVENT_FACTORY()
def ACQUIRE():
    VALUE = CONTEXT.__enter__()
    ENTERED.set()
    return VALUE
async def RELEASE():
    await RUN_IO(CONTEXT.__exit__, None, None, None)
try:
    VALUE = await RUN_IO(ACQUIRE)
except BaseException:
    if ENTERED.is_set():
        await RELEASE()
    raise
try:
    yield VALUE
finally:
    await RELEASE()
'''


@dataclass(frozen=True)
class CustodyAlgorithmEvidence:
    symbol: str
    algorithm: str
    shape_sha256: str
    required_inputs: tuple[str, ...]
    dependencies: tuple[CustodyAlgorithmEvidence, ...] = ()
    confers_effect_permission: bool = False
    header_execution_qualified: bool = False


def _body(function: ast.AsyncFunctionDef) -> list[ast.stmt]:
    body = copy.deepcopy(function.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body.pop(0)
    # Header execution stays a separate inventory obligation. Normalizing it
    # here does not certify decorators/defaults/annotations as pure.
    for statement in body:
        for node in ast.walk(statement):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                node.returns = None
                node.type_comment = None
                node.type_params = []
            elif isinstance(node, ast.arg):
                node.annotation = None
                node.type_comment = None
    return body


def _matches(pattern: Any, actual: Any, roles: dict[str, str]) -> bool:
    if type(pattern) is not type(actual):
        return False
    if isinstance(pattern, list):
        return len(pattern) == len(actual) and all(_matches(left, right, roles) for left, right in zip(pattern, actual, strict=True))
    if isinstance(pattern, ast.AST):
        for name, expected in ast.iter_fields(pattern):
            observed = getattr(actual, name)
            if name in {"id", "name", "arg"} and isinstance(expected, str) and expected.isupper():
                if expected not in roles:
                    if observed in roles.values():
                        return False
                    roles[expected] = observed
                if roles[expected] != observed:
                    return False
            elif not _matches(expected, observed, roles):
                return False
        return True
    return bool(pattern == actual)


class NativeCustodyAlgorithms:
    def __init__(self, inventory: dict[str, Any]) -> None:
        self.world = ExactSourceBodies(inventory)

    def _function(self, symbol: str) -> tuple[dict[str, Any], ast.AsyncFunctionDef]:
        row = self.world.functions.get(symbol)
        if row is None:
            raise ExactProtocolRefusal("custody source function is absent")
        function = ast.parse(row["python_value_source"]).body[0]
        if not isinstance(function, ast.AsyncFunctionDef):
            raise ExactProtocolRefusal("custody function is not a native async definition")
        digest = hashlib.sha256(ast.dump(function, include_attributes=False).encode()).hexdigest()
        if digest != row["python_value_shape_sha256"]:
            raise ExactProtocolRefusal("custody source shape changed")
        path, _, name = symbol.partition("::")
        if not self.world._stable(path, name, definition=True) or any(call.get("known_rebound_import") for call in row.get("calls", [])):
            raise ExactProtocolRefusal("custody source or library binding is not closed")
        return row, function

    def _import(self, path: str, subject: str) -> str:
        candidates = [name for name, target in self.world.imports[path].items()
                      if target == subject and self.world._stable(path, name)]
        if len(candidates) != 1:
            raise ExactProtocolRefusal("custody primitive import does not bind uniquely: " + subject)
        return candidates[0]

    def _match(self, row: dict[str, Any], function: ast.AsyncFunctionDef, pattern: str,
               roles: dict[str, str]) -> dict[str, str]:
        parsed = ast.parse("async def proof():\n" + "".join("    " + line + "\n" for line in pattern.splitlines())).body[0]
        assert isinstance(parsed, ast.AsyncFunctionDef)
        if not _matches(_body(parsed), _body(function), roles):
            raise ExactProtocolRefusal("complete custody body does not match the proved algorithm: " + str(row["symbol"]))
        return roles

    def task_drain(self, symbol: str) -> CustodyAlgorithmEvidence:
        row, function = self._function(symbol)
        args = function.args
        positional = [*args.posonlyargs, *args.args]
        if (function.decorator_list or len(positional) != 2 or args.vararg or args.kwarg or args.kwonlyargs
                or len(args.defaults) != 1 or not isinstance(args.defaults[0], ast.Constant) or args.defaults[0].value is not None):
            raise ExactProtocolRefusal("drain signature does not preserve the required None cancellation binding")
        if "Exception" not in row.get("unshadowed_container_builtins", []):
            raise ExactProtocolRefusal("drain exception matching is not native")
        path = symbol.partition("::")[0]
        self._match(row, function, TASK_DRAIN, {"TASK": positional[0].arg, "CANCELLED": positional[1].arg,
                                              "ASYNCIO": self._import(path, "asyncio::module")})
        return CustodyAlgorithmEvidence(symbol, "drain-native-task-through-repeated-cancellation-v1",
            row["python_value_shape_sha256"], ("exact-native-asyncio-task", "cancelled-is-None", "native-asyncio-shield-binding"))

    def file_io(self, symbol: str) -> CustodyAlgorithmEvidence:
        row, function = self._function(symbol)
        args = function.args
        positional = [*args.posonlyargs, *args.args]
        if (function.decorator_list or len(positional) != 1 or args.defaults or args.kwonlyargs
                or args.vararg is None or args.kwarg is None):
            raise ExactProtocolRefusal("file-work signature does not bind its actual callback")
        path = symbol.partition("::")[0]
        roles = self._match(row, function, FILE_IO, {"OPERATION": positional[0].arg,
            "ARGS": args.vararg.arg, "KWARGS": args.kwarg.arg, "ASYNCIO": self._import(path, "asyncio::module")})
        target = self.world.imports[path].get(roles["AWAITER"])
        if target is None:
            raise ExactProtocolRefusal("actual file-work drain target is absent")
        dependency = self.task_drain(target)
        return CustodyAlgorithmEvidence(symbol, "thread-work-task-drained-before-return-v1",
            row["python_value_shape_sha256"], ("native-default-task-factory", "native-asyncio-to-thread-binding",
            "callback-effects-remain-with-the-declaring-port"), (dependency,))

    def file_context(self, symbol: str) -> CustodyAlgorithmEvidence:
        row, function = self._function(symbol)
        args = function.args
        positional = [*args.posonlyargs, *args.args]
        if len(positional) != 1 or args.defaults or args.vararg or args.kwarg or args.kwonlyargs or len(function.decorator_list) != 1:
            raise ExactProtocolRefusal("file-context signature does not bind one actual manager")
        path = symbol.partition("::")[0]
        decorator = function.decorator_list[0]
        if not isinstance(decorator, ast.Name) or self.world.imports[path].get(decorator.id) != "contextlib::asynccontextmanager" or not self.world._stable(path, decorator.id):
            raise ExactProtocolRefusal("file-context wrapper is not the native contextlib binding")
        if "BaseException" not in row.get("unshadowed_container_builtins", []):
            raise ExactProtocolRefusal("file-context exceptional acquisition is not closed")
        roles = self._match(row, function, FILE_CONTEXT, {"CONTEXT": positional[0].arg,
            "EVENT_FACTORY": self._import(path, "threading::Event")})
        target = self.world.imports[path].get(roles["RUN_IO"])
        if target is None:
            raise ExactProtocolRefusal("actual context acquisition/release worker is absent")
        dependency = self.file_io(target)
        return CustodyAlgorithmEvidence(symbol, "observable-acquire-and-drained-exit-v1",
            row["python_value_shape_sha256"], ("qualified-actual-sync-manager", "native-threading-event",
            "enter-and-exit-effects-remain-with-the-declaring-port"), (dependency,))

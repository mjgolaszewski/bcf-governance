"""Proposed neutral constructor contexts; never dispatch or effect authority.

Source-only prototype for Root review. It does not change inventory call edges,
opaque-input guards, unsupported flags, definition-time obligations or ports.
"""
from __future__ import annotations

import ast
import copy
import hashlib
from collections.abc import Callable, Mapping
from typing import Any

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_HOOKS = {"__new__", "__getattr__", "__getattribute__", "__setattr__",
          "__delattr__", "__init_subclass__", "__slots__"}


def _digest(node: ast.AST) -> str:
    return hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()


def _value(node: ast.expr, source: str) -> dict[str, Any]:
    return {"expression_AST": ast.unparse(node), "AST_sha256": _digest(node),
            "source": source, "literal": isinstance(node, ast.Constant),
            "opaque_parameter": not isinstance(node, ast.Constant),
            "runtime_value": "NOT_EVALUATED"}


def _bind(function: ast.FunctionDef | ast.AsyncFunctionDef, call: ast.Call
          ) -> tuple[dict[str, Any], list[str]]:
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    failures: list[str] = []
    if not positional or args.vararg or args.kwarg or function.decorator_list:
        return {}, ["unsupported_receiver_or_signature"]
    receiver = positional.pop(0).arg
    names = [n.arg for n in positional]
    posonly = {n.arg for n in args.posonlyargs} - {receiver}
    keyword_names = {n.arg for n in args.kwonlyargs}
    if len(call.args) > len(names) or any(isinstance(n, ast.Starred) for n in call.args):
        failures.append("unsupported_positional_binding")
    bound = {name: _value(value, "explicit_positional")
             for name, value in zip(names, call.args, strict=False)}
    for keyword in call.keywords:
        name = keyword.arg
        if name is None or name in bound or name in posonly or name not in set(names) | keyword_names:
            failures.append("duplicate_expanded_or_unknown_keyword")
        else:
            bound[name] = _value(keyword.value, "explicit_keyword")
    all_positional = [*args.posonlyargs, *args.args]
    defaults: dict[str, ast.expr | None] = {n.arg: value for n, value in zip(
        all_positional[-len(args.defaults):] if args.defaults else [], args.defaults, strict=True)}
    defaults.update({n.arg: value for n, value in zip(args.kwonlyargs, args.kw_defaults, strict=True)})
    for name in [*names, *[n.arg for n in args.kwonlyargs]]:
        if name in bound:
            continue
        default = defaults.get(name)
        if default is None:
            failures.append("missing_required_argument:" + name)
        else:
            bound[name] = _value(default, "omitted_default")
            if not isinstance(default, ast.Constant):
                failures.append("nonliteral_default_obligation:" + name)
    return bound, failures


def _summary(function: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Any]:
    parameters = [*function.args.posonlyargs, *function.args.args]
    receiver = parameters[0].arg if parameters else None
    writes, calls, unsupported = [], [], []
    declarations = [node for statement in function.body for node in ast.walk(statement)
                    if isinstance(node, ast.AnnAssign)]
    annotation_nodes = {id(value) for node in declarations for value in ast.walk(node.annotation)}
    annotation_obligations = [{"line": node.lineno, "target_AST": ast.unparse(node.target),
                               "annotation_AST": ast.unparse(node.annotation),
                               "performs_store": node.value is not None,
                               "evaluation_policy": "Scope/interpreter declaration and target-expression obligations retained; annotation not executed by collector."}
                              for node in declarations]
    simple = not isinstance(function, ast.AsyncFunctionDef)
    if not simple:
        unsupported.append("async_callable_requires_await_context")
    for statement in function.body:
        if isinstance(statement, ast.AnnAssign) and statement.value is None:
            annotation_target = statement.target
            if not (isinstance(annotation_target, ast.Name) or isinstance(annotation_target, ast.Attribute)
                    and isinstance(annotation_target.value, ast.Name) and annotation_target.value.id == receiver):
                unsupported.append("annotation_target_evaluation_obligation")
                simple = False
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for target in targets:
                if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == receiver:
                    if statement.value is not None and not isinstance(statement.value, (ast.Name, ast.Constant)):
                        unsupported.append("assignment_expression_effect_obligation")
                        simple = False
                else:
                    unsupported.append("non_receiver_assignment")
                    simple = False
        elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
            pass  # Source docstring; no expression execution claimed.
        elif isinstance(statement, ast.Pass):
            pass
        else:
            unsupported.append(type(statement).__name__)
            simple = False
        for node in ast.walk(statement):
            if id(node) in annotation_nodes:
                continue
            if isinstance(node, ast.Call):
                calls.append({"line": node.lineno, "expression_AST": ast.unparse(node),
                              "AST_sha256": _digest(node), "effect": "UNRESOLVED"})
                simple = False
            if isinstance(node, (ast.Await, ast.Yield, ast.YieldFrom)):
                unsupported.append(type(node).__name__)
                simple = False
    for statement in function.body:
        for node in ast.walk(statement):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
                if isinstance(node, ast.AnnAssign) and node.value is None:
                    continue  # Annotation-only declarations have no STORE effect.
                targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == receiver:
                        value = getattr(node, "value", None)
                        writes.append({"line": node.lineno, "attribute": target.attr,
                                       "value_AST": ast.unparse(value) if value is not None else None,
                                       "annotation_AST": ast.unparse(node.annotation) if isinstance(node, ast.AnnAssign) else None,
                                       "kind": "receiver_state_delete" if isinstance(node, ast.Delete) else "receiver_state_write",
                                       "statement_kind": type(node).__name__, "identity_authority": False})
    return {"writes": writes, "calls": calls, "annotation_obligations": annotation_obligations,
            "unsupported": sorted(set(unsupported)),
            "return_fact": "fallthrough_none" if simple else "UNRESOLVED",
            "simple_body": simple, "definition_time_obligations": {
                "decorators_AST": [ast.unparse(d) for d in function.decorator_list],
                "defaults_AST": [ast.unparse(d) for d in [*function.args.defaults, *function.args.kw_defaults] if d is not None],
                "annotations_preserved_not_used_for_identity": True},
            "body_AST_sha256": _digest(function)}


class _ContextFlow:
    def __init__(self, function: ast.FunctionDef | ast.AsyncFunctionDef, *, path: str,
                 symbol: str, classes: Mapping[str, ast.ClassDef],
                 reference: Callable[[str, str], str | None]) -> None:
        self.function, self.path, self.symbol = function, path, symbol
        self.classes, self.reference = classes, reference
        self.events: list[dict[str, Any]] = []
        self.remaining = 4096
        self.epoch = 0
        self.history: set[str] = set()
        self.control: list[str] = ["decorated_callable"] if function.decorator_list else []
        self.env: dict[str, dict[str, Any] | None] = {
            n.arg: None for n in [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]}
        def locals_in(node: ast.AST) -> set[str]:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                return {node.name}
            if isinstance(node, ast.Lambda):
                return set()
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                return {node.id}
            if isinstance(node, ast.Import):
                return {a.asname or a.name.split('.')[0] for a in node.names}
            if isinstance(node, ast.ImportFrom):
                return {a.asname or a.name for a in node.names}
            return {n for child in ast.iter_child_nodes(node) for n in locals_in(child)}
        self.env.update({name: None for statement in function.body for name in locals_in(statement)})
        for parameter in (function.args.vararg, function.args.kwarg):
            if parameter is not None:
                self.env[parameter.arg] = None
        self.budget_exhausted = False

    def emit(self, kind: str, node: ast.expr | ast.stmt, **facts: Any) -> None:
        self.events.append({"kind": kind, "line": node.lineno, "column": node.col_offset,
                            "source_AST_sha256": _digest(node), "identity_authority": False,
                            "permits_acceptance": False, **copy.deepcopy(facts)})

    def barrier(self, reason: str, node: ast.expr | ast.stmt) -> None:
        self.epoch += 1
        self.history.add(reason)
        for context in self.env.values():
            if context is not None:
                context["status"] = "conditional"
                context["guards"] = sorted(set([*context["guards"], reason]))
        self.emit("context_barrier", node, reason=reason)

    def class_parts(self, symbol: str) -> tuple[ast.ClassDef | None, dict[str, Any], list[str]]:
        cls = self.classes.get(symbol)
        if cls is None:
            return None, {}, ["missing_declared_source_class"]
        if sum(1 for _ in ast.walk(cls)) > 4096:
            return cls, {}, ["class_node_budget"]
        names = {n.name for n in cls.body if isinstance(n, _FUNCTIONS)}
        names.update(n.id for stmt in cls.body for n in ast.walk(stmt)
                     if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store))
        guards = []
        if cls.bases or cls.decorator_list or cls.keywords or names & _HOOKS:
            guards.append("unsupported_class_structure_or_hook")
        if any(isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)) for n in cls.body):
            guards.append("class_field_or_descriptor_obligation")
        methods = {n.name: n for n in cls.body if isinstance(n, _FUNCTIONS)}
        if len(methods) != sum(isinstance(n, _FUNCTIONS) for n in cls.body):
            guards.append("ambiguous_method_binding")
        return cls, methods, guards

    def expression(self, node: ast.expr | None) -> dict[str, Any] | None:
        self.remaining -= 1
        if self.remaining < 0:
            self.budget_exhausted = True
            self.barrier("analysis_budget", node or self.function)
            return None
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return self.env.get(node.id)
        if isinstance(node, ast.Await):
            self.expression(node.value)
            self.barrier("await_or_suspend", node)
            return None  # An awaited result has no receiver identity here.
        if isinstance(node, ast.Call):
            receiver = self.expression(node.func.value) if isinstance(node.func, ast.Attribute) else None
            start_epoch = self.epoch
            escaped_argument = False
            for value in [*node.args, *[k.value for k in node.keywords]]:
                escaped_argument = self.expression(value) is not None or escaped_argument
            if escaped_argument:
                self.barrier("argument_alias_escape", node)
            if isinstance(node.func, ast.Name) and node.func.id not in self.env:
                symbol = self.reference(self.path, node.func.id)
                if symbol in self.classes:
                    cls, methods, failures = self.class_parts(str(symbol))
                    initializer = methods.get("__init__")
                    bindings: dict[str, Any]
                    if initializer is None:
                        bindings, more = {}, (["implicit_constructor_with_arguments"] if node.args or node.keywords else [])
                        summary = {"writes": [], "calls": [], "annotation_obligations": [],
                                   "unsupported": [], "return_fact": "fallthrough_none"}
                    else:
                        bindings, more = _bind(initializer, node)
                        summary = _summary(initializer)
                        if isinstance(initializer, ast.AsyncFunctionDef):
                            more.append("async_initializer_not_supported")
                    failures.extend(more)
                    guards = [*self.control, *self.history]
                    if self.epoch != start_epoch:
                        guards.append("argument_evaluation_barrier")
                    if summary["calls"] or summary["unsupported"]:
                        guards.append("initializer_effect_or_flow_obligation")
                    context = {"source_class": symbol, "status": "unresolved" if failures else "conditional" if guards else "candidate",
                               "constructor_line": node.lineno, "constructor_column": node.col_offset,
                               "class_AST_sha256": _digest(cls) if cls is not None else None,
                               "argument_bindings": bindings, "initializer": summary,
                               "guards": sorted(set([*guards, *failures])), "runtime_identity": "UNPROVEN"}
                    self.emit("constructor_context", node, context=context)
                    if failures:
                        self.barrier("refused_constructor_binding", node)
                        return None
                    return context
            if isinstance(node.func, ast.Attribute) and receiver is not None:
                _, methods, failures = self.class_parts(str(receiver["source_class"]))
                method = methods.get(node.func.attr)
                if method is not None:
                    bindings, more = _bind(method, node)
                    summary = _summary(method)
                    reasons = sorted(set([*receiver["guards"], *self.control, *failures, *more]))
                    status = "unresolved" if failures or more else "conditional" if reasons or not summary["simple_body"] else receiver["status"]
                    self.emit("method_context", node, source_target=str(receiver["source_class"]) + "." + node.func.attr,
                              status=status, context=receiver, argument_bindings=bindings,
                              body_effects=summary, guards=reasons, runtime_identity="UNPROVEN")
                    if not summary["simple_body"] or failures or more:
                        self.barrier("method_effect_or_flow_obligation", node)
                    return None  # No returned receiver inference, including body None.
            self.emit("unresolved_call", node, callee_AST=ast.unparse(node.func), runtime_identity="UNPROVEN")
            self.barrier("unknown_call_or_escape", node)
            return None
        if isinstance(node, (ast.Lambda, ast.NamedExpr)):
            self.barrier("unsupported_expression_or_capture", node)
            return None
        if isinstance(node, ast.Attribute):
            self.expression(node.value)
            self.emit("field_read_obligation", node, receiver_AST=ast.unparse(node.value), attribute=node.attr,
                      runtime_identity="UNPROVEN")
            self.barrier("attribute_read_obligation", node)
            return None
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self.expression(child)
        return None

    def block(self, statements: list[ast.stmt]) -> None:
        for node in statements:
            if self.budget_exhausted:
                return
            if isinstance(node, ast.AnnAssign) and node.value is None:
                self.emit("annotation_declaration_obligation", node, target_AST=ast.unparse(node.target),
                          annotation_AST=ast.unparse(node.annotation), performs_store=False,
                          evaluation_policy="Preserve declaration/target scope semantics; no local rebind or attribute store.")
                if isinstance(node.target, ast.Attribute):
                    self.expression(node.target.value)
                elif isinstance(node.target, ast.Subscript):
                    self.expression(node.target.value)
                    self.expression(node.target.slice)
                continue
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                context = self.expression(node.value)
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        if self.env.get(target.id) is not None and self.env[target.id] is not context:
                            self.barrier("local_rebinding", node)
                        self.env[target.id] = context
                    else:
                        self.emit("state_write_obligation", node, target_AST=ast.unparse(target), value_AST=ast.unparse(node.value) if node.value else None)
                        self.barrier("attribute_or_destructuring_write", node)
            elif isinstance(node, ast.Expr):
                self.expression(node.value)
            elif isinstance(node, ast.Assert):
                self.expression(node.test)
                self.expression(node.msg)
            elif isinstance(node, (ast.Return, ast.Raise)):
                if isinstance(node, ast.Return):
                    context = self.expression(node.value)
                    if context is not None:
                        self.barrier("return_escape", node)
                        self.emit("escaped_return_origin", node, context=context)
                else:
                    self.expression(node.exc)
                    self.expression(node.cause)
                return
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                self.barrier("context_manager_enter", node)
                for item in node.items:
                    self.expression(item.context_expr)
                    if isinstance(item.optional_vars, ast.Name):
                        self.env[item.optional_vars.id] = None
                self.control.append(type(node).__name__)
                self.block(node.body)
                self.control.pop()
                self.barrier("context_manager_exit", node)
            elif isinstance(node, ast.If):
                self.expression(node.test)
                initial = copy.deepcopy(self.env)
                self.control.append("branch_arm")
                self.block(node.body)
                names = set(self.env)
                self.env = copy.deepcopy(initial)
                self.block(node.orelse)
                names.update(self.env)
                self.control.pop()
                self.env = {name: None for name in names}
                self.barrier("branch_join_unresolved", node)
            elif isinstance(node, ast.Pass):
                continue
            else:
                self.barrier("unsupported_statement:" + type(node).__name__, node)
                # No execution of loops/try/nested definitions or guessed joins.


def discover_constructor_contexts(tree: ast.Module, *, path: str,
                                  class_definitions: Mapping[str, ast.ClassDef],
                                  reference: Callable[[str, str], str | None]) -> dict[str, Any]:
    """Return proposed side facts only; caller's input inventory is never modified.

    `reference` must come from Root's exact declared-source import resolver.
    Supplying a mapping is not a loader/receiver/mutation or effect attestation.
    Every source candidate still requires the maintained resolver's opaque,
    initializer, cohort mutation, escape and operation-effect checks.
    """
    result = []
    population = [(node, node.name) for node in tree.body if isinstance(node, _FUNCTIONS)]
    population += [(member, node.name + "." + member.name) for node in tree.body
                   if isinstance(node, ast.ClassDef) for member in node.body if isinstance(member, _FUNCTIONS)]
    for function, name in population[:128]:
        flow = _ContextFlow(function, path=path, symbol=path + "::" + name,
                            classes=class_definitions, reference=reference)
        if sum(1 for _ in ast.walk(function)) > 4096:
            flow.budget_exhausted = True
            flow.barrier("function_node_budget", function)
        else:
            flow.block(function.body)
        result.append({"symbol": flow.symbol, "events": flow.events,
                       "budget_exhausted": flow.budget_exhausted,
                       "existing_candidate_obligations_must_be_preserved": True,
                       "identity_authority": False, "permits_acceptance": False})
    return {"source_path": path, "source_AST_sha256": _digest(tree), "functions": result,
            "population_budget_exhausted": len(population) > 128,
            "module_initializer_effects": "REQUIRED_FROM_MAINTAINED_DEFINITION_INVENTORY",
            "loader_and_cohort_mutation_guard": "UNPROVEN",
            "identity_authority": False, "permits_acceptance": False}

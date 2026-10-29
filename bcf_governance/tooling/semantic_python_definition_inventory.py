"""Partition definition-site expressions without executing source.

Potential module/class initialization is an explicit source execution context,
not a runtime observation or a purity assertion. Implicit dispatch and delayed
execution that this slice cannot prove remain visible fail-closed obligations.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import sysconfig
from pathlib import Path
from typing import Any

from .semantic_python_descriptor_identity import _bindings, _namespace_mutations
from .semantic_python_inventory_ast import _FunctionVisitor


def _span(node: ast.AST) -> tuple[int, int]:
    return (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))


class _ContextVisitor(_FunctionVisitor):
    """Shared source-context diagnostic shape for two actual execution visitors."""

    definition_time_contracts: list[dict[str, Any]]

    def facts(self) -> dict[str, Any]:
        facts = super().facts()
        facts["definition_time_obligations"] = getattr(self, "definition_time_obligations", [])
        facts["definition_time_contracts"] = getattr(self, "definition_time_contracts", [])
        return facts

    def refuse(self, node: ast.AST, kind: str) -> None:
        if not hasattr(self, "definition_time_obligations"):
            self.definition_time_obligations: list[dict[str, Any]] = []
        self.definition_time_obligations.append({"kind": kind, "symbol": self.symbol,
                                "line": _span(node)[0], "column": _span(node)[1]})


class _DefinitionVisitor(_ContextVisitor):
    """Use the same call grammar but respect delayed expression bodies."""

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        for value in [*node.args.defaults, *node.args.kw_defaults]:
            if value is not None:
                self.visit(value)
        self.refuse(node, "definition_time_deferred_lambda")

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:  # noqa: N802
        # Only the outermost iterator expression is eagerly evaluated when a
        # generator expression is created. Body/filters/inner iterators are lazy.
        if node.generators:
            self.visit(node.generators[0].iter)
        self.refuse(node, "definition_time_deferred_generator")

    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
        self.refuse(node, "definition_time_attribute_dispatch_requires_resolution")
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:  # noqa: N802
        self.refuse(node, "definition_time_subscript_dispatch_requires_resolution")
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp | ast.SetComp | ast.DictComp) -> None:  # noqa: N802
        self.refuse(node, "definition_time_iterator_dispatch_requires_resolution")
        self.generic_visit(node)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        super().visit_Call(node)
        if isinstance(node.func, ast.Attribute):
            # No receiver type/effect certainty is invented from syntax. The
            # native source resolver/effect contract must discharge this later.
            self.refuse(node, "definition_time_receiver_effect_requires_resolution")


class _InvocationVisitor(_ContextVisitor):
    """Ordinary function invocation excludes nested delayed lexical bodies."""

    def __init__(self, *, path: str, imports: dict[str, str],
                 import_bindings: dict[str, dict[str, Any]], local_types: set[str],
                 class_name: str | None,
                 function: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        super().__init__(path=path, imports=imports, import_bindings=import_bindings,
                         local_types=local_types, class_name=class_name, function=function)
        self._function_root = function

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:  # noqa: N802
        if node is self._function_root:
            for statement in node.body:
                self.visit(statement)
            return
        for value in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults]:
            if value is not None:
                self.visit(value)
        self.refuse(node, "definition_time_nested_runtime_scope_requires_resolution")
        # Nested annotations/type parameters have unspecified eager/deferred
        # timing here; refusing the scope never invents an invocation edge.

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        # Function-local annotations are never evaluated. Preserve the existing
        # assignment-origin/receiver-mutation machinery for actual assignments
        # while excluding the annotation subtree from invocation facts.
        if node.value is None:
            if not isinstance(node.target, ast.Name):
                self.visit(node.target)
            return
        invocation = copy.copy(node)
        invocation.annotation = ast.Constant(value=None)
        super().visit_AnnAssign(invocation)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        for value in [*node.decorator_list, *node.bases,
                      *(keyword.value for keyword in node.keywords)]:
            self.visit(value)
        self.refuse(node, "definition_time_nested_runtime_scope_requires_resolution")

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        for value in [*node.args.defaults, *node.args.kw_defaults]:
            if value is not None:
                self.visit(value)
        self.refuse(node, "definition_time_deferred_lambda")

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:  # noqa: N802
        if node.generators:
            self.visit(node.generators[0].iter)
        self.refuse(node, "definition_time_deferred_generator")


def _plain_empty_classes(tree: ast.Module, *,
                         namespace_mutations: list[dict[str, Any]] | None = None) -> set[int]:
    """Only direct, uniquely bound, empty builtin class statements.

    No base/metaclass, decorator, descriptor, slot or dynamic namespace proof
    is borrowed from this rule. Class body inventory is still retained.
    """
    mutations = _namespace_mutations(tree) if namespace_mutations is None else namespace_mutations
    if mutations:
        return set()
    forbidden = {"__builtins__", "builtins", "__build_class__"}
    if any(
        (isinstance(node, ast.Name) and node.id in forbidden)
        or (isinstance(node, ast.Attribute) and node.attr in forbidden | {"__dict__"})
        or (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in {"globals", "locals", "vars", "exec", "eval", "setattr", "delattr"})
        or (isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names))
        or (isinstance(node, (ast.Import, ast.ImportFrom))
            and (getattr(node, "module", None) == "builtins"
                 or any(alias.name in forbidden for alias in node.names)))
        for node in ast.walk(tree)
    ):
        return set()
    proven = set()
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        if node.bases or node.keywords or node.decorator_list or getattr(node, "type_params", []):
            continue
        if any(not (isinstance(statement, ast.Pass)
                    or (isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant)
                        and isinstance(statement.value.value, str))) for statement in node.body):
            continue
        bindings = sum(
            isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and value.name == node.name
            or isinstance(value, ast.Name) and value.id == node.name and isinstance(value.ctx, (ast.Store, ast.Del))
            or isinstance(value, (ast.Import, ast.ImportFrom))
            and any((alias.asname or alias.name.split(".", 1)[0]) == node.name for alias in value.names)
            for value in ast.walk(tree)
        )
        if bindings == 1:
            proven.add(id(node))
    return proven


def _stdlib_type_union(annotation: ast.expr, *, tree: ast.Module,
                       bindings: dict[str, dict[str, Any]],
                       source_paths: tuple[str, ...]) -> dict[str, str] | None:
    """Bound type.__or__ only; no instance method or constructor effects granted."""
    if not (isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr)):
        return None
    operands = [annotation.left, annotation.right]
    names = [node.id for node in operands if isinstance(node, ast.Name)]
    if (len(names) != 1 or not any(isinstance(node, ast.Constant) and node.value is None
                                 for node in operands)):
        return None
    if _namespace_mutations(tree):
        return None
    name = names[0]
    binding = bindings.get(name, {})
    module, member = binding.get("module"), binding.get("member")
    if (binding.get("kind") != "from" or binding.get("level", 0)
            or not isinstance(module, str) or not isinstance(member, str)
            or not all(part.isidentifier() for part in module.split("."))):
        return None
    # Local modules, aliases, namespace escape and rebinding cannot borrow the
    # installed runtime's source identity. No source import is executed here.
    suffixes = (module.replace(".", "/") + ".py", module.split(".")[0] + ".py")
    if any(path == suffix or path.endswith("/" + suffix)
           for path in source_paths for suffix in suffixes):
        return None
    for node in ast.walk(tree):
        if ((isinstance(node, ast.Name) and node.id in {name, "__builtins__"}
             and isinstance(node.ctx, (ast.Store, ast.Del)))
                or (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in {"globals", "locals", "vars", "exec", "eval", "setattr", "delattr"})
                or (isinstance(node, ast.Attribute) and node.attr == "__dict__")
                or (isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names))):
            return None
    imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
               for alias in node.names if (alias.asname or alias.name.split(".", 1)[0]) == name]
    if len(imports) != 1:
        return None
    root = Path(sysconfig.get_path("stdlib")).resolve()
    source = root.joinpath(*module.split(".")).with_suffix(".py")
    try:
        source.resolve(strict=True).relative_to(root)
        if source.is_symlink() or source.stat().st_size > 1_048_576:
            return None
        raw = source.read_bytes()
        syntax = ast.parse(raw)
    except (OSError, ValueError, SyntaxError):
        return None
    if _namespace_mutations(syntax):
        return None
    if module != "email.message" or hashlib.sha256(raw).hexdigest() != '57fc451e7bc431389706dc00c0ff2456aee2c41f4786a5bce8475b9870f70684':
        return None
    classes = [node for node in syntax.body if isinstance(node, ast.ClassDef) and node.name == member]
    if len(classes) != 1:
        return None
    declarations = sum(
        isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == member
        or isinstance(node, (ast.Import, ast.ImportFrom))
        and any((alias.asname or alias.name.split(".", 1)[0]) == member for alias in node.names)
        for node in ast.walk(syntax)
    )
    if declarations != 1:
        return None
    cls = classes[0]
    if cls.bases or cls.keywords or cls.decorator_list or getattr(cls, "type_params", []):
        return None
    for node in ast.walk(syntax):
        if ((isinstance(node, ast.Name) and node.id in {member, "__builtins__"}
             and isinstance(node.ctx, (ast.Store, ast.Del)))
                or (isinstance(node, ast.Attribute) and node.attr in {"__class__", "__bases__", "__dict__"}
                    or isinstance(node, ast.Attribute) and node.attr == member
                    and isinstance(node.ctx, (ast.Store, ast.Del)))
                or (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in {"globals", "locals", "vars", "exec", "eval", "setattr", "delattr"})):
            return None
    return {"kind": "exact_stdlib_type_none_union", "module": module, "class": member,
            "source_sha256": hashlib.sha256(raw).hexdigest(), "method": "type.__or__"}


def _literal_record_decorators(tree: ast.Module, *, bindings: dict[str, dict[str, Any]],
                               source_paths: tuple[str, ...],
                               namespace_mutations: list[dict[str, Any]] | None = None) -> dict[int, dict[str, str]]:
    """Bound only stdlib dataclass on a base-free literal field-only record."""
    mutations = _namespace_mutations(tree) if namespace_mutations is None else namespace_mutations
    if mutations or any(
        path == suffix or path.endswith("/" + suffix)
        for path in source_paths for suffix in ("dataclasses.py", "dataclasses/__init__.py")
    ):
        return {}
    standard = Path(sysconfig.get_path("stdlib")) / "dataclasses.py"
    if standard.is_symlink() or not standard.is_file() or standard.stat().st_size > 1_048_576:
        return {}
    raw = standard.read_bytes()
    if hashlib.sha256(raw).hexdigest() != 'd242aea5fcf6408b1c1f622442f88f68b9526ce1f8bd2890d74a144677c427d9':
        return {}
    names = _bindings(list(ast.walk(tree)))
    contracts = {}
    for cls in tree.body:
        if (not isinstance(cls, ast.ClassDef) or cls.bases or cls.keywords
                or getattr(cls, "type_params", []) or len(cls.decorator_list) != 1):
            continue
        decorator = cls.decorator_list[0]
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if not isinstance(target, ast.Name):
            continue
        binding = bindings.get(target.id, {})
        if (binding.get("kind") != "from" or binding.get("module") != "dataclasses"
                or binding.get("member") != "dataclass" or binding.get("level", 0)):
            continue
        if isinstance(decorator, ast.Call) and (
            decorator.args or len(decorator.keywords) != 1
            or decorator.keywords[0].arg != "frozen"
            or not isinstance(decorator.keywords[0].value, ast.Constant)
            or decorator.keywords[0].value.value is not True
        ):
            continue
        if names[cls.name] != 1 or names[target.id] != 1:
            continue
        fields = []
        supported = True
        for statement in cls.body:
            if isinstance(statement, ast.Pass) or (
                isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            ):
                continue
            if (not isinstance(statement, ast.AnnAssign) or not isinstance(statement.target, ast.Name)
                    or statement.target.id.startswith("__")
                    or statement.target.id in {"str", "bytes", "int", "float", "bool"}
                    or not isinstance(statement.annotation, (ast.Name, ast.Constant))
                    or isinstance(statement.annotation, ast.Name) and (
                        statement.annotation.id not in {"str", "bytes", "int", "float", "bool"}
                        or names[statement.annotation.id] != 0
                    )
                    or isinstance(statement.annotation, ast.Constant)
                    and type(statement.annotation.value) not in (str, type(None))
                    or statement.value is not None and (
                        not isinstance(statement.value, ast.Constant)
                        or type(statement.value.value) not in (str, bytes, int, float, bool, type(None))
                    )):
                supported = False
                break
            fields.append(statement.target.id)
        if not supported or len(set(fields)) != len(fields):
            continue
        contracts[id(cls)] = {"kind": "exact_stdlib_literal_record_definition",
                              "module": "dataclasses", "callable": "dataclass",
                              "source_sha256": hashlib.sha256(raw).hexdigest()}
    return contracts


class _DefinitionCollector(ast.NodeVisitor):
    def __init__(self, *, path: str, imports: dict[str, str],
                 bindings: dict[str, dict[str, Any]], local_types: set[str],
                 future_annotations: bool = False, stable_module_name: bool = False,
                 plain_empty_classes: set[int] | None = None,
                 tree: ast.Module, source_paths: tuple[str, ...],
                 literal_records: dict[int, dict[str, str]]) -> None:
        self.literal_records = literal_records
        self.tree, self.source_paths = tree, source_paths
        self.plain_empty_classes = plain_empty_classes or set()
        self.path, self.imports, self.bindings, self.local_types = path, imports, bindings, local_types
        self.future_annotations = future_annotations
        self.stable_module_name = stable_module_name
        self.owner = f"{path}::<module>"
        self.phase = "module_body"
        self.class_names: list[str] = []
        self.regions: dict[str, _DefinitionVisitor] = {}
        self.definition_spans: set[tuple[int, int]] = set()

    def region(self) -> _DefinitionVisitor:
        if self.owner not in self.regions:
            function = ast.FunctionDef(name="<definition-context>",
                                       args=ast.arguments(posonlyargs=[], args=[], vararg=None,
                                                          kwonlyargs=[], kw_defaults=[], kwarg=None,
                                                          defaults=[]),
                                       body=[], decorator_list=[], returns=None, type_comment=None,
                                       type_params=[])
            visitor = _DefinitionVisitor(path=self.path, imports=self.imports,
                                         import_bindings=self.bindings,
                                         local_types=self.local_types, class_name=None,
                                         function=function)
            visitor.symbol = self.owner
            self.regions[self.owner] = visitor
        return self.regions[self.owner]

    def context(self) -> dict[str, Any]:
        return {"owning_module": self.path, "owner_symbol": self.owner,
                "phase": self.phase, "runtime_observed": False,
                "execution": "source_potential"}

    def refuse(self, node: ast.AST, kind: str) -> None:
        visitor = self.region()
        visitor.refuse(node, kind)
        visitor.definition_time_obligations[-1]["execution_context"] = self.context()

    def expression(self, node: ast.expr, phase: str) -> None:
        previous = self.phase
        self.phase = phase
        # Retain the complete lexical span set so old function invocation facts
        # cannot accidentally keep default/decorator/annotation call duplicates,
        # even where a delayed body is refused rather than modeled as eager.
        self.definition_spans.update(_span(value) for value in ast.walk(node)
                                     if isinstance(value, ast.Call))
        visitor = self.region()
        sizes = {name: len(getattr(visitor, name, []))
                 for name in ("calls", "constructors", "normalizations", "unresolved", "definition_time_obligations")}
        visitor.visit(node)
        for name, start in sizes.items():
            for row in getattr(visitor, name, [])[start:]:
                row["execution_context"] = self.context()
        self.phase = previous

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        self.expression(node, self.phase)

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        self.expression(node, self.phase)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:  # noqa: N802
        self.expression(node, self.phase)

    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
        self.expression(node, self.phase)

    def visit_Subscript(self, node: ast.Subscript) -> None:  # noqa: N802
        self.expression(node, self.phase)

    def visit_ListComp(self, node: ast.ListComp | ast.SetComp | ast.DictComp) -> None:  # noqa: N802
        self.expression(node, self.phase)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:  # noqa: N802
        self.refuse(node, "definition_time_iterator_dispatch_requires_resolution")
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With | ast.AsyncWith) -> None:  # noqa: N802
        self.refuse(node, "definition_time_context_manager_dispatch_requires_resolution")
        self.generic_visit(node)

    visit_AsyncWith = visit_With

    def type_parameters(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        for parameter in getattr(node, "type_params", []):
            self.refuse(parameter, "definition_time_type_parameter_contract_required")
            for value in ast.iter_child_nodes(parameter):
                if isinstance(value, ast.expr):
                    self.expression(value, "type_parameter_deferred_contract_required")

    def decorators(self, decorators: list[ast.expr],
                   contract: dict[str, str] | None = None) -> None:
        for decorator in decorators:
            self.expression(decorator, "decorator_expression")
            # @name applies a callable even without an ast.Call; @factory()
            # additionally applies its return value. Neither is silently pure.
            if contract is None:
                self.refuse(decorator, "definition_time_decorator_application")
            else:
                visitor = self.region()
                if not hasattr(visitor, "definition_time_contracts"):
                    visitor.definition_time_contracts = []
                visitor.definition_time_contracts.append({**contract, "line": decorator.lineno,
                                                           "execution_context": self.context()})

    def annotation(self, annotation: ast.expr) -> None:
        # The future directive compiles annotations to strings. Retain their
        # potential evaluation separately; importing this module does not run it.
        previous_owner = self.owner
        if self.future_annotations:
            self.owner = f"{self.path}::<deferred-annotations>"
        self.expression(annotation, "annotation_evaluation_contract_required")
        contract = None if self.future_annotations else _stdlib_type_union(
            annotation, tree=self.tree, bindings=self.bindings, source_paths=self.source_paths)
        if contract is None:
            self.refuse(annotation, "definition_time_annotation_contract_required")
        else:
            visitor = self.region()
            if not hasattr(visitor, "definition_time_contracts"):
                visitor.definition_time_contracts = []
            visitor.definition_time_contracts.append({**contract, "line": annotation.lineno,
                                                       "execution_context": self.context()})
        self.owner = previous_owner

    def visit_If(self, node: ast.If) -> None:  # noqa: N802
        test = node.test
        script_guard = (
            self.stable_module_name and self.owner == f"{self.path}::<module>"
            and isinstance(test, ast.Compare) and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq) and len(test.comparators) == 1
            and isinstance(test.left, ast.Name) and test.left.id == "__name__"
            and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value == "__main__"
        )
        if not script_guard:
            self.generic_visit(node)
            return
        # Mapping/export populations import modules. A script body is a distinct
        # execution root, retained for discovery rather than charged as an import.
        previous_owner, previous_phase = self.owner, self.phase
        self.owner, self.phase = f"{self.path}::<script-body>", "script_body"
        for statement in node.body:
            self.visit(statement)
        self.owner, self.phase = previous_owner, previous_phase
        for statement in node.orelse:
            self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:  # noqa: N802
        self.type_parameters(node)
        self.decorators(node.decorator_list)
        for value in [*node.args.defaults, *node.args.kw_defaults]:
            if value is not None:
                self.expression(value, "function_default")
        args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        annotations = [argument.annotation for argument in args]
        annotations.extend([node.returns,
                            node.args.vararg.annotation if node.args.vararg else None,
                            node.args.kwarg.annotation if node.args.kwarg else None])
        for annotation in annotations:
            if annotation is not None and not isinstance(annotation, (ast.Name, ast.Constant)):
                self.annotation(annotation)
    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self.type_parameters(node)
        self.decorators(node.decorator_list, self.literal_records.get(id(node)))
        for base in node.bases:
            self.expression(base, "class_base_expression")
        for keyword in node.keywords:
            self.expression(keyword.value, "class_keyword_expression")
        if id(node) not in self.plain_empty_classes and id(node) not in self.literal_records:
            self.refuse(node, "definition_time_implicit_class_dispatch_requires_resolution")
        previous_owner, previous_phase = self.owner, self.phase
        self.class_names.append(node.name)
        class_owner = f"{self.path}::<class-body:{'.'.join(self.class_names)}>"
        self.region().calls.append({
            "caller": previous_owner, "called_symbol": class_owner,
            "call_name": "<class-body>", "line": node.lineno,
            "column": node.col_offset, "argument_origins": [],
            "implicit": True, "dispatch_kind": "language_class_statement",
            "execution_context": {**self.context(), "phase": "class_body_dispatch"},
        })
        self.owner = class_owner
        self.phase = "class_body"
        self.region()
        for statement in node.body:
            self.visit(statement)
        self.class_names.pop()
        self.owner, self.phase = previous_owner, previous_phase

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        if node.value is not None:
            self.visit(node.value)
        if not isinstance(node.target, ast.Name):
            self.expression(node.target, "annotated_target_evaluation")
            self.refuse(node.target, "definition_time_annotated_target_contract_required")
            self.region().definition_time_obligations[-1]["assigned_value_present"] = node.value is not None
        if not isinstance(node.annotation, (ast.Name, ast.Constant)):
            self.annotation(node.annotation)


def definition_time_facts(
    tree: ast.Module, *, path: str, imports: dict[str, str],
    bindings: dict[str, dict[str, Any]], local_types: set[str],
    source_paths: tuple[str, ...] = (),
    namespace_mutations: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], set[tuple[int, int]]]:
    """Return explicit potential definition contexts plus exact relocated call spans."""
    future_annotations = any(
        isinstance(node, ast.ImportFrom) and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in tree.body
    )
    stable_module_name = not any(
        (isinstance(node, ast.Name) and node.id == "__name__"
         and isinstance(node.ctx, (ast.Store, ast.Del)))
        or (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in {"globals", "locals", "exec", "eval", "setattr", "delattr"})
        for node in ast.walk(tree)
    )
    mutations = _namespace_mutations(tree) if namespace_mutations is None else namespace_mutations
    collector = _DefinitionCollector(path=path, imports=imports, bindings=bindings,
                                     local_types=local_types,
                                     future_annotations=future_annotations,
                                     stable_module_name=stable_module_name,
                                     plain_empty_classes=_plain_empty_classes(tree, namespace_mutations=mutations),
                                     tree=tree, source_paths=source_paths,
                                     literal_records=_literal_record_decorators(
                                         tree, bindings=bindings, source_paths=source_paths, namespace_mutations=mutations))
    collector.visit(tree)
    facts = []
    for symbol, visitor in collector.regions.items():
        row = visitor.facts()
        row["execution_context"] = {"owning_module": path, "owner_symbol": symbol,
                                    "kind": "definition_site", "runtime_observed": False,
                                    "execution": "source_potential"}
        facts.append(row)
    return facts, collector.definition_spans


def retain_invocation_facts(
    facts: dict[str, Any], definition_spans: set[tuple[int, int]],
) -> dict[str, Any]:
    """Remove exact header-expression sites from invocation-only collections."""
    for collection in ("calls", "constructors", "normalizations", "unresolved", "definition_time_obligations"):
        facts[collection] = [row for row in facts[collection]
                             if (row.get("line"), row.get("column")) not in definition_spans]
    return facts

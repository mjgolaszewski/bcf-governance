"""Precise dependency witnesses for retained namespace/binding refusals.

An assignment input shape is not a field lifetime or descriptor proof. An
attribute projection is not its imported module object or a consumer contract.
"""
from __future__ import annotations

import ast
import hashlib
from typing import Any

_MUTATORS = {'exec', 'eval', 'globals', 'locals', 'vars', 'setattr', 'delattr'}
_HOOKS = {'__getattribute__', '__getattr__', '__setattr__', '__delattr__', '__new__'}


def _witness(node: ast.AST) -> dict[str, Any]:
    return {'line': getattr(node, 'lineno', 0), 'column': getattr(node, 'col_offset', 0),
            'expression_AST': ast.unparse(node),
            'AST_sha256': hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()}


def _owned(node: ast.AST) -> list[ast.AST]:
    result = [node]
    for child in ast.iter_child_nodes(node):
        if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            result.extend(_owned(child))
    return result


def _argument_roots(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    children: list[ast.AST]
    if isinstance(node, ast.Call):
        children = [*node.args, *(k.value for k in node.keywords)]
    else:
        children = list(ast.iter_child_nodes(node))
    return {name for child in children for name in _argument_roots(child)}


def _root(node: ast.AST) -> str | None:
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _input_kind(node: ast.expr | None) -> str:
    if isinstance(node, (ast.Set, ast.SetComp)):
        return 'builtin_set_expression'
    if isinstance(node, (ast.Dict, ast.DictComp)):
        return 'builtin_dict_expression'
    if isinstance(node, (ast.List, ast.ListComp)):
        return 'builtin_list_expression'
    if isinstance(node, ast.Name) and node.id in _MUTATORS:
        return 'possible_namespace_mutator_reference'
    return 'UNPROVEN'


def discover_binding_dependencies(tree: ast.Module, *, path: str,
                                  return_facts: list[dict[str, Any]]) -> dict[str, Any]:
    if sum(1 for _ in ast.walk(tree)) > 16384:
        return {'source_path': path, 'field_alias_reads': [], 'module_argument_dependencies': [],
                'budget_exhausted': True, 'identity_authority': False, 'permits_acceptance': False}
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {
        path + '::' + n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    imports = {alias.asname or alias.name.split('.')[0]: alias.name
               for n in tree.body if isinstance(n, ast.Import) for alias in n.names}
    field_reads = []
    for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
        methods = [n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        stores: dict[str, list[dict[str, Any]]] = {}
        for method in methods:
            functions[path + '::' + cls.name + '.' + method.name] = method
            args = [*method.args.posonlyargs, *method.args.args]
            if not args:
                continue
            receiver = args[0].arg
            for statement in method.body:
                for n in _owned(statement):
                    if not isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                        continue
                    targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                    for target in targets:
                        if (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                                and target.value.id == receiver):
                            value = n.value
                            stores.setdefault(target.attr, []).append({
                                'owner': path + '::' + cls.name + '.' + method.name,
                                'store': _witness(n), 'assigned_input_kind': _input_kind(value),
                                'input_value': _witness(value) if value is not None else None,
                                'receiver_store_semantics': 'UNPROVEN',
                                'initializer': method.name == '__init__',
                            })
        for method in methods:
            args = [*method.args.posonlyargs, *method.args.args]
            if not args:
                continue
            nodes = [n for statement in method.body for n in _owned(statement)]
            parents = {child: n for n in nodes for child in ast.iter_child_nodes(n)}
            for n in nodes:
                if (not isinstance(n, ast.Attribute) or not isinstance(n.ctx, ast.Load)
                        or n.attr not in _MUTATORS or not isinstance(n.value, ast.Name)
                        or n.value.id != args[0].arg):
                    continue
                parent = parents.get(n)
                if isinstance(parent, ast.Call) and parent.func is n:
                    continue
                field_reads.append({
                    'owner': path + '::' + cls.name + '.' + method.name,
                    'read': _witness(n), 'field': n.attr,
                    'candidate_source_stores': stores.get(n.attr, []),
                    'class_structural_obligations': {'bases': [ast.unparse(v) for v in cls.bases],
                        'decorators': [ast.unparse(v) for v in cls.decorator_list],
                        'metaclass_keywords': [ast.unparse(v.value) for v in cls.keywords],
                        'hooks': sorted({m.name for m in methods} & _HOOKS)},
                    'read_value_identity': 'UNPROVEN', 'receiver_lifetime': 'UNPROVEN',
                    'callback_and_descriptor_effect_closure': 'UNPROVEN',
                    'permits_acceptance': False,
                })
    arguments = []
    for facts in return_facts:
        function = functions.get(str(facts['symbol']))
        if function is None:
            continue
        calls = [n for statement in function.body for n in _owned(statement) if isinstance(n, ast.Call)]
        for escape in facts.get('source_escapes', []):
            name = str(escape['name'])
            if escape['role'] != 'argument' or name not in imports:
                continue
            alternatives = []
            for call in calls:
                if call.lineno != escape['line']:
                    continue
                for index, value in enumerate([*call.args, *(k.value for k in call.keywords)]):
                    if name not in _argument_roots(value):
                        continue
                    projections = [n for n in ast.walk(value) if isinstance(n, ast.Attribute) and _root(n) == name]
                    alternatives.append({'call': _witness(call), 'argument_index': index,
                        'argument': _witness(value),
                        'argument_is_imported_root': isinstance(value, ast.Name) and value.id == name,
                        'attribute_projections': [_witness(n) for n in projections],
                        'consumer_AST': ast.unparse(call.func), 'consumer_contract': 'UNPROVEN',
                        'projected_value_identity': 'UNPROVEN'})
            arguments.append({'owner': facts['symbol'], 'original_escape': dict(escape),
                'declared_import_module': imports[name], 'source_root_name': name,
                'alternatives': alternatives, 'ambiguous_span': len(alternatives) != 1,
                'loader_binding': 'UNPROVEN', 'permits_acceptance': False})
    return {'source_path': path, 'field_alias_reads': field_reads[:256],
            'module_argument_dependencies': arguments[:512],
            'budget_exhausted': len(field_reads) > 256 or len(arguments) > 512,
            'identity_authority': False,
            'permits_acceptance': False}

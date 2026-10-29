"""Source value/nonretention contracts; never general call purity contracts."""
from __future__ import annotations

import ast
from collections import Counter
import hashlib
from pathlib import Path
from typing import Any

_AST_TYPES = {
    'AST', 'Name', 'Constant', 'IfExp', 'Call', 'Starred', 'Attribute', 'Store', 'Load', 'Del',
    'FunctionDef', 'AsyncFunctionDef', 'ClassDef', 'Lambda', 'Global', 'Nonlocal', 'Yield',
    'YieldFrom', 'Await', 'NamedExpr', 'Assign', 'AnnAssign', 'AugAssign', 'Delete',
    'Return', 'If', 'Assert', 'Pass',
}
_SENSITIVE = {'__dict__', '__builtins__', '__getattribute__', '__getattr__', '__setattr__',
              '__delattr__', '__class__', '__bases__', '__mro__', '__instancecheck__',
              '__subclasscheck__', '__code__', '__defaults__', '__kwdefaults__', '__globals__',
              '__closure__', '__build_class__', '__mro_entries__', 'isinstance', 'any', 'len', 'ast'}


class NamespaceValueSourceError(ValueError):
    """A value contract cannot consume a changed discovery snapshot."""


def _bindings(tree: ast.AST) -> Counter[str]:
    result: Counter[str] = Counter()
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            result[n.id] += 1
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            result[n.name] += 1
        elif isinstance(n, ast.arg):
            result[n.arg] += 1
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for alias in n.names:
                result[alias.asname or alias.name.split('.')[0]] += 1
    return result


def _value_names(node: ast.AST) -> list[ast.Name]:
    if isinstance(node, ast.Name):
        return [node]
    children: list[ast.AST]
    if isinstance(node, ast.Call):
        children = [*node.args, *(k.value for k in node.keywords)]
    else:
        children = list(ast.iter_child_nodes(node))
    return [name for child in children for name in _value_names(child)]


def _same_value_field_contracts(trees: dict[str, ast.Module], builtin_names: Counter[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    all_nodes = [n for tree in trees.values() for n in ast.walk(tree)]
    for path, tree in trees.items():
        parents = {child: n for n in ast.walk(tree) for child in ast.iter_child_nodes(n)}
        for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
            if (cls.bases or cls.keywords or cls.decorator_list or getattr(cls, 'type_params', [])
                    or _bindings(tree)[cls.name] != 1
                    or any(not isinstance(n, ast.FunctionDef) for n in cls.body)):
                continue
            methods = {n.name: n for n in cls.body if isinstance(n, ast.FunctionDef)}
            if (len(methods) != len(cls.body) or '__init__' not in methods
                    or any(n.startswith('__') and n != '__init__' for n in methods)
                    or any(m.decorator_list for m in methods.values())):
                continue
            safe = True
            for method in methods.values():
                args = [*method.args.posonlyargs, *method.args.args]
                if not args:
                    safe = False
                    break
                receiver = args[0].arg
                for n in ast.walk(method):
                    if n is not method and isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                        safe = False
                    if isinstance(n, ast.Name) and n.id == receiver:
                        if isinstance(n.ctx, (ast.Store, ast.Del)):
                            safe = False
                        if isinstance(n.ctx, ast.Load):
                            parent = parents.get(n)
                            if not isinstance(parent, ast.Attribute) or parent.value is not n:
                                safe = False
                            elif parent.attr in methods:
                                invocation = parents.get(parent)
                                if not isinstance(invocation, ast.Call) or invocation.func is not parent:
                                    safe = False
                            elif parent.attr.startswith('__'):
                                safe = False
                    if isinstance(n, (ast.GeneratorExp, ast.Lambda)) and any(
                            isinstance(v, ast.Name) and v.id == receiver for v in ast.walk(n)):
                        safe = False
            # No class export, unbound method acquisition, subclass use or
            # escaped local instance/bound method may justify this contract.
            for n in all_nodes:
                if isinstance(n, ast.ImportFrom) and any(a.name == cls.name for a in n.names):
                    safe = False
                if isinstance(n, ast.Attribute) and n.attr == cls.name:
                    safe = False
            for n in ast.walk(tree):
                if not isinstance(n, ast.Name) or n.id != cls.name or not isinstance(n.ctx, ast.Load):
                    continue
                call = parents.get(n)
                assignment = parents.get(call) if call is not None else None
                if (isinstance(call, ast.Call) and call.func is n
                        and isinstance(assignment, ast.Attribute) and assignment.value is call
                        and assignment.attr in methods):
                    invocation = parents.get(assignment)
                    if isinstance(invocation, ast.Call) and invocation.func is assignment:
                        continue
                if (not isinstance(call, ast.Call) or call.func is not n
                        or not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1
                        or not isinstance(assignment.targets[0], ast.Name)):
                    safe = False
                    continue
                local = assignment.targets[0].id
                owner: ast.AST = assignment
                while owner in parents and not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    owner = parents[owner]
                if not isinstance(owner, ast.FunctionDef):
                    safe = False
                    continue
                for use in ast.walk(owner):
                    if isinstance(use, ast.Name) and use.id == local and isinstance(use.ctx, ast.Load):
                        attribute = parents.get(use)
                        invocation = parents.get(attribute) if attribute is not None else None
                        if (not isinstance(attribute, ast.Attribute) or attribute.value is not use
                                or attribute.attr not in methods or not isinstance(invocation, ast.Call)
                                or invocation.func is not attribute):
                            safe = False
            if not safe:
                continue
            initializer = methods['__init__']
            init_args = [*initializer.args.posonlyargs, *initializer.args.args]
            receiver = init_args[0].arg
            for statement in initializer.body:
                if (not isinstance(statement, ast.Assign) or len(statement.targets) != 1
                        or not isinstance(statement.targets[0], ast.Attribute)
                        or not isinstance(statement.targets[0].value, ast.Name)
                        or statement.targets[0].value.id != receiver
                        or not isinstance(statement.value, (ast.Set, ast.SetComp))):
                    continue
                field = statement.targets[0].attr
                if field in methods or sum(isinstance(n, ast.Attribute) and n.attr == field
                                          and isinstance(n.ctx, (ast.Store, ast.Del)) for n in all_nodes) != 1:
                    continue
                for method in methods.values():
                    args = [*method.args.posonlyargs, *method.args.args]
                    for read in ast.walk(method):
                        if (not isinstance(read, ast.Attribute) or read.attr != field
                                or not isinstance(read.ctx, ast.Load) or not isinstance(read.value, ast.Name)
                                or read.value.id != args[0].arg):
                            continue
                        parent = parents.get(read)
                        consumer = None
                        if isinstance(parent, ast.comprehension) and parent.iter is read:
                            consumer = 'builtin_set_iteration'
                        elif isinstance(parent, ast.Compare):
                            for index, operand in enumerate(parent.comparators):
                                if operand is read and isinstance(parent.ops[index], (ast.In, ast.NotIn)):
                                    consumer = 'builtin_set_membership'
                        elif (isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name)
                              and parent.func.id == 'len' and parent.args == [read] and not parent.keywords
                              and not builtin_names['len']):
                            consumer = 'builtin_set_len'
                        if consumer:
                            result.append({'path': path, 'line': read.lineno, 'kind': 'mutator_value_alias',
                                'class_symbol': path + '::' + cls.name, 'field': field,
                                'initializer_store_line': statement.lineno, 'consumer': consumer,
                                'contract': 'source_ordinary_set_field_nonmutator',
                                'other_body_effects': 'PRESERVED', 'native_authority': False})
    return result


def _projection_contracts(trees: dict[str, ast.Module], inventory: dict[str, Any],
                          module_index: dict[str, str], builtin_names: Counter[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if 'ast' in module_index or builtin_names['isinstance'] or builtin_names['any']:
        return result
    for path, tree in trees.items():
        names = _bindings(tree)
        imports = {a.asname or a.name: a.name for n in tree.body if isinstance(n, ast.Import)
                   for a in n.names if a.name == 'ast' and names[a.asname or a.name] == 1}
        parents = {child: n for n in ast.walk(tree) for child in ast.iter_child_nodes(n)}
        constants = {n.targets[0].id: n.value for n in tree.body
                     if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                     and isinstance(n.value, ast.Tuple) and names[n.targets[0].id] == 1}

        def types(node: ast.AST, root: str, seen: frozenset[str] = frozenset()) -> bool:
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                return node.value.id == root and node.attr in _AST_TYPES
            if isinstance(node, ast.Tuple):
                return bool(node.elts) and all(types(n, root, seen) for n in node.elts)
            if isinstance(node, ast.Starred) and isinstance(node.value, ast.Name):
                name = node.value.id
                return name in constants and name not in seen and types(constants[name], root, seen | {name})
            return False

        functions = {path + '::' + n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        functions.update({path + '::' + c.name + '.' + n.name: n for c in tree.body if isinstance(c, ast.ClassDef)
                          for n in c.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))})
        for facts in inventory.get('return_facts', []):
            function = functions.get(str(facts['symbol']))
            if function is None:
                continue
            for escape in facts.get('source_escapes', []):
                root = str(escape['name'])
                if escape['role'] != 'argument' or root not in imports:
                    continue
                candidates = [argument for call in ast.walk(function) if isinstance(call, ast.Call)
                              and call.lineno == escape['line']
                              for argument in [*call.args, *(k.value for k in call.keywords)]
                              if any(n.id == root for n in _value_names(argument))]
                valid = bool(candidates)
                witnesses = []
                for argument in candidates:
                    for n in [v for v in _value_names(argument) if v.id == root]:
                        attribute = parents.get(n)
                        if (not isinstance(attribute, ast.Attribute) or attribute.value is not n
                                or attribute.attr not in _AST_TYPES):
                            valid = False
                            continue
                        cursor: ast.AST = attribute
                        while isinstance(parents.get(cursor), ast.Tuple):
                            cursor = parents[cursor]
                        consumer = parents.get(cursor)
                        if (not isinstance(consumer, ast.Call) or not isinstance(consumer.func, ast.Name)
                                or consumer.func.id != 'isinstance' or len(consumer.args) != 2
                                or consumer.keywords or consumer.args[1] is not cursor
                                or not types(cursor, root)):
                            valid = False
                        ancestor: ast.AST = n
                        while ancestor in parents and ancestor is not function:
                            if isinstance(ancestor, ast.Lambda):
                                valid = False
                            if isinstance(ancestor, ast.GeneratorExp):
                                outer = parents.get(ancestor)
                                if (not isinstance(outer, ast.Call) or not isinstance(outer.func, ast.Name)
                                        or outer.func.id != 'any' or outer.args != [ancestor] or outer.keywords):
                                    valid = False
                            ancestor = parents[ancestor]
                        witnesses.append({'line': attribute.lineno, 'column': attribute.col_offset,
                                          'projection': ast.unparse(attribute)})
                if valid:
                    result.append({'symbol': facts['symbol'], 'line': escape['line'], 'name': root,
                        'role': 'argument', 'contract': 'qualified_ast_types_builtin_isinstance_nonretention',
                        'projections': witnesses, 'input_and_body_effects': 'PRESERVED_UNRESOLVED',
                        'native_authority': False})
    return result


def qualify_namespace_value_contracts(repo_root: Path, inventory: dict[str, Any], *,
                                      module_index: dict[str, str]) -> None:
    trees = {}
    node_count = 0
    for row in inventory.get('files', []):
        p = repo_root / str(row['path'])
        if p.is_symlink() or not p.resolve().is_relative_to(repo_root.resolve()):
            raise NamespaceValueSourceError('unsafe namespace contract source: ' + str(row['path']))
        raw = p.read_bytes()
        if hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise NamespaceValueSourceError('namespace contract source changed: ' + str(row['path']))
        tree = ast.parse(raw.decode('utf-8'))
        node_count += sum(1 for _ in ast.walk(tree))
        if node_count > 32768:
            inventory['namespace_value_contracts'] = {'aliases': [], 'escapes': [], 'closed': False,
                                                    'budget_exhausted': True}
            return
        trees[str(row['path'])] = tree
    if sum(isinstance(n, ast.ClassDef) for t in trees.values() for n in ast.walk(t)) > 64:
        inventory['namespace_value_contracts'] = {'aliases': [], 'escapes': [], 'closed': False,
                                                'budget_exhausted': True}
        return
    names: Counter[str] = Counter()
    for tree in trees.values():
        names.update(_bindings(tree))
    writes = {n.attr for tree in trees.values() for n in ast.walk(tree)
              if isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del))}
    loader_or_namespace_view = any(
        (isinstance(n, ast.Attribute) and n.attr in {'modules', '__dict__', 'import_module', 'reload'})
        or (isinstance(n, ast.Name) and n.id in {'__import__', '__builtins__'})
        for tree in trees.values() for n in ast.walk(tree))
    wildcard_import = any(isinstance(n, ast.ImportFrom) and any(a.name == '*' for a in n.names)
                          for tree in trees.values() for n in ast.walk(tree))
    if writes & (_SENSITIVE | _AST_TYPES) or loader_or_namespace_view or wildcard_import:
        inventory['namespace_value_contracts'] = {'aliases': [], 'escapes': [], 'closed': False}
        return
    aliases = _same_value_field_contracts(trees, names)
    escapes = _projection_contracts(trees, inventory, module_index, names)
    escape_keys = {(r['symbol'], r['line'], r['name'], r['role']) for r in escapes}
    raw_mutations = [(str(s['path']), m) for s in inventory.get('descriptor_syntax', []) for m in s['namespace_mutations']]
    raw_counts = Counter((p, m['line'], m['kind']) for p, m in raw_mutations)
    proof_counts = Counter((r['path'], r['line'], r['kind']) for r in aliases)
    aliases = [r for r in aliases if raw_counts[(r['path'], r['line'], r['kind'])] == 1
               and proof_counts[(r['path'], r['line'], r['kind'])] == 1]
    alias_keys = {(r['path'], r['line'], r['kind']) for r in aliases}
    bindings = {str(s['path']): s['bindings'] for s in inventory.get('descriptor_syntax', [])}
    imports = {str(s['path']): {r['local'] for r in s['bindings'] if r['kind'] == 'import'}
               for s in inventory.get('imports', [])}
    open_escapes = []
    for facts in inventory.get('return_facts', []):
        path = str(facts['symbol']).split('::', 1)[0]
        for escape in facts.get('source_escapes', []):
            if (escape['name'] in bindings.get(path, {}) and
                    (escape['role'] == 'argument' or escape['name'] not in imports.get(path, set()))):
                if (facts['symbol'], escape['line'], escape['name'], escape['role']) not in escape_keys:
                    open_escapes.append(escape)
    closed = not open_escapes and all((path, m['line'], m['kind']) in alias_keys for path, m in raw_mutations)
    inventory['namespace_value_contracts'] = {'aliases': aliases if closed else [],
                                            'escapes': escapes if closed else [], 'closed': closed}


def alias_discharged(inventory: dict[str, Any], path: str, mutation: dict[str, Any]) -> bool:
    return any((row['path'], row['line'], row['kind']) == (path, mutation['line'], mutation['kind'])
               for row in inventory.get('namespace_value_contracts', {}).get('aliases', []))


def escape_discharged(inventory: dict[str, Any], symbol: str, escape: dict[str, Any]) -> bool:
    return any((row['symbol'], row['line'], row['name'], row['role']) ==
               (symbol, escape['line'], escape['name'], escape['role'])
               for row in inventory.get('namespace_value_contracts', {}).get('escapes', []))

"""Source constructor callback closure, separate from returned class identity.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

import ast
import builtins
import sys
from types import BuiltinFunctionType, WrapperDescriptorType
from typing import Any

_FORBIDDEN = {"__new__", "__getattr__", "__getattribute__", "__setattr__",
              "__delattr__", "__init_subclass__", "__mro_entries__", "__class_getitem__"}
_SIMPLE_EXCEPTIONS = {BaseException, Exception, ValueError, RuntimeError}


def builtin_constructor_bases(tree: ast.Module) -> dict[str, list[str]]:
    """Bind only unshadowed native exception slots, never arbitrary libraries."""
    nodes = list(ast.walk(tree))
    # Objects/exceptions.c: SimpleExtendsException uses BaseException_new/init.
    # Native descriptors are separately wrapped per public exception type; their
    # Python object identities are not shared. Restrict this primitive contract
    # to the reviewed CPython families and versions, not arbitrary exception types.
    # https://github.com/python/cpython/blob/3.12/Objects/exceptions.c
    if sys.implementation.name != 'cpython' or not (3, 11) <= sys.version_info[:2] <= (3, 14):
        return {}
    rebound = {node.id for node in nodes if isinstance(node, ast.Name)
               and isinstance(node.ctx, (ast.Store, ast.Del))}
    rebound.update(node.arg for node in nodes if isinstance(node, ast.arg))
    rebound.update(node.name for node in nodes
                   if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    rebound.update(node.asname or node.name.split('.')[0] for node in nodes if isinstance(node, ast.alias))
    if '*' in rebound or any(isinstance(node, ast.Name) and node.id in {
        'globals', 'locals', 'vars', 'setattr', 'delattr', 'eval', 'exec', '__import__', '__builtins__'
    } for node in nodes):
        return {}
    result = {}
    for node in nodes:
        if not isinstance(node, ast.ClassDef):
            continue
        for base in node.bases:
            if not isinstance(base, ast.Name) or base.id in rebound:
                continue
            value = getattr(builtins, base.id, None)
            if (type(value) is type and value in _SIMPLE_EXCEPTIONS and value.__module__ == 'builtins'
                    and value.__name__ == base.id
                    and isinstance(value.__new__, BuiltinFunctionType)
                    and value.__new__.__qualname__ == value.__name__ + '.__new__'
                    and isinstance(value.__dict__.get('__init__'), WrapperDescriptorType)
                    and value.__dict__['__init__'].__objclass__ is value):
                result[base.id] = ['builtins::' + item.__name__ for item in value.__mro__]
    return result


def constructor_declaration_shape(node: ast.ClassDef, tree: ast.Module) -> bool:
    """Keep the first callback slice closed to namespace and receiver hooks."""
    if any(
        isinstance(value, ast.Name) and value.id in {
            '__builtins__', '__build_class__', 'globals', 'locals', 'vars', 'setattr',
            'delattr', 'eval', 'exec', '__import__'
        }
        or isinstance(value, ast.Import) and any(alias.name == 'builtins' for alias in value.names)
        or isinstance(value, ast.ImportFrom) and value.module == 'builtins'
        for value in ast.walk(tree)
    ):
        return False
    for member in node.body:
        if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if member.name in _FORBIDDEN:
                return False
            headers = [*member.args.defaults, *member.args.kw_defaults, member.returns,
                       *(argument.annotation for argument in [*member.args.posonlyargs,
                           *member.args.args, *member.args.kwonlyargs])]
            if any(isinstance(item, ast.Call) for header in headers if header is not None
                   for item in ast.walk(header)):
                return False
            if any(not isinstance(value, ast.Name) or value.id not in {
                'property', 'classmethod', 'staticmethod'
            } for value in member.decorator_list):
                return False
            if member.name == '__init__':
                if member.decorator_list or not member.args.args:
                    return False
                receiver = member.args.args[0].arg
                parents = {id(child): parent for parent in ast.walk(member)
                           for child in ast.iter_child_nodes(parent)}
                for value in ast.walk(member):
                    if isinstance(value, ast.Name) and value.id == receiver:
                        parent = parents.get(id(value))
                        if not (isinstance(value.ctx, ast.Load) and isinstance(parent, ast.Attribute)
                                and parent.value is value and isinstance(parent.ctx, ast.Store)):
                            return False
        elif isinstance(member, (ast.Assign, ast.AnnAssign)):
            targets = member.targets if isinstance(member, ast.Assign) else [member.target]
            if any(isinstance(target, ast.Name) and target.id in _FORBIDDEN | {'__init__', '__del__'}
                   for target in targets):
                return False
        elif not (isinstance(member, ast.Pass) or isinstance(member, ast.Expr)
                  and isinstance(member.value, ast.Constant) and isinstance(member.value.value, str)):
            return False
    return True


def constructor_callback_closures(classes: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Compute C3 over closed source classes and verified native exception bases."""
    cache: dict[str, dict[str, Any] | None] = {}
    active: set[str] = set()

    def resolve(symbol: str) -> dict[str, Any] | None:
        if symbol in cache:
            return cache[symbol]
        row = classes.get(symbol, {})
        if symbol in active or not row or row.get('library_model_binding'):
            return None
        if not row.get('closed_class_binding') and not row.get('constructor_local_binding'):
            return None
        if row.get('class_decorators') and not row.get('closed_class_binding'):
            return None
        active.add(symbol)
        parents = []
        methods: dict[str, dict[str, Any]] = {}
        for base in row.get('bases', []):
            if base.get('builtin_constructor_mro'):
                parents.append(list(base['builtin_constructor_mro']))
            else:
                parent = resolve(str(base.get('called_symbol', '')))
                if parent is None or classes.get(str(base.get('called_symbol', '')), {}).get('class_decorators'):
                    active.remove(symbol)
                    cache[symbol] = None
                    return None
                parents.append(list(parent['mro']))
        if not parents:
            parents = [['builtins::object']]
        sequences = [*parents, [parent[0] for parent in parents]]
        mro = [symbol]
        while any(sequences):
            sequences = [sequence for sequence in sequences if sequence]
            candidate = next((sequence[0] for sequence in sequences
                              if not any(sequence[0] in other[1:] for other in sequences)), None)
            if candidate is None:
                active.remove(symbol)
                cache[symbol] = None
                return None
            mro.append(candidate)
            for sequence in sequences:
                if sequence[0] == candidate:
                    sequence.pop(0)
        native_owners = {'builtins::' + value.__name__ for value in _SIMPLE_EXCEPTIONS}
        initializer_selected = False
        native_initializer = None
        for owner in mro:
            if not initializer_selected and owner in native_owners:
                native_initializer = owner + '.__init__'
                initializer_selected = True
            for method in classes.get(owner, {}).get('methods', []):
                if method['name'] == '__init__':
                    if initializer_selected:
                        continue
                    initializer_selected = True
                methods.setdefault(str(method['name']), method)
        initializer = methods.get('__init__')
        initializer_owner = str(initializer['symbol']).rsplit('.', 1)[0] if initializer else ''
        following = mro[mro.index(initializer_owner)+1:] if initializer_owner in mro else []
        super_initializer = None
        for owner in following:
            if any(method['name'] == '__init__' for method in classes.get(owner, {}).get('methods', [])):
                break
            if owner in native_owners:
                super_initializer = owner + '.__init__'
                break
        value = {'mro': mro, 'methods': methods, 'initializer': initializer,
                 'initializer_owner': initializer_owner, 'super_initializer': super_initializer,
                 'native_initializer': native_initializer}
        active.remove(symbol)
        cache[symbol] = value
        return value

    for symbol in classes:
        resolve(symbol)
    return {symbol: value for symbol, value in cache.items() if value is not None}


def literal_constructor_frames(
    row: dict[str, Any], function: ast.AST, positions: dict[int, list[int]],
    functions: dict[str, dict[str, Any]],
) -> tuple[set[tuple[Any, ...]], dict[tuple[Any, ...], tuple[tuple[str, str], ...]]]:
    """Bind literal call arguments even when surrounding control flow is unknown."""
    sites = {tuple(positions[id(node)]): node for node in ast.walk(function) if isinstance(node, ast.Call)}
    inputs: set[tuple[Any, ...]] = set()
    frames = {}
    for call in row.get('calls', []):
        spec = call.get('source_constructor_frame')
        site = (call.get('line'), call.get('column'))
        node = sites.get(site)
        if not spec or not isinstance(node, ast.Call) or not call.get('literal_arguments'):
            continue
        inputs.add((*site, spec['subject']))
        target = spec.get('initializer')
        declaration = functions.get(str(target), {}).get('python_value_source')
        if not declaration:
            continue
        parsed = ast.parse(declaration).body[0]
        if not isinstance(parsed, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        parameters = [*parsed.args.posonlyargs, *parsed.args.args]
        if not parameters:
            continue
        def origin(value: ast.AST) -> str:
            return type(value).__name__.lower() if isinstance(value, (ast.List, ast.Tuple, ast.Set, ast.Dict)) else 'scalar'
        bound = {parameters[0].arg: 'new-object:' + spec['subject'],
                 '$constructor_owner': spec['initializer_owner'],
                 '$constructor_super': spec.get('super_initializer') or ''}
        bound.update((parameter.arg, origin(value)) for parameter, value in zip(parameters[1:], node.args, strict=False))
        bound.update((keyword.arg, origin(keyword.value)) for keyword in node.keywords if keyword.arg is not None)
        default_parameters = parameters[-len(parsed.args.defaults):] if parsed.args.defaults else []
        for parameter, default in zip(default_parameters, parsed.args.defaults, strict=True):
            bound.setdefault(parameter.arg, 'scalar' if isinstance(default, ast.Constant) else 'unknown')
        for parameter, keyword_default in zip(parsed.args.kwonlyargs, parsed.args.kw_defaults, strict=True):
            bound.setdefault(parameter.arg, 'scalar' if isinstance(keyword_default, ast.Constant) else 'unknown')
        frames[(*site, target)] = tuple(sorted(bound.items()))
    return inputs, frames

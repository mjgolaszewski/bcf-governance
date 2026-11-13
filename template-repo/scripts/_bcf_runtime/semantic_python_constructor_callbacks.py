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


def native_exception_binding(name: str) -> bool:
    """Bind an exact reviewed CPython native constructor, not an annotation."""
    value = getattr(builtins, name, None)
    return (sys.implementation.name == 'cpython' and (3, 11) <= sys.version_info[:2] <= (3, 14)
            and type(value) is type and value in _SIMPLE_EXCEPTIONS
            and value.__module__ == 'builtins' and value.__name__ == name
            and isinstance(value.__new__, BuiltinFunctionType)
            and value.__new__.__qualname__ == name + '.__new__'
            and isinstance(value.__dict__.get('__init__'), WrapperDescriptorType)
            and value.__dict__['__init__'].__objclass__ is value)


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


def exact_scalar_guard(statement: ast.AST) -> str | None:
    """Recognize only exact, callback-free builtin type identity admission."""
    if not isinstance(statement, ast.If) or statement.orelse or not statement.body or not isinstance(statement.body[-1], ast.Raise):
        return None
    test = statement.test
    if (isinstance(test, ast.Compare) and len(test.ops) == 1
            and isinstance(test.ops[0], ast.IsNot) and len(test.comparators) == 1
            and isinstance(test.comparators[0], ast.Name) and test.comparators[0].id == 'str'
            and isinstance(test.left, ast.Call) and isinstance(test.left.func, ast.Name)
            and test.left.func.id == 'type' and len(test.left.args) == 1
            and not test.left.keywords and isinstance(test.left.args[0], ast.Name)):
        return test.left.args[0].id
    return None


def initial_scalar_guards(function: ast.AST, builtin_names: list[str]) -> set[str]:
    """Exact runtime type admission before any user-value protocol is invoked."""
    if not isinstance(function, ast.FunctionDef) or not {'type', 'str'} <= set(builtin_names):
        return set()
    guarded = set()
    for statement in function.body:
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str):
            continue
        name = exact_scalar_guard(statement)
        if name is None:
            break
        guarded.add(name)
    return guarded


def static_scalar_expression(value: ast.AST, function: ast.AST) -> bool:
    """Literal scalars and exact keys from a private, unaliased literal dict."""
    if isinstance(value, ast.Constant):
        return True
    if isinstance(value, ast.JoinedStr):
        return all(isinstance(part, ast.Constant) or isinstance(part, ast.FormattedValue)
                   and static_scalar_expression(part.value, function)
                   and (part.format_spec is None or static_scalar_expression(part.format_spec, function))
                   for part in value.values)
    if not isinstance(value, ast.Name):
        return False
    nodes = list(ast.walk(function))
    if any(isinstance(node, (ast.Global, ast.Nonlocal)) or isinstance(node, ast.Name)
           and node.id in {'exec', 'eval', 'globals', 'locals', 'vars'} for node in nodes):
        return False
    stores = [node for node in nodes if isinstance(node, ast.Name)
              and node.id == value.id and isinstance(node.ctx, (ast.Store, ast.Del))]
    if len(stores) != 1:
        return False
    for loop in nodes:
        if not (isinstance(loop, ast.For) and isinstance(loop.target, ast.Tuple)
                and len(loop.target.elts) == 2 and loop.target.elts[0] is stores[0]
                and isinstance(loop.iter, ast.Call) and not loop.iter.args and not loop.iter.keywords
                and isinstance(loop.iter.func, ast.Attribute) and loop.iter.func.attr == 'items'
                and isinstance(loop.iter.func.value, ast.Name)):
            continue
        mapping = loop.iter.func.value
        accesses = [node for node in nodes if isinstance(node, ast.Name) and node.id == mapping.id]
        assignments = [node for node in nodes if isinstance(node, ast.Assign)
                       and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                       and node.targets[0].id == mapping.id and isinstance(node.value, ast.Dict)]
        if len(accesses) != 2 or len(assignments) != 1:
            continue
        assignment = assignments[0]
        assert isinstance(assignment.value, ast.Dict)
        if assignment.lineno >= loop.lineno or any(not isinstance(key, ast.Constant) for key in assignment.value.keys):
            continue
        # This proof is lexical to this loop, never a function-wide name grant.
        if any(node is value for node in ast.walk(loop)):
            return True
    return False


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
        if not spec or not isinstance(node, ast.Call) or any(isinstance(arg, ast.Starred) for arg in node.args) or any(keyword.arg is None for keyword in node.keywords):
            continue
        target = spec.get('initializer')
        declaration = functions.get(str(target), {}).get('python_value_source')
        if not declaration:
            # Qualified native initialization stores borrowed references; it
            # does not inspect their protocols or confer ownership on them.
            inputs.add((*site, spec['subject']))
            continue
        parsed = ast.parse(declaration).body[0]
        if not isinstance(parsed, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        parameters = [*parsed.args.posonlyargs, *parsed.args.args]
        if not parameters:
            continue
        def origin(value: ast.AST) -> str:
            if isinstance(value, ast.JoinedStr) and static_scalar_expression(value, function):
                return 'scalar'
            return (type(value).__name__.lower() if isinstance(value, (ast.List, ast.Tuple, ast.Set, ast.Dict))
                    else 'scalar') if all(isinstance(part, (ast.Constant, ast.List, ast.Tuple, ast.Set, ast.Dict, ast.Load, ast.UnaryOp, ast.USub, ast.UAdd)) for part in ast.walk(value)) else 'unknown'
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
        # Unknown inputs stay borrowed. The actual initializer is visited
        # under this frame and must independently qualify every protocol/use.
        inputs.add((*site, spec['subject']))
        frames[(*site, target)] = tuple(sorted(bound.items()))
    return inputs, frames


def resolve_exception_callbacks(inventory: dict[str, Any], closures: dict[str, dict[str, Any]]) -> None:
    """Keep caught receiver identity, possible subclasses and native arg hooks."""
    classes = {str(row['symbol']): row for row in inventory.get('classes', [])}
    functions = {str(row['symbol']): row for row in inventory.get('functions', [])}
    constructors: dict[str, list[tuple[ast.Call, dict[tuple[int, int], dict[str, Any]]]]] = {}
    for function in functions.values():
        source = function.get('python_value_source')
        if not source:
            continue
        parsed = ast.parse(source).body[0]
        sites = iter(function.get('python_value_sites', []))
        positions = {id(node): tuple(next(sites, [0, 0])) for node in ast.walk(parsed)}
        calls = {(call.get('line'), call.get('column')): call
                 for call in function.get('calls', []) if not call.get('implicit_callback')}
        for node in ast.walk(parsed):
            if isinstance(node, ast.Call):
                call = calls.get(positions[id(node)], {})
                target = str(call.get('called_symbol', ''))
                if target in classes:
                    constructors.setdefault(target, []).append((node, {
                        (part.lineno, part.col_offset): calls.get(positions[id(part)], {})
                        for part in ast.walk(node) if isinstance(part, ast.Call)
                    }))

    def descends(symbol: str, target: str, seen: frozenset[str] = frozenset()) -> bool:
        if symbol == target:
            return True
        if symbol in seen:
            return False
        return any(descends(str(base.get('called_symbol', '')), target, seen | {symbol})
                   for base in classes.get(symbol, {}).get('bases', []))

    for function in functions.values():
        for read in function.get('caught_protocol_reads', []):
            targets = read.get('caught_type_symbols', [])
            candidates = [symbol for symbol in classes if any(descends(symbol, target) for target in targets)]
            name = '__str__' if read['call_name'] == 'str' else '__repr__'
            def callback(symbol: str, method_name: str = name, caller: dict[str, Any] = function,
                         site: dict[str, Any] = read) -> None:
                method = closures.get(symbol, {}).get('methods', {}).get(method_name)
                if method:
                    caller.setdefault('calls', []).append({'caller': caller['symbol'],
                        'called_symbol': method['symbol'], 'call_name': method_name,
                        'line': site['line'], 'column': site['column'],
                        'implicit_callback': True, 'callback_phase': 'caught_exception_formatting'})
            for candidate in candidates:
                closure = closures.get(candidate)
                if closure is None:
                    function.setdefault('implicit_effect_obligations', []).append({
                        'kind': 'unqualified_caught_exception_binding', 'line': read['line'], 'class_symbol': candidate})
                    continue
                if name in closure.get('methods', {}):
                    callback(candidate)
                    continue
                unresolved = not bool(constructors.get(candidate))
                for node, calls in constructors.get(candidate, []):
                    for value in node.args:
                        if isinstance(value, (ast.Constant, ast.JoinedStr)):
                            continue
                        if isinstance(value, ast.Call):
                            target = str(calls.get((value.lineno, value.col_offset), {}).get('called_symbol', ''))
                            argument_method = '__str__' if name == '__str__' and len(node.args) == 1 else '__repr__'
                            if target in closures and argument_method in closures[target].get('methods', {}):
                                callback(target, argument_method)
                                continue
                        unresolved = True
                if unresolved:
                    function.setdefault('implicit_effect_obligations', []).append({
                        'kind': 'unqualified_native_exception_argument_protocol',
                        'line': read['line'], 'class_symbol': candidate})

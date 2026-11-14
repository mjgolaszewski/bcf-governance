"""Associate normalization with a source-produced record, never annotation purity."""
from __future__ import annotations

import ast
from typing import Any

from .semantic_python_effect_obligations import python_binding_names


def resolve_normalization_receivers(inventory: dict[str, Any]) -> None:
    functions={str(row['symbol']):row for row in inventory.get('functions',[])}
    classes={str(row['symbol']):row for row in inventory.get('classes',[])}
    source_trees: dict[str, _SourceTree | None] = {}
    for function in functions.values():
        resolve_format_predicates(function)
        resolve_verified_content_receivers(function, functions, source_trees)
        by_site: dict[str,list[tuple[int,dict[str,Any]]]]={}
        for index,call in enumerate(function.get('calls',[])):
            if not call.get('implicit_callback'):
                by_site.setdefault(f"call:{call.get('line')}:{call.get('column')}",[]).append((index,call))
        for normalization in function.get('normalizations',[]):
            sources=normalization.get('receiver_result_sources',[])
            subjects=set()
            qualified=bool(sources)
            for source in sources:
                calls=by_site.get(source,[])
                if len(calls)!=1:
                    qualified=False
                    break
                index,call=calls[0]
                target=str(call.get('called_symbol',''))
                candidates={target} if target in classes else set()
                producer=functions.get(target,{})
                if producer.get('direct_class_receiver_return'):
                    candidates.update(str(binding['constructed_symbol'])
                        for inner in producer.get('calls',[])
                        for binding in inner.get('class_constructor_bindings',[])
                        if binding.get('binding_caller')==function['symbol']
                        and binding.get('binding_occurrence')==index)
                if len(candidates)!=1:
                    qualified=False
                    break
                subject=next(iter(candidates))
                record=classes.get(subject,{})
                if (not record.get('closed_class_binding') or record.get('library_model_binding')
                        or record.get('dataclass_default_factories')
                        or any(method['name'] in {'__init__','__new__','__post_init__','__getattr__','__getattribute__'}
                               for method in record.get('methods',[]))):
                    qualified=False
                    break
                subjects.add(subject)
            if qualified:
                normalization['source_receiver_subjects']=sorted(subjects)
                normalization['receiver_subject_binding']='closed_source_constructor_result'


def _standard_call(call: dict[str, Any], module: str, member: str) -> bool:
    if call.get('known_rebound_import'):
        return False
    reference = call.get('import_reference', {})
    binding = reference.get('binding', {})
    attributes = reference.get('attributes', [])
    return (binding.get('module') == module and (
        binding.get('kind') == 'import' and attributes == [member]
        or binding.get('kind') == 'from' and binding.get('member') == member and not attributes
    ))


def resolve_format_predicates(function: dict[str, Any]) -> None:
    """A qualified path suffix comparison is a format predicate, not identity rewriting."""
    source = function.get('python_value_source')
    if not source:
        return
    tree = ast.parse(source).body[0]
    nodes = list(ast.walk(tree))
    positions = {id(node): site for node, site in zip(nodes, function.get('python_value_sites', []), strict=False)}
    parents = {id(child): node for node in nodes for child in ast.iter_child_nodes(node)}
    calls = {(row.get('line'), row.get('column')): row for row in function.get('calls', [])
             if not row.get('implicit_callback')}
    normalizations = {(row.get('line'), row.get('column')): row for row in function.get('normalizations', [])}
    rebound = python_binding_names(nodes)
    for node in nodes:
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        receiver = node.func.value
        parent = parents.get(id(node))
        if (node.func.attr not in {'lower', 'upper'} or node.args or node.keywords
                or not isinstance(receiver, ast.Attribute) or receiver.attr != 'suffix'
                or not isinstance(receiver.value, ast.Call)
                or not isinstance(parent, ast.Compare) or len(parent.ops) != 1
                or not isinstance(parent.ops[0], (ast.Eq, ast.NotEq))
                or parent.left is not node or len(parent.comparators) != 1
                or not isinstance(parent.comparators[0], ast.Constant)
                or not isinstance(parent.comparators[0].value, str)):
            continue
        producer = calls.get(tuple(positions.get(id(receiver.value), [])), {})
        local = producer.get('import_reference', {}).get('local')
        if local in rebound or not _standard_call(producer, 'pathlib', 'Path'):
            continue
        fact = normalizations.get(tuple(positions.get(id(node), [])))
        if fact is not None:
            fact['normalization_role'] = 'path_suffix_format_predicate'


_SourceTree = tuple[ast.AST, dict[int, Any], dict[tuple[Any, ...], Any]]


def _source_tree(row: dict[str, Any], cache: dict[str, _SourceTree | None] | None = None) -> _SourceTree | None:
    symbol = str(row.get('symbol', ''))
    if cache is not None and symbol in cache:
        return cache[symbol]
    result: _SourceTree | None = None
    if row.get('python_value_source'):
        tree = ast.parse(row['python_value_source']).body[0]
        sites = {id(node): site for node, site in zip(ast.walk(tree), row.get('python_value_sites', []), strict=False)}
        calls = {(call.get('line'), call.get('column')): call for call in row.get('calls', []) if not call.get('implicit_callback')}
        result = tree, sites, calls
    if cache is not None:
        cache[symbol] = result
    return result


def _source_actuals(callee: dict[str, Any], invocation: ast.Call, caller: dict[str, Any], trees: dict[str, _SourceTree | None]) -> dict[str, ast.expr] | None:
    parsed = _source_tree(callee, trees)
    if parsed is None or not isinstance(parsed[0], (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    tree = parsed[0]
    positional = [argument.arg for argument in [*tree.args.posonlyargs, *tree.args.args]]
    if callee.get('class_symbol') and callee.get('method_binding_kind') != 'static':
        receiver = next(iter(caller.get('parameters', {})), '')
        if (not positional or caller.get('class_symbol') != callee['class_symbol']
                or not isinstance(invocation.func, ast.Attribute)
                or not isinstance(invocation.func.value, ast.Name)
                or invocation.func.value.id != receiver):
            return None
        positional = positional[1:]
    if len(invocation.args) > len(positional) or any(isinstance(value, ast.Starred) for value in invocation.args):
        return None
    actuals = dict(zip(positional, invocation.args, strict=False))
    declared = {*positional, *(argument.arg for argument in tree.args.kwonlyargs)}
    positional_only = {argument.arg for argument in tree.args.posonlyargs}
    for keyword in invocation.keywords:
        if keyword.arg is None or keyword.arg not in declared or keyword.arg in actuals or keyword.arg in positional_only:
            return None
        actuals[keyword.arg] = keyword.value
    return actuals


def _single_local_value(tree: ast.AST, name: str) -> ast.expr | None:
    stores = [node for node in ast.walk(tree) if isinstance(node, ast.Name)
              and node.id == name and isinstance(node.ctx, (ast.Store, ast.Del))]
    values = [node.value for node in ast.walk(tree)
              if isinstance(node, ast.Assign) and len(node.targets) == 1
              and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    values.extend(node.value for node in ast.walk(tree) if isinstance(node, ast.AnnAssign)
                  and isinstance(node.target, ast.Name) and node.target.id == name and node.value is not None)
    return values[0] if len(stores) == len(values) == 1 else None


def _returned_parameters(row: dict[str, Any], functions: dict[str, dict[str, Any]], trees: dict[str, _SourceTree | None], active: frozenset[str], budget: list[int]) -> set[str] | None:
    symbol = str(row.get('symbol', ''))
    parsed = _source_tree(row, trees)
    if not symbol or symbol in active or budget[0] <= 0 or parsed is None:
        return None
    budget[0] -= 1
    tree, sites, calls = parsed
    active = active | {symbol}

    def origins(value: ast.AST, aliases: frozenset[str] = frozenset()) -> set[str] | None:
        if isinstance(value, ast.Await):
            return origins(value.value, aliases)
        if isinstance(value, ast.Name) and value.id not in aliases:
            stores = any(isinstance(node, ast.Name) and node.id == value.id
                         and isinstance(node.ctx, (ast.Store, ast.Del)) for node in ast.walk(tree))
            if value.id in row.get('parameters', {}) and not stores:
                return {value.id}
            assigned = _single_local_value(tree, value.id)
            return origins(assigned, aliases | {value.id}) if assigned is not None else None
        if isinstance(value, ast.Call):
            call = calls.get(tuple(sites.get(id(value), [])), {})
            callee = functions.get(str(call.get('called_symbol', '')), {})
            returned = _returned_parameters(callee, functions, trees, active, budget)
            actuals = _source_actuals(callee, value, row, trees)
            if returned is None or actuals is None or any(name not in actuals for name in returned):
                return None
            result: set[str] = set()
            for name in returned:
                source = origins(actuals[name], aliases)
                if source is None:
                    return None
                result.update(source)
            return result
        return None

    returns = [node.value for node in ast.walk(tree) if isinstance(node, ast.Return)]
    if not returns or any(value is None for value in returns):
        return None
    result: set[str] = set()
    for value in returns:
        if value is None:
            return None
        source = origins(value)
        if source is None:
            return None
        result.update(source)
    return result


def _payload_parameters(row: dict[str, Any], value: ast.AST, functions: dict[str, dict[str, Any]], trees: dict[str, _SourceTree | None], active: frozenset[tuple[str, str]], budget: list[int]) -> set[tuple[str, str]] | None:
    parsed = _source_tree(row, trees)
    if parsed is None or budget[0] <= 0:
        return None
    budget[0] -= 1
    tree, sites, calls = parsed
    symbol = str(row.get('symbol', ''))
    result: set[tuple[str, str]] = set()
    if isinstance(value, ast.Await):
        return _payload_parameters(row, value.value, functions, trees, active, budget)
    if isinstance(value, ast.Constant) and type(value.value) in {bytes, str}:
        return set()
    if isinstance(value, ast.Name):
        key = symbol, value.id
        if key in active:
            return None
        stores = any(isinstance(node, ast.Name) and node.id == value.id
                     and isinstance(node.ctx, (ast.Store, ast.Del)) for node in ast.walk(tree))
        if value.id not in row.get('parameters', {}) or stores:
            assigned = _single_local_value(tree, value.id)
            if value.id in row.get('parameters', {}) or assigned is None:
                return None
            return _payload_parameters(row, assigned, functions, trees, active | {key}, budget)
        incoming = [(caller, call) for caller in functions.values() for call in caller.get('calls', [])
                    if not call.get('implicit_callback') and call.get('called_symbol') == symbol]
        if not incoming:
            return {key}
        for caller, call in incoming:
            source = _source_tree(caller, trees)
            if source is None:
                return None
            invocation = next((node for node in ast.walk(source[0]) if isinstance(node, ast.Call)
                               and tuple(source[1].get(id(node), [])) == (call.get('line'), call.get('column'))), None)
            actuals = _source_actuals(row, invocation, caller, trees) if invocation is not None else None
            if actuals is None or value.id not in actuals:
                return None
            roots = _payload_parameters(caller, actuals[value.id], functions, trees, active | {key}, budget)
            if roots is None:
                return None
            result.update(roots)
        return result
    if isinstance(value, ast.Call):
        call = calls.get(tuple(sites.get(id(value), [])), {})
        callee = functions.get(str(call.get('called_symbol', '')), {})
        returned = _returned_parameters(callee, functions, trees, frozenset(), budget)
        actuals = _source_actuals(callee, value, row, trees)
        if returned is None or actuals is None or any(name not in actuals for name in returned):
            return None
        for name in returned:
            roots = _payload_parameters(row, actuals[name], functions, trees, active, budget)
            if roots is None:
                return None
            result.update(roots)
        return result
    return None


def _content_transport(row: dict[str, Any], functions: dict[str, dict[str, Any]], trees: dict[str, _SourceTree | None]) -> bool:
    """Follow closed source returns; argument position alone is no output proof."""
    parsed = _source_tree(row, trees)
    if parsed is None or not isinstance(parsed[0], (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    args = [argument.arg for argument in [*parsed[0].args.posonlyargs, *parsed[0].args.args]]
    if row.get('class_symbol') and row.get('method_binding_kind') != 'static':
        args = args[1:]
    return bool(args) and _returned_parameters(row, functions, trees, frozenset(), [64]) == {args[0]}


def resolve_verified_content_receivers(function: dict[str, Any], functions: dict[str, dict[str, Any]], trees: dict[str, _SourceTree | None] | None = None) -> None:
    trees = {} if trees is None else trees
    parsed = _source_tree(function, trees)
    if parsed is None:
        return
    caller_tree, sites, calls = parsed
    for fact in function.get('normalizations', []):
        if fact.get('call_name') != 'decode':
            continue
        sources = fact.get('receiver_result_sources', [])
        if len(sources) != 1:
            continue
        source = sources[0].split(':')
        if len(source) != 3 or source[0] != 'call':
            continue
        call = calls.get((int(source[1]), int(source[2])), {})
        producer = functions.get(str(call.get('called_symbol', '')), {})
        produced = _source_tree(producer, trees)
        if produced is None:
            continue
        tree, producer_sites, producer_calls = produced
        returns = [node.value for node in ast.walk(tree) if isinstance(node, ast.Return)]
        if len(returns) != 1 or not isinstance(returns[0], ast.Name):
            continue
        name = returns[0].id
        stores = [node for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, (ast.Store, ast.Del))]
        assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)
            and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
        if len(stores) != 1 or len(assignments) != 1 or not isinstance(assignments[0].value, ast.Call):
            continue
        load = assignments[0].value
        load_call = producer_calls.get(tuple(producer_sites.get(id(load), [])), {})
        transport = functions.get(str(load_call.get('called_symbol', '')), {})
        if not _content_transport(transport, functions, trees) or not load.args or not isinstance(load.args[0], ast.Name):
            continue
        # The data input must be its own formal; record fields used as custody
        # keywords are not the returned representation. Alias/field data stays unknown.
        data_parameter = load.args[0].id
        if data_parameter not in producer.get('parameters', {}) or any(
            isinstance(node, ast.Name) and node.id == data_parameter and isinstance(node.ctx, (ast.Store, ast.Del))
            for node in ast.walk(tree)
        ):
            continue
        invocation = next((node for node in ast.walk(caller_tree) if isinstance(node, ast.Call)
                           and tuple(sites.get(id(node), [])) == (int(source[1]), int(source[2]))), None)
        actuals = _source_actuals(producer, invocation, function, trees) if invocation is not None else None
        if actuals is None or data_parameter not in actuals:
            continue
        data_sources = _payload_parameters(function, actuals[data_parameter], functions, trees, frozenset(), [64])
        if data_sources is None:
            continue
        digests = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and len(node.args) == 1 and isinstance(node.args[0], ast.Name) and node.args[0].id == name
            and _standard_call(producer_calls.get(tuple(producer_sites.get(id(node), [])), {}), 'hashlib', 'sha256')]
        if not digests:
            continue
        fact['source_content_input_parameters'] = [{'symbol': symbol, 'parameter': parameter}
                                                   for symbol, parameter in sorted(data_sources)]
        fact['normalization_role'] = 'source_verified_content_decode'
        fact['receiver_role_execution_qualified'] = False

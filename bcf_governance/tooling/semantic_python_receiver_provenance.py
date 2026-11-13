"""Associate normalization with a source-produced record, never annotation purity."""
from __future__ import annotations

import ast
from typing import Any


def resolve_normalization_receivers(inventory: dict[str, Any]) -> None:
    functions={str(row['symbol']):row for row in inventory.get('functions',[])}
    classes={str(row['symbol']):row for row in inventory.get('classes',[])}
    for function in functions.values():
        resolve_format_predicates(function)
        resolve_verified_content_receivers(function, functions)
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
    rebound = {node.id for node in nodes if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))}
    rebound.update(node.arg for node in nodes if isinstance(node, ast.arg))
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


def _source_tree(row: dict[str, Any]) -> tuple[ast.AST, dict[int, Any], dict[tuple[Any, ...], Any]] | None:
    if not row.get('python_value_source'):
        return None
    tree = ast.parse(row['python_value_source']).body[0]
    sites = {id(node): site for node, site in zip(ast.walk(tree), row.get('python_value_sites', []), strict=False)}
    calls = {(call.get('line'), call.get('column')): call for call in row.get('calls', []) if not call.get('implicit_callback')}
    return tree, sites, calls


def _content_transport(row: dict[str, Any]) -> bool:
    """Associate the first data argument, without claiming callback or output purity."""
    parsed = _source_tree(row)
    if parsed is None or not isinstance(parsed[0], (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    tree = parsed[0]
    args = [*tree.args.posonlyargs, *tree.args.args]
    names = [arg.arg for arg in args if arg.arg != next(iter(row.get('parameters', {})), '') or not row.get('class_symbol')]
    if not names:
        return False
    data = names[0]
    if any(isinstance(node, ast.Name) and node.id == data and isinstance(node.ctx, (ast.Store, ast.Del)) for node in ast.walk(tree)):
        return False
    returns = [node.value for node in ast.walk(tree) if isinstance(node, ast.Return)]
    return bool(returns) and all(
        isinstance(value, ast.Name) and value.id == data
        or isinstance(value, ast.Call) and bool(value.args)
        and isinstance(value.args[0], ast.Name) and value.args[0].id == data
        for value in returns)


def resolve_verified_content_receivers(function: dict[str, Any], functions: dict[str, dict[str, Any]]) -> None:
    parsed = _source_tree(function)
    if parsed is None:
        return
    _, sites, calls = parsed
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
        produced = _source_tree(producer)
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
        if not _content_transport(transport) or not load.args or not isinstance(load.args[0], ast.Name):
            continue
        # The data input must be its own formal; record fields used as custody
        # keywords are not the returned representation. Alias/field data stays unknown.
        if load.args[0].id not in producer.get('parameters', {}):
            continue
        digests = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and len(node.args) == 1 and isinstance(node.args[0], ast.Name) and node.args[0].id == name
            and _standard_call(producer_calls.get(tuple(producer_sites.get(id(node), [])), {}), 'hashlib', 'sha256')]
        if not digests:
            continue
        fact['normalization_role'] = 'source_verified_content_decode'
        fact['receiver_role_execution_qualified'] = False

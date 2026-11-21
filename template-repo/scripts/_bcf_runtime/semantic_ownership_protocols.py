"""Native-literal eligibility and neutral Python protocol observations."""

from __future__ import annotations

import ast


def _native_literal_value(node: ast.AST, names: set[str]) -> bool:
    """Recognize only closed builtin values; names here were bound locally."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        return node.id in names
    if isinstance(node, ast.UnaryOp):
        return _native_literal_value(node.operand, names)
    if isinstance(node, ast.Compare):
        return all(_native_literal_value(value, names) for value in [node.left, *node.comparators])
    if isinstance(node, ast.BoolOp):
        return all(_native_literal_value(value, names) for value in node.values)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_native_literal_value(value, names) for value in node.elts)
    if isinstance(node, ast.Dict):
        return all((key is None or _native_literal_value(key, names))
                   and _native_literal_value(value, names)
                   for key, value in zip(node.keys, node.values))
    if isinstance(node, ast.Starred):
        return _native_literal_value(node.value, names)
    if isinstance(node, ast.Subscript):
        return _native_literal_value(node.value, names) and _native_literal_value(node.slice, names)
    if isinstance(node, ast.Slice):
        return all(value is None or _native_literal_value(value, names)
                   for value in (node.lower, node.upper, node.step))
    return False


def boolean_result_sites(function: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[int]:
    """Bind result facts to a closed supported frame, never expression purity."""
    expressions = {ast.Constant, ast.UnaryOp, ast.Compare, ast.BoolOp, ast.Dict,
        ast.List, ast.Set, ast.Tuple, ast.IfExp, ast.Subscript, ast.Slice,
        ast.Attribute, ast.BinOp, ast.Load, ast.Return, ast.If, ast.Expr, ast.Pass,
        ast.And, ast.Or, ast.Not, ast.UAdd, ast.USub, ast.Invert, ast.Is, ast.IsNot,
        ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn,
        ast.Add, ast.Sub, ast.Mult, ast.MatMult, ast.Div, ast.FloorDiv, ast.Mod,
        ast.Pow, ast.LShift, ast.RShift, ast.BitOr, ast.BitXor, ast.BitAnd}
    args = function.args
    parameters = {arg.arg for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs,
        *([args.vararg] if args.vararg else []), *([args.kwarg] if args.kwarg else [])]}

    def supported(node: ast.AST, bound: set[str]) -> bool:
        if isinstance(node, ast.Name):
            return isinstance(node.ctx, ast.Load) and node.id in bound
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp)):
            local = set(bound)
            for generator in node.generators:
                if (generator.is_async or not supported(generator.iter, local)
                        or not isinstance(generator.target, ast.Name)):
                    return False
                local.add(generator.target.id)
                if not all(supported(guard, local) for guard in generator.ifs):
                    return False
            values = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            return all(supported(value, local) for value in values)
        return type(node) in expressions and all(supported(child, bound) for child in ast.iter_child_nodes(node))

    if not isinstance(function, ast.FunctionDef) or not all(supported(node, parameters) for node in function.body):
        return frozenset()
    return frozenset(id(node) for statement in function.body for node in ast.walk(statement)
        if (isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not))
        or (isinstance(node, ast.Compare) and node.ops
            and all(isinstance(operator, (ast.Is, ast.IsNot)) for operator in node.ops)))


def _native_protocol_value(node: ast.AST, names: set[str], boolean_results: frozenset[int]) -> bool:
    """Result consumption may be native while evaluating its operands is not."""
    if id(node) in boolean_results:
        return True
    if isinstance(node, ast.BoolOp):
        return all(_native_protocol_value(value, names, boolean_results) for value in node.values)
    return _native_literal_value(node, names)


# Version 1.1 adds explicit suspension/exception observations; legacy kinds stay 1.0.
IMPLICIT_PROTOCOL_KIND_VERSIONS = {"await": "1.1", "exception": "1.1", "pattern_match": "1.1"}


def implicit_runtime_protocols(
    node: ast.AST, native: set[str], call_targets: set[int],
    boolean_results: frozenset[int] = frozenset(),
) -> tuple[str, ...]:
    """Retain unknown runtime dispatch in the existing source call population."""
    def known(value):
        return _native_protocol_value(value, native, boolean_results)
    if isinstance(node, ast.Match):
        patterns = (ast.MatchValue, ast.MatchSequence, ast.MatchMapping, ast.MatchClass)
        active = any(any(isinstance(value, patterns) for value in ast.walk(case.pattern))
                     or (case.guard is not None and not known(case.guard)) for case in node.cases)
        return ("pattern_match",) if active else ()
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
        return () if id(node) in call_targets else ("attribute_read",)
    if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
        return () if known(node) else ("subscript_read",)
    if isinstance(node, ast.Dict):
        unknown = any(not known(value if key is None else key)
                      for key, value in zip(node.keys, node.values))
        return ("collection",) if unknown else ()
    if isinstance(node, ast.Set):
        return ("collection",) if any(not known(value) for value in node.elts) else ()
    if isinstance(node, (ast.DictComp, ast.SetComp)):
        bound = set(native)
        for generator in node.generators:
            if generator.is_async or not known(generator.iter):
                return ("collection",)
            bound.update(value.id for value in ast.walk(generator.target) if isinstance(value, ast.Name))
        key = node.key if isinstance(node, ast.DictComp) else node.elt
        return () if _native_protocol_value(key, bound, boolean_results) else ("collection",)
    if isinstance(node, ast.comprehension):
        return ("iteration",) if node.is_async or not known(node.iter) else ()
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return ("iteration",) if isinstance(node, ast.AsyncFor) or not known(node.iter) else ()
    if isinstance(node, ast.Starred) and isinstance(node.ctx, ast.Load):
        return () if known(node.value) else ("iteration",)
    if isinstance(node, ast.Assign) and any(isinstance(target, (ast.Tuple, ast.List)) for target in node.targets):
        return () if known(node.value) else ("iteration",)
    if isinstance(node, ast.YieldFrom):
        return () if known(node.value) else ("iteration",)
    if isinstance(node, ast.Await):
        return ("await",)
    if isinstance(node, ast.Raise) and node.exc is not None:
        return () if known(node.exc) else ("exception",)
    if isinstance(node, ast.UnaryOp):
        return () if known(node.operand) else (("truth",) if isinstance(node.op, ast.Not) else ("operator",))
    if isinstance(node, ast.Compare):
        if all(isinstance(operator, (ast.Is, ast.IsNot)) for operator in node.ops):
            return ()
        return () if all(known(value) for value in [node.left, *node.comparators]) else ("operator",)
    if isinstance(node, ast.BoolOp):
        return () if all(known(value) for value in node.values[:-1]) else ("truth",)
    if isinstance(node, ast.AugAssign):
        return () if known(node.target) and known(node.value) else ("operator",)
    if isinstance(node, ast.BinOp):
        return () if known(node.left) and known(node.right) else ("operator",)
    if isinstance(node, (ast.If, ast.IfExp, ast.While, ast.Assert)):
        return () if known(node.test) else ("truth",)
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return ("context_manager",)
    if isinstance(node, ast.FormattedValue):
        return () if known(node.value) and (node.format_spec is None or known(node.format_spec)) else ("format",)
    return ()


def cli_snapshot_model_sites(caller_source, guard_source, approved_guard_source, *, caller, callee, calls):
    """Derive supported call sites; qualification and native binding live outside syntax."""
    import hashlib
    import json

    if guard_source != approved_guard_source:
        raise ValueError("snapshot guard implementation differs from protected model source")
    guard_tree, caller_tree = ast.parse(guard_source), ast.parse(caller_source)
    functions = [node for node in guard_tree.body if isinstance(node, ast.FunctionDef) and node.name == "cli_arguments"]
    if len(functions) != 1:
        raise ValueError("snapshot guard definition is ambiguous")
    function = functions[0]
    args = function.args
    if (function.decorator_list or args.posonlyargs or args.kwonlyargs or args.vararg or args.kwarg
            or len(args.args) != 1 or args.args[0].arg != "argv"
            or len(args.defaults) != 1 or not isinstance(args.defaults[0], ast.Constant)
            or args.defaults[0].value is not None):
        raise ValueError("snapshot guard callable shape is unsupported")
    # This is the model's independently checked source contract, not a claim
    # of native purity or an authority flag on producer facts.
    expected = ast.parse("""def guard(argv):
    raw = sys.argv if argv is None else argv
    kind = type(raw)
    if kind is not list and kind is not tuple:
        raise TypeError("CLI arguments must be an ordinary string list or tuple")
    values = raw[:]
    if any(type(value) is not str for value in values):
        raise TypeError("CLI arguments must contain only ordinary strings")
    if argv is None:
        values = values[1:]
    return values if kind is list else [value for value in values]
""").body[0].body
    body = function.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    if [ast.dump(node, include_attributes=False) for node in body] != [ast.dump(node, include_attributes=False) for node in expected]:
        raise ValueError("snapshot guard body is outside qualified model")
    reserved = {"type", "list", "tuple", "str", "any", "TypeError", "sys", "__builtins__"}
    if any(isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in reserved
           for node in ast.walk(guard_tree)):
        raise ValueError("snapshot guard namespace contains rewritten model bindings")
    for node in ast.walk(guard_tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in reserved:
            raise ValueError("snapshot guard namespace contains a shadow definition")
        if isinstance(node, ast.arg) and node.arg in reserved:
            raise ValueError("snapshot guard namespace contains a shadow parameter")
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for name in node.names:
                bound = name.asname or name.name.split(".")[0]
                if bound in reserved and not (isinstance(node, ast.Import) and name.name == "sys" and bound == "sys"):
                    raise ValueError("snapshot guard namespace imports a model override")
    imports = [node for node in guard_tree.body if isinstance(node, ast.Import)
               for name in node.names if name.name == "sys" and name.asname in {None, "sys"}]
    if len(imports) != 1:
        raise ValueError("snapshot guard sys binding is unsupported")
    aliases = [name.asname or name.name for node in caller_tree.body if isinstance(node, ast.ImportFrom)
               and node.module and node.module.split(".")[-1] == "nested_cli_runtime"
               for name in node.names if name.name == "cli_arguments"]
    if len(aliases) != 1:
        raise ValueError("snapshot guard import binding is ambiguous")
    alias = aliases[0]
    if any((isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id == alias)
           or (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == alias)
           or (isinstance(node, ast.arg) and node.arg == alias) for node in ast.walk(caller_tree)):
        raise ValueError("snapshot guard caller rewrites its binding")
    for node in ast.walk(caller_tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for name in node.names:
                bound = name.asname or name.name.split(".")[0]
                if bound == alias and not (isinstance(node, ast.ImportFrom) and node in caller_tree.body
                        and node.module and node.module.split(".")[-1] == "nested_cli_runtime"
                        and name.name == "cli_arguments"):
                    raise ValueError("snapshot caller imports a rewritten guard binding")
    roots = [node for node in caller_tree.body if isinstance(node, ast.FunctionDef) and node.name == caller.split("::")[-1]]
    if len(roots) != 1 or roots[0].decorator_list:
        raise ValueError("snapshot caller definition is unsupported")
    root = roots[0]
    locations = {(row.get("line"), row.get("column")): row for row in calls if row.get("called_symbol") == callee}
    if len(locations) != len([row for row in calls if row.get("called_symbol") == callee]):
        raise ValueError("snapshot call location is ambiguous")
    registrations = [node for node in ast.walk(caller_tree) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument"
        and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "--adopter-python"]
    sites = []
    for node in ast.walk(root):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != alias:
            continue
        row = locations.get((node.lineno, node.col_offset))
        if row is None:
            # Other lexical frames remain ordinary obligations, not model credit.
            continue
        if len(node.args) != 1 or node.keywords:
            raise ValueError("snapshot invocation has unsupported arguments")
        value = node.args[0]
        if isinstance(value, ast.Name) and value.id == "argv":
            origin = "cli_entry_vector"
        elif (isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name)
                and value.value.id == "args" and value.attr == "adopter_python"):
            if len(registrations) != 1:
                raise ValueError("snapshot parser source population is ambiguous")
            settings = {keyword.arg: keyword.value for keyword in registrations[0].keywords}
            if ("type" in settings or not isinstance(settings.get("action"), ast.Constant)
                    or settings["action"].value != "append" or not isinstance(settings.get("default"), ast.List)
                    or settings["default"].elts):
                raise ValueError("snapshot parser append vector is unsupported")
            origin = "parser_append_vector"
        else:
            raise ValueError("snapshot argument origin is outside qualified model")
        contract = row.get("call_contract")
        digest = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
        if not isinstance(contract, dict) or contract.get("expression_sha256") != digest:
            raise ValueError("snapshot call contract differs from source")
        identity = dict(caller=caller, callee=callee, line=node.lineno, column=node.col_offset,
                        expression_sha256=digest, occurrence=contract.get("occurrence"), input_origin=origin)
        sites.append((json.dumps(identity, sort_keys=True, separators=(",", ":")),
                      json.dumps(row, sort_keys=True, separators=(",", ":"))))
    if not sites or len(sites) != len(locations):
        raise ValueError("snapshot model omits or invents source call contexts")
    return tuple(sorted(sites))


def cli_snapshot_iteration_sites(caller_source, *, caller, calls, guard_sites):
    """Derive only native-list iteration entry; body and element effects remain open."""
    import hashlib
    import json

    tree = ast.parse(caller_source)
    if not any(isinstance(node, ast.ImportFrom) and node.module == "__future__"
               and any(name.name == "annotations" for name in node.names) for node in tree.body):
        raise ValueError("snapshot iteration requires postponed local annotations")
    roots = [node for node in tree.body if isinstance(node, ast.FunctionDef)
             and node.name == caller.split("::")[-1]]
    if len(roots) != 1:
        raise ValueError("snapshot iteration caller is ambiguous")
    expected_test = ast.dump(ast.parse('args.operation == "qualify-release"', mode="eval").body,
                             include_attributes=False)
    branches = [node for node in ast.walk(roots[0]) if isinstance(node, ast.If)
                and ast.dump(node.test, include_attributes=False) == expected_test]
    if len(branches) != 1 or len(branches[0].body) < 3:
        raise ValueError("snapshot iteration branch is unsupported")
    guarded, allocation, loop = branches[0].body[:3]
    if (not isinstance(guarded, ast.Try) or len(guarded.body) != 1
            or guarded.orelse or guarded.finalbody or len(guarded.handlers) != 1):
        raise ValueError("snapshot iteration guard flow is unsupported")
    handler = guarded.handlers[0]
    assignment = guarded.body[0]
    if (not isinstance(handler.type, ast.Name) or handler.type.id != "TypeError"
            or len(handler.body) != 1 or not isinstance(handler.body[0], ast.Raise)
            or not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1
            or not isinstance(assignment.targets[0], ast.Name) or not isinstance(assignment.value, ast.Call)):
        raise ValueError("snapshot iteration requires a guarded local assignment and terminal error path")
    bound = assignment.targets[0].id
    if any(isinstance(node, (ast.Global, ast.Nonlocal)) and bound in node.names
           for node in ast.walk(roots[0])):
        raise ValueError("snapshot iteration result is not a local binding")
    if (not isinstance(allocation, ast.AnnAssign) or not isinstance(allocation.target, ast.Name)
            or allocation.target.id == bound or not isinstance(allocation.value, ast.Dict)
            or allocation.value.keys or not isinstance(loop, ast.For)
            or not isinstance(loop.iter, ast.Name) or loop.iter.id != bound
            or not isinstance(loop.target, ast.Name)):
        raise ValueError("snapshot iteration local is rebound or has intervening effects")
    invocation = assignment.value
    guards = [json.loads(identity) for identity, _ in guard_sites]
    guards = [row for row in guards if row["input_origin"] == "parser_append_vector"
              and (row["line"], row["column"]) == (invocation.lineno, invocation.col_offset)]
    if len(guards) != 1:
        raise ValueError("snapshot iteration does not consume a qualified guard result")
    rows = [row for row in calls if row.get("called_symbol") == "python-implicit::iteration"
            and (row.get("line"), row.get("column")) == (loop.lineno, loop.col_offset)]
    digest = hashlib.sha256(ast.dump(loop, include_attributes=False).encode()).hexdigest()
    if (len(rows) != 1 or rows[0].get("call_contract", {}).get("expression_sha256") != digest
            or rows[0].get("implicit_protocol", {}).get("expression_sha256") != digest):
        raise ValueError("snapshot iteration source protocol is missing or ambiguous")
    row = rows[0]
    identity = dict(caller=caller, line=loop.lineno, column=loop.col_offset,
        expression_sha256=digest, occurrence=row["call_contract"]["occurrence"],
        kind="native_list_iterator", value_origin="fresh_exact_list_at_loop_entry", guard_call=guards[0])
    return ((json.dumps(identity, sort_keys=True, separators=(",", ":")),
             json.dumps(row, sort_keys=True, separators=(",", ":"))),)

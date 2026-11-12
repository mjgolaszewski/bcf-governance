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


# Version 1.1 adds explicit suspension/exception observations; legacy kinds stay 1.0.
IMPLICIT_PROTOCOL_KIND_VERSIONS = {"await": "1.1", "exception": "1.1", "pattern_match": "1.1"}


def implicit_runtime_protocols(
    node: ast.AST, native: set[str], call_targets: set[int],
) -> tuple[str, ...]:
    """Retain unknown runtime dispatch in the existing source call population."""
    known = lambda value: _native_literal_value(value, native)
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
        return () if _native_literal_value(key, bound) else ("collection",)
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

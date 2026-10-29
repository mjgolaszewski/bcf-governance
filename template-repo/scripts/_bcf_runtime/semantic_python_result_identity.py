"""Conservative source-result dispatch; ordinary call edges retain all effects.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

from collections import Counter
import copy
from collections.abc import Callable
from typing import Any

from .semantic_python_descriptor_identity import _inherited_classes
from .semantic_python_return_facts import _contains_opaque_input
from .semantic_python_namespace_value_contracts import escape_discharged

_UNKNOWN = "?"
_HOOKS = {"__new__", "__getattr__", "__getattribute__", "__class__", "__bases__",
          "__dict__", "__builtins__", "__code__", "__init__", "__build_class__",
          "__globals__", "__closure__", "__mro__", "__defaults__", "__kwdefaults__",
          "__get__", "__set__", "__delete__", "__setattr__", "__delattr__"}


class _Results:
    def __init__(self, inventory: dict[str, Any],
                 reference: Callable[[str, str], str | None]) -> None:
        self.inventory = inventory
        self.remaining_origins = 100000
        self.reference = reference
        self.functions = {str(row["symbol"]): row for row in inventory.get("functions", [])}
        population = inventory.get("return_facts", [])
        counts = Counter(str(row["symbol"]) for row in population)
        self.facts = {str(row["symbol"]): row for row in population if counts[str(row["symbol"])] == 1}
        self.classes: dict[str, dict[str, Any]] = {}
        self.class_symbols: set[str] = set()
        self.class_names: set[str] = set()
        self.methods: set[str] = set()
        self.ordinary: set[str] = set()
        self.syntax: dict[str, dict[str, Any]] = {}
        self.sources: dict[str, dict[str, Any]] = {}
        sources = inventory.get("descriptor_syntax", [])
        inherited = _inherited_classes(sources, inventory)
        writes = {name for source in sources for name in source["attribute_writes"]}
        critical_bindings = {name for source in sources for name in source["bindings"]}
        uncertain = bool(inventory.get("descriptor_binding_uncertainty")) or any(
            {"Global", "Nonlocal"} & set(row["unsupported"]) for row in population)
        self.binding_guard_obligations: list[dict[str, Any]] = []
        if inventory.get("binding_dependencies"):
            self.binding_guard_obligations.append({"kind": "source_binding_dependencies",
                "facts": copy.deepcopy(inventory["binding_dependencies"]),
                "permits_acceptance": False})
        if inventory.get("descriptor_binding_uncertainty"):
            self.binding_guard_obligations.append({
                "kind": "descriptor_binding_uncertainty",
                "facts": copy.deepcopy(inventory["descriptor_binding_uncertainty"]),
            })
        for row in population:
            if {"Global", "Nonlocal"} & set(row["unsupported"]):
                self.binding_guard_obligations.append({"kind": "global_or_nonlocal",
                    "symbol": row["symbol"], "unsupported": list(row["unsupported"])})
        uncertain = uncertain or bool(writes & critical_bindings)
        if writes & critical_bindings:
            self.binding_guard_obligations.append({"kind": "critical_binding_write",
                                                  "names": sorted(writes & critical_bindings)})
        uncertain = uncertain or any(
            read["attribute"] in {"__globals__", "__closure__", "__dict__", "__builtins__"}
            for source in sources
            for method in [*source["functions"],
                           *(method for cls in source["classes"] for method in cls["methods"])]
            for read in method["attribute_reads"])
        module_bindings = {str(row["path"]): row["bindings"] for row in sources}
        for source in sources:
            for method in [*source["functions"], *(m for cls in source["classes"] for m in cls["methods"])]:
                for read in method["attribute_reads"]:
                    if read["attribute"] in {"__globals__", "__closure__", "__dict__", "__builtins__"}:
                        self.binding_guard_obligations.append({"kind": "reflective_read",
                            "symbol": method["symbol"], "read": copy.deepcopy(read)})
        module_imports = {str(row["path"]): {binding["local"] for binding in row["bindings"]
                                            if binding["kind"] == "import"}
                          for row in inventory.get("imports", [])}
        for row in population:
            path = str(row["symbol"]).split("::", 1)[0]
            for escape in row.get("source_escapes", []):
                if escape_discharged(inventory, str(row['symbol']), escape):
                    continue  # Only the qualified value/nonretention cause; raw facts retained.
                if (escape["name"] in module_bindings.get(path, {})
                        and (escape["role"] == "argument"
                             or escape["name"] not in module_imports.get(path, set()))):
                    uncertain = True
                    self.binding_guard_obligations.append({"kind": "source_escape",
                        "symbol": row["symbol"], "escape": copy.deepcopy(escape)})
        for source in sources:
            path = str(source["path"])
            self.sources[path] = source
            for method in source["functions"]:
                self.syntax[method["symbol"]] = method
                if (not uncertain and not source["unsafe_scope"]
                        and source["bindings"].get(method["name"]) == 1
                        and not method["decorators"] and method["name"] not in writes):
                    self.ordinary.add(method["symbol"])
            for cls in source["classes"]:
                self.class_symbols.add(cls["symbol"])
                self.class_names.add(cls["name"])
                for method in cls["methods"]:
                    self.syntax[method["symbol"]] = method
                    self.methods.add(method["name"])
                if (uncertain or cls["symbol"] in inherited or cls["decorators"]
                        or cls["bases"] or cls["keywords"] or cls["unsafe_scope"]
                        or source["unsafe_scope"] or writes & _HOOKS
                        or source["bindings"].get(cls["name"]) != 1
                        or {"__new__", "__getattr__", "__getattribute__"} & set(cls["bindings"])):
                    continue
                self.classes[cls["symbol"]] = cls
        self.writes = writes

    def method(self, cls: str, name: str) -> str | None:
        row = self.classes.get(cls)
        target = cls + "." + name
        syntax = self.syntax.get(target)
        if (row is None or syntax is None or syntax["decorators"]
                or row["bindings"].get(name) != 1 or name in self.writes
                or syntax["unsafe_scope"] or syntax["eager_header_unresolved"]
                or not syntax["receiver_stable"] or target not in self.functions):
            return None
        return target

    def arguments(self, target: str, call: dict[str, Any], env: dict[str, set[str]],
                  path: str, stack: frozenset[str], receiver: str | None
                  ) -> dict[str, set[str]] | None:
        facts = self.facts.get(target)
        if facts is None or facts["unsupported"] or facts["defaults"]:
            return None
        names = list(facts["parameters"])
        values = ([{receiver}] if receiver is not None else []) + [
            self.origins(group, env, path, stack) for group in call["arguments"]]
        if len(values) > len(names):
            return None
        bound = dict(zip(names, values, strict=False))
        for keyword in call["keywords"]:
            name = keyword["name"]
            if name is None or name not in names or name in bound:
                return None
            bound[name] = self.origins(keyword["origins"], env, path, stack)
        return bound if set(bound) == set(names) else None

    def returned(self, target: str, call: dict[str, Any], env: dict[str, set[str]],
                 path: str, stack: frozenset[str], receiver: str | None = None) -> set[str]:
        if target in stack or len(stack) >= 32:
            return {_UNKNOWN}
        bound = self.arguments(target, call, env, path, stack, receiver)
        if bound is None:
            return {_UNKNOWN}
        rows = self.facts[target]["returns"]
        if not rows:
            return {_UNKNOWN}  # No successful returned object established.
        result: set[str] = set()
        for row in rows:
            result.update(self.origins(row["alternatives"], bound,
                                       target.split("::", 1)[0], stack | {target}))
        return result or {_UNKNOWN}

    def origins(self, rows: list[dict[str, Any]], env: dict[str, set[str]],
                path: str, stack: frozenset[str]) -> set[str]:
        result: set[str] = set()
        for row in rows:
            self.remaining_origins -= 1
            if self.remaining_origins < 0:
                self.inventory["result_receiver_budget_exhausted"] = True
                return {_UNKNOWN}
            kind = row["kind"]
            if kind in {"self", "parameter"}:
                result.update(env.get(row["name"], {_UNKNOWN}))
            elif kind == "call_result":
                result.update(self.call_result(row, env, path, stack))
            else:
                result.add(_UNKNOWN)
            if len(result) > 64:
                return {_UNKNOWN}
        return result or {_UNKNOWN}

    def call_target(self, call: dict[str, Any], env: dict[str, set[str]],
                    path: str, stack: frozenset[str]) -> tuple[str | None, str | None]:
        if call["callee_kind"] == "Name":
            origins = call["callee_origins"]
            if len(origins) != 1 or origins[0]["kind"] != "source_name":
                return None, None
            target = self.reference(path, call["callee"])
            return target, None
        if call["callee_kind"] == "Attribute":
            receiver = self.origins(call["receiver_origins"], env, path, stack)
            if len(receiver) == 1 and _UNKNOWN not in receiver:
                cls = next(iter(receiver))
                return self.method(cls, call["callee"].rsplit(".", 1)[-1]), cls
            # A literal imported module reference may resolve a source factory.
            raw = call["receiver_origins"]
            if len(raw) == 1 and raw[0]["kind"] == "source_name":
                return self.reference(path, call["callee"]), None
        return None, None

    def call_result(self, call: dict[str, Any], env: dict[str, set[str]],
                    path: str, stack: frozenset[str]) -> set[str]:
        target, receiver = self.call_target(call, env, path, stack)
        if target in self.classes:
            assert target is not None
            initializer = self.method(target, "__init__")
            if "__init__" in self.classes[target]["bindings"]:
                if initializer is None or self.arguments(initializer, call, env, path, stack, target) is None:
                    return {_UNKNOWN}
            elif call["arguments"] or call["keywords"]:
                return {_UNKNOWN}
            return {target}
        if target is not None and (target in self.ordinary or receiver is not None):
            return self.returned(target, call, env, path, stack, receiver)
        return {_UNKNOWN}

    def keep_effects(self, target: str) -> None:
        function = self.functions.get(target)
        syntax = self.syntax.get(target)
        if function is None or syntax is None:
            return
        existing = {(call.get("line"), call.get("called_symbol"))
                    for call in function.get("calls", [])}
        for write in syntax["attribute_writes"]:
            symbol = target + ":result-body-write:" + write["target"]
            if (write["line"], symbol) not in existing:
                function.setdefault("calls", []).append({
                    "caller": target, "called_symbol": symbol, "line": write["line"],
                    "call_name": "<result-body-write>", "effect": "write", "argument_origins": []})

    def literal_path_constructor(self, path: str, syntax: dict[str, Any],
                                 call: dict[str, Any]) -> bool:
        """Bound only stdlib Path allocation from exact literal strings.

        This proves neither the result's model identity nor purity of methods
        called on it. All enclosing call effects remain independently charged.
        """
        if (call.get("called_symbol") != "pathlib::Path"
                or syntax["callee_kind"] != "Name" or syntax["keywords"]
                or syntax["callee_origins"] != [{"kind": "source_name", "name": syntax["callee"]}]
                or any(group != [{"kind": "literal", "type": "str"}]
                       for group in syntax["arguments"])):
            return False
        source = self.sources.get(path, {})
        if source.get("bindings", {}).get(syntax["callee"]) != 1:
            return False
        sensitive = {syntax["callee"], "Path", "__new__", "__init__", "__call__",
                     "__getattribute__", "__class__", "__bases__", "__dict__", "__mro__"}
        if self.writes & sensitive or any(
            mutation["attribute"] is None or mutation["attribute"] in sensitive
            for row in self.inventory.get("descriptor_syntax", [])
            for mutation in row["namespace_mutations"]
        ):
            return False
        call["dispatch_resolution"] = "exact_stdlib_literal_path_constructor"
        call["dispatch_port_eligible"] = False
        call["result_identity"] = "unresolved_external"
        return True

    def _guard_opaque_receivers(self, function: dict[str, Any], facts: dict[str, Any]) -> None:
        for syntax in facts["call_sites"]:
            origins = (syntax["receiver_origins"] if syntax["callee_kind"] == "Attribute"
                       else syntax["callee_origins"])
            if not _contains_opaque_input(origins):
                continue
            name = syntax["callee"].rsplit(".", 1)[-1]
            for call in function.get("calls", []):
                if (call.get("line") == syntax["line"] and call.get("call_name") == name
                        and not call.get("descriptor_access")
                        and call.get("dispatch_resolution") not in {
                            "exact_same_instance", "exact_builtin_exception_constructor",
                            "exact_source_result_receiver"}):
                    call["dispatch_resolution"] = "unresolved"
                    call["dispatch_port_eligible"] = False

    def apply(self) -> None:
        for symbol, facts in self.facts.items():
            function = self.functions.get(symbol)
            if function is None:
                continue
            calls = function.get("calls", [])
            if facts["unsupported"]:
                self._guard_opaque_receivers(function, facts)
                for call in calls:
                    if (call.get("call_name") in self.methods | self.class_names
                            and call.get("dispatch_resolution") not in {
                                "exact_same_instance", "exact_builtin_exception_constructor"}):
                        call["dispatch_resolution"] = "unresolved"
                        call["dispatch_port_eligible"] = False
                continue
            anchors = Counter((row["line"], row["callee"].rsplit(".", 1)[-1])
                              for row in facts["call_sites"])
            for syntax in facts["call_sites"]:
                name = syntax["callee"].rsplit(".", 1)[-1]
                matches = [call for call in calls if call.get("line") == syntax["line"]
                           and call.get("call_name") == name and not call.get("descriptor_access")]
                if len(matches) != 1 or anchors[(syntax["line"], name)] != 1:
                    if name in self.methods | self.class_names:
                        for call in matches:
                            call["dispatch_resolution"] = "unresolved"
                            call["dispatch_port_eligible"] = False
                    continue  # Never guess same-line call identities.
                call = matches[0]
                if self.literal_path_constructor(symbol.split("::", 1)[0], syntax, call):
                    continue
                if call.get("dispatch_resolution") in {"exact_same_instance", "exact_builtin_exception_constructor"}:
                    continue
                target, receiver = self.call_target(syntax, {}, symbol.split("::", 1)[0], frozenset())
                if target is None and call.get("called_symbol") in self.functions:
                    call["dispatch_resolution"] = "unresolved"
                    call["dispatch_port_eligible"] = False
                    continue
                if (target in self.functions and receiver is None and target not in self.ordinary):
                    call["dispatch_resolution"] = "unresolved"
                    call["dispatch_port_eligible"] = False
                    continue
                if target is None and syntax["callee_kind"] == "Name":
                    path = symbol.split("::", 1)[0]
                    origins = syntax["callee_origins"]
                    if (any(row["kind"] != "source_name" for row in origins)
                            or self.sources.get(path, {}).get("bindings", {}).get(syntax["callee"])):
                        call["dispatch_resolution"] = "unresolved"
                        call["dispatch_port_eligible"] = False
                        continue
                if target in self.class_symbols and target not in self.classes:
                    call["dispatch_resolution"] = "unresolved"
                    call["dispatch_port_eligible"] = False
                    continue
                constructor = target in self.classes
                if constructor:
                    assert target is not None
                    if self.call_result(syntax, {}, symbol.split("::", 1)[0], frozenset()) == {_UNKNOWN}:
                        call["dispatch_resolution"] = "unresolved"
                        call["dispatch_port_eligible"] = False
                        continue
                    initializer = self.method(target, "__init__")
                    if initializer is None:
                        call["dispatch_resolution"] = "exact_source_implicit_object_constructor"
                        continue
                    target = initializer
                if target is not None and (constructor or receiver is not None or target in self.ordinary):
                    previous = call.get("called_symbol")
                    call["called_symbol"] = target
                    call["dispatch_resolution"] = "exact_source_result_receiver"
                    call["dispatch_port_eligible"] = False
                    call["source_column"] = syntax["column"]
                    function["effect_unresolved"] = [failure for failure in function.get("effect_unresolved", [])
                        if not (failure.get("line") == syntax["line"] and failure.get("called_symbol") == previous
                                and failure.get("kind") == "ambiguous_method_dispatch")]
                    self.keep_effects(target)
                elif syntax["callee_kind"] == "Attribute" and name in self.methods:
                    call["dispatch_resolution"] = "unresolved"
                    call["dispatch_port_eligible"] = False
                    function.setdefault("effect_unresolved", []).append({
                        "kind": "unproven_result_receiver", "dispatch_kind": "result_receiver",
                        "symbol": symbol, "called_symbol": call.get("called_symbol"),
                        "line": syntax["line"], "column": syntax["column"], "port_eligible": False})

            self._guard_opaque_receivers(function, facts)


def resolve_result_receivers(inventory: dict[str, Any], *,
                             reference: Callable[[str, str], str | None]) -> None:
    """Resolve a closed source subset; unsupported results never become permission."""
    _Results(inventory, reference).apply()

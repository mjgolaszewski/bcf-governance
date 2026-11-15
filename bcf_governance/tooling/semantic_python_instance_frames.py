"""Closed source-instance dispatch identities, separate from mutation ownership."""
from __future__ import annotations

import copy
from typing import Any


def source_instance_method_maps(inventory: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Reuse the real dispatcher for exact constructor-site receiver identities."""
    from .semantic_python_method_identity import resolve_method_dispatch
    view: dict[str, Any] = {"classes": copy.deepcopy(inventory.get("classes", [])),
            "functions": copy.deepcopy(inventory.get("functions", []))}
    blocked = {row.get("called_symbol") for row in inventory.get("class_binding_mutations", [])}
    probes: list[dict[str, Any]] = []
    for cls in view["classes"]:
        subject = str(cls["symbol"])
        if (subject in blocked or cls.get("library_model_binding")
                or not (cls.get("closed_class_binding") or cls.get("constructor_local_binding"))):
            continue
        calls = [{"called_symbol": str(method["symbol"]), "call_name": method["name"],
                  "line": 0, "column": index,
                  "method_dispatch": {"kind": "same_instance", "class_symbol": subject,
                                      "method": method["name"], "receiver": "$instance"}}
                 for index, method in enumerate(cls.get("methods", []))
                 if method.get("binding") == "instance" and not method.get("decorators")
                 and not str(method["name"]).startswith("__")]
        probe = {"symbol": subject + ".<instance-dispatch-proof>", "class_symbol": subject,
                 "calls": calls, "receiver_attribute_mutations": [], "decorators": []}
        probes.append(probe)
    view["functions"].extend(probes)
    resolve_method_dispatch(view)
    return {str(row["class_symbol"]): {
        str(call["call_name"]): str(call["called_symbol"])
        for call in row["calls"] if call.get("dispatch_resolution") == "exact_same_instance"
    } for row in probes}

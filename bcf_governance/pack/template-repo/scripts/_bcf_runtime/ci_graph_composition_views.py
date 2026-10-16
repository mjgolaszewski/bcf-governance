"""Pure projections of the singular compiled lifecycle owner.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

import hashlib
import html
from typing import Any

from .ci_graph_errors import CIGraphError


def _render_lifecycle_composition(compiled: dict[str, Any], *, view: str = "bound") -> str:
    """Format a compiled snapshot after the public owner validates identity."""

    from .ci_graph_composition import _bytes

    if view not in {"bound", "contract", "machine"}:
        raise CIGraphError("lifecycle composition projection view is invalid")
    if view == "machine":
        return _bytes({
            "schema_version": "1.1", "relationships": compiled["relationships"],
        }).decode() + "\n"
    source = compiled["source"]
    identity = f"Composition: `{compiled['composition_sha256']}`"
    if view == "contract":
        source = {key: source[key] for key in ("graph_sha256", "ci_edges_sha256", "policy_sha256")}
        digest = hashlib.sha256(_bytes({
            "schema_version": compiled["schema_version"],
            "source": source,
            "relationships": compiled["relationships"],
        })).hexdigest()
        identity = f"Contract: `{digest}`; exact attempt custody remains in the bound runtime envelope."

    def display(value: Any) -> str:
        text = value if isinstance(value, str) else _bytes(value).decode()
        return html.escape(text, quote=True).replace("|", "&#124;").replace("\n", "<br>")

    rows = compiled["relationships"]
    states = sorted({(row["context"], row[key]) for row in rows for key in ("producer", "consumer")})
    nodes = {state: f"n{index}" for index, state in enumerate(states)}
    lines = [
        "# Lifecycle composition", "",
        "Generated from the compiled machine contract; this view grants no authority.", "",
        identity, "",
        "| Source identity | Value |", "| --- | --- |",
        *[f"| {display(key)} | {display(value)} |" for key, value in sorted(source.items())],
        "", "```mermaid", "flowchart TD",
    ]
    for state in states:
        lines.append(f'  {nodes[state]}["{display(state[0])}: {display(state[1])}"]')
    for row in rows:
        if row["contract"] is not None:
            lines.append(
                f"  {nodes[(row['context'], row['producer'])]} --> "
                f"{nodes[(row['context'], row['consumer'])]}"
            )
    lines += ["```", "", "| Context | Producer | Consumer | Disposition |", "| --- | --- | --- | --- |"]
    for row in rows:
        disposition = row["exclusion"] if row["contract"] is None else "reachable"
        lines.append("| " + " | ".join(display(value) for value in (
            row["context"], row["producer"], row["consumer"], disposition,
        )) + " |")
    for row in rows:
        if row["contract"] is None:
            continue
        lines += [
            "", f"## {display(row['context'])}: {display(row['producer'])} → {display(row['consumer'])}",
            "", "| Contract field | Value |", "| --- | --- |",
            *[f"| {display(key)} | {display(value)} |" for key, value in sorted(row["contract"].items())],
        ]
    return "\n".join(lines) + "\n"

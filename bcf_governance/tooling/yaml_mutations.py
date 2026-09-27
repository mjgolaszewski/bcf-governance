"""Single-owner resolution for typed governance YAML mutation paths."""

from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
import re
from typing import Any

import yaml  # type: ignore[import-untyped]
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode  # type: ignore[import-untyped]


_SELECTOR = re.compile(r"^(?P<key>[^\[\]]+)\[(?P<field>[A-Za-z_][A-Za-z0-9_-]*)=(?P<value>[^\[\]]+)\]$")


class YAMLMutationPathError(ValueError):
    """Raised when a typed YAML path is absent, ambiguous, or unsafe."""


def mutation_mode(mutation: dict[str, Any], *, suffix: str) -> str:
    """Classify one control mutation and reject ambiguous or untyped YAML edits."""

    text_mode = isinstance(mutation.get("search"), str) and bool(mutation["search"])
    replacement_count = sum(
        isinstance(mutation.get(key), str) for key in ("replace", "replace_base64")
    )
    text_mode = text_mode and replacement_count == 1
    typed_value_count = sum(key in mutation for key in ("value", "value_base64"))
    typed_mode = isinstance(mutation.get("yaml_path"), str) and typed_value_count == 1
    if text_mode == typed_mode:
        raise YAMLMutationPathError(
            "mutation must declare exactly one of text replacement or YAML assignment"
        )
    if (
        text_mode
        and suffix.lower() in {".yml", ".yaml"}
        and not str(mutation.get("byte_level_reason", "")).strip()
    ):
        raise YAMLMutationPathError("YAML text replacement requires byte_level_reason")
    return "text" if text_mode else "yaml"


def typed_mutation_value(mutation: dict[str, Any]) -> Any:
    """Decode the single typed mutation value without exposing encoded strings."""

    if "value" in mutation and "value_base64" not in mutation:
        return mutation["value"]
    encoded = mutation.get("value_base64")
    if not isinstance(encoded, str) or "value" in mutation:
        raise YAMLMutationPathError("typed mutation value is absent or ambiguous")
    try:
        return base64.b64decode(encoded, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise YAMLMutationPathError("typed mutation value_base64 is invalid") from exc


@dataclass(frozen=True)
class YAMLMutationTarget:
    container: dict[str, Any] | list[Any]
    key: str | int
    value: Any


def _segments(path: str) -> list[str]:
    if not path or path.startswith(".") or path.endswith("."):
        raise YAMLMutationPathError("YAML mutation path is empty or malformed")
    segments: list[str] = []
    start = 0
    bracket_depth = 0
    for index, character in enumerate(path):
        if character == "[":
            bracket_depth += 1
        elif character == "]":
            bracket_depth -= 1
            if bracket_depth < 0:
                raise YAMLMutationPathError("YAML mutation path has unmatched brackets")
        elif character == "." and bracket_depth == 0:
            segments.append(path[start:index])
            start = index + 1
    if bracket_depth:
        raise YAMLMutationPathError("YAML mutation path has unmatched brackets")
    segments.append(path[start:])
    if any(not segment for segment in segments):
        raise YAMLMutationPathError("YAML mutation path contains an empty segment")
    return segments


def _step(current: Any, segment: str) -> Any:
    selector = _SELECTOR.fullmatch(segment)
    if selector is not None:
        if not isinstance(current, dict) or selector["key"] not in current:
            raise YAMLMutationPathError(f"missing YAML mapping key {selector['key']!r}")
        values = current[selector["key"]]
        if not isinstance(values, list):
            raise YAMLMutationPathError(f"selected YAML value {selector['key']!r} is not a list")
        matches = [
            item
            for item in values
            if isinstance(item, dict)
            and str(item.get(selector["field"])) == selector["value"]
        ]
        if len(matches) != 1:
            raise YAMLMutationPathError(
                f"YAML selector {segment!r} resolved {len(matches)} values"
            )
        return matches[0]
    if isinstance(current, list):
        if not segment.isdigit():
            raise YAMLMutationPathError(f"YAML list segment {segment!r} is not an index")
        index = int(segment)
        if index >= len(current):
            raise YAMLMutationPathError(f"YAML list index {index} is absent")
        return current[index]
    if not isinstance(current, dict) or segment not in current:
        raise YAMLMutationPathError(f"missing YAML mapping key {segment!r}")
    return current[segment]


def resolve_yaml_target(payload: Any, path: str) -> YAMLMutationTarget:
    """Resolve a mapping key or list index, including stable keyed list selectors."""

    segments = _segments(path)
    current = payload
    for segment in segments[:-1]:
        current = _step(current, segment)
    final = segments[-1]
    if _SELECTOR.fullmatch(final):
        raise YAMLMutationPathError("a YAML selector cannot be the assignment target")
    if isinstance(current, list):
        if not final.isdigit() or int(final) >= len(current):
            raise YAMLMutationPathError(f"YAML assignment index {final!r} is absent")
        key: str | int = int(final)
    elif isinstance(current, dict):
        if final not in current:
            raise YAMLMutationPathError(f"YAML assignment key {final!r} is absent")
        key = final
    else:
        raise YAMLMutationPathError("YAML assignment parent is not a container")
    return YAMLMutationTarget(current, key, current[key])


def assign_yaml_value(payload: Any, path: str, value: Any) -> Any:
    """Assign a value only after the typed path resolves exactly once."""

    target = resolve_yaml_target(payload, path)
    target.container[target.key] = value
    return target.value


def _mapping_value(node: Node, key: str) -> Node:
    if not isinstance(node, MappingNode):
        raise YAMLMutationPathError(f"YAML node containing {key!r} is not a mapping")
    matches = [value for raw_key, value in node.value if isinstance(raw_key, ScalarNode) and raw_key.value == key]
    if len(matches) != 1:
        raise YAMLMutationPathError(f"YAML mapping key {key!r} resolved {len(matches)} values")
    return matches[0]


def _node_step(current: Node, segment: str) -> Node:
    selector = _SELECTOR.fullmatch(segment)
    if selector is not None:
        values = _mapping_value(current, selector["key"])
        if not isinstance(values, SequenceNode):
            raise YAMLMutationPathError(f"selected YAML value {selector['key']!r} is not a list")
        matches = []
        for item in values.value:
            try:
                identity = _mapping_value(item, selector["field"])
            except YAMLMutationPathError:
                continue
            if isinstance(identity, ScalarNode) and identity.value == selector["value"]:
                matches.append(item)
        if len(matches) != 1:
            raise YAMLMutationPathError(
                f"YAML selector {segment!r} resolved {len(matches)} values"
            )
        return matches[0]
    if isinstance(current, SequenceNode):
        if not segment.isdigit() or int(segment) >= len(current.value):
            raise YAMLMutationPathError(f"YAML assignment index {segment!r} is absent")
        return current.value[int(segment)]
    return _mapping_value(current, segment)


def _yaml_value_node(source: str, path: str) -> Node:
    root = yaml.compose(source)
    if root is None:
        raise YAMLMutationPathError("YAML mutation source is empty")
    current = root
    for segment in _segments(path):
        current = _node_step(current, segment)
    return current


def _inline_yaml(value: Any) -> str:
    rendered = yaml.safe_dump(
        value, allow_unicode=True, default_flow_style=True, sort_keys=False, width=4096
    ).strip()
    return rendered.removesuffix("\n...")


def _replacement_yaml(value: Any, node: Node) -> str:
    if isinstance(node, ScalarNode) and isinstance(value, str) and node.style in {"'", '"'}:
        rendered = yaml.safe_dump(
            value,
            allow_unicode=True,
            default_flow_style=True,
            default_style=node.style,
            sort_keys=False,
            width=4096,
        ).strip()
        return rendered.removesuffix("\n...")
    if isinstance(node, (MappingNode, SequenceNode)) and node.flow_style is not True:
        rendered = yaml.safe_dump(
            value,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
            width=4096,
        ).rstrip()
        indentation = " " * node.start_mark.column
        return rendered.replace("\n", "\n" + indentation)
    return _inline_yaml(value)


def replace_yaml_value_bytes(source: str, path: str, value: Any) -> tuple[str, Any]:
    """Replace one typed YAML value without rewriting unrelated source bytes."""

    payload = yaml.safe_load(source)
    expected = copy.deepcopy(payload)
    previous = assign_yaml_value(expected, path, value)
    node = _yaml_value_node(source, path)
    original = source[node.start_mark.index : node.end_mark.index]
    separator = original[len(original.rstrip()) :]
    candidate = (
        source[: node.start_mark.index]
        + _replacement_yaml(value, node)
        + separator
        + source[node.end_mark.index :]
    )
    try:
        decoded = yaml.safe_load(candidate)
    except yaml.YAMLError as exc:
        raise YAMLMutationPathError(
            "typed YAML byte mutation did not preserve a valid document"
        ) from exc
    if decoded != expected:
        raise YAMLMutationPathError(
            "typed YAML byte mutation changed content outside its resolved target"
        )
    return candidate, previous

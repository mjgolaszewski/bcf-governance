"""Write sealed native diagnostic projections without application callbacks.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

import json
from enum import Enum
from types import GetSetDescriptorType
from typing import cast

from .native_protocol_slots import native_class_attribute, native_class_name


def _atom_text(value: object, representation: bool) -> str | None:
    kind = type(value)
    if (kind is str or kind is int or kind is float or kind is bool
            or kind is bytes or kind is complex or value is None):
        return repr(value) if representation else str(value)
    return None


def _enum_field(value: object, name: str) -> object:
    storage = cast(GetSetDescriptorType, Enum.__dict__['__dict__']).__get__(value)
    if type(storage) is not dict:
        raise TypeError('native enum metadata requires a native dictionary')
    result: object = None
    found = False
    for key, child in cast(dict[object, object], storage).items():
        if type(key) is not str:
            raise TypeError('native enum metadata keys must be plain strings')
        if key == name:
            found, result = True, child
    if not found:
        raise TypeError('native enum metadata is incomplete')
    return result


def _enum_text(value: object, representation: bool) -> str:
    kind = type(value)
    if type(kind) is not type(Enum) or not issubclass(kind, Enum):
        raise TypeError('CLI projections cannot invoke custom formatters')
    getter = native_class_attribute(kind, '__getattribute__')
    if not (getter is object.__getattribute__ or getter is str.__getattribute__
            or getter is int.__getattribute__ or getter is float.__getattribute__):
        raise TypeError('CLI enum projections cannot invoke custom getters')
    if native_class_attribute(kind, '__class__') is not object.__dict__['__class__']:
        raise TypeError('CLI enum projections cannot invoke a class property')
    if (native_class_attribute(kind, '_name_') is not None
            or native_class_attribute(kind, '_value_') is not None):
        raise TypeError('CLI enum projections cannot invoke metadata descriptors')
    name, raw = _enum_field(value, '_name_'), _enum_field(value, '_value_')
    if type(name) is not str or _atom_text(raw, True) is None:
        raise TypeError('CLI enum projections require native scalar metadata')
    class_name = native_class_name(kind)
    if representation:
        if native_class_attribute(kind, '__repr__') is not Enum.__repr__:
            raise TypeError('CLI enum projections cannot invoke custom repr')
        formatter = native_class_attribute(kind, '_value_repr_')
        expected = type(raw).__repr__
        if formatter is not None and formatter is not repr and formatter is not expected:
            raise TypeError('CLI enum values cannot invoke custom repr')
        return '<' + class_name + '.' + name + ': ' + cast(str, _atom_text(raw, True)) + '>'
    formatter = native_class_attribute(kind, '__format__')
    if formatter is Enum.__format__:
        stringifier = native_class_attribute(kind, '__str__')
        if stringifier is Enum.__str__:
            return class_name + '.' + name
        if (stringifier is str.__str__ or stringifier is int.__repr__
                or stringifier is float.__repr__):
            return cast(str, _atom_text(raw, False))
    if formatter is str.__format__ and issubclass(kind, str):
        return str.__str__(cast(str, value))
    if formatter is int.__format__ and issubclass(kind, int):
        return str(int.__int__(cast(int, value)))
    if formatter is float.__format__ and issubclass(kind, float):
        return str(float.__float__(cast(float, value)))
    raise TypeError('CLI enum projections cannot invoke custom formatting')


def _native_text(value: object, active: set[int], representation: bool = False) -> str:
    atom = _atom_text(value, representation)
    if atom is not None:
        return atom
    kind = type(value)
    if kind is not dict and kind is not list and kind is not tuple:
        return _enum_text(value, representation)
    marker = id(value)
    if marker in active:
        return '{...}' if kind is dict else '[...]' if kind is list else '(...)'
    active.add(marker)
    try:
        if kind is dict:
            parts = [_native_text(key, active, True) + ': ' + _native_text(child, active, True)
                     for key, child in cast(dict[object, object], value).items()]
            return '{' + ', '.join(parts) + '}'
        parts = [_native_text(child, active, True) for child in cast(list[object] | tuple[object, ...], value)]
        if kind is list:
            return '[' + ', '.join(parts) + ']'
        return '(' + ', '.join(parts) + (',' if len(parts) == 1 else '') + ')'
    finally:
        active.remove(marker)


def _copy_native_value(value: object, active: set[int]) -> object:
    kind = type(value)
    if kind is str or kind is int or kind is float or kind is bool or value is None:
        return value
    # JSON uses these immutable base values, never subclass formatting hooks.
    if issubclass(kind, str):
        return str.__str__(cast(str, value))
    if issubclass(kind, int):
        return int.__int__(cast(int, value))
    if issubclass(kind, float):
        return float.__float__(cast(float, value))
    if kind is not dict and kind is not list and kind is not tuple:
        raise TypeError('CLI projections require native JSON values')
    marker = id(value)
    if marker in active:
        raise ValueError('CLI projections cannot contain circular references')
    active.add(marker)
    try:
        if kind is dict:
            result: dict[str, object] = {}
            for key, child in cast(dict[object, object], value).items():
                if type(key) is not str:
                    raise TypeError('CLI projection keys must be native strings')
                result[key] = _copy_native_value(child, active)
            return result
        values = cast(list[object] | tuple[object, ...], value)
        copied = [_copy_native_value(child, active) for child in values]
        return tuple(copied) if kind is tuple else copied
    finally:
        active.remove(marker)


def snapshot_native_projection(payload: object) -> dict[str, object]:
    if type(payload) is not dict:
        raise TypeError('CLI projection payload must be a native dictionary')
    return cast(dict[str, object], _copy_native_value(payload, set()))


def write_native_projection(payload: object, output_format: str) -> None:
    """Declared stdout effect; seal every output before calling the sink."""
    if type(output_format) is not str:
        raise TypeError('CLI output format must be a native string')
    if output_format not in ('text', 'json'):
        raise ValueError('CLI output format must be text or json')
    if type(payload) is not dict:
        raise TypeError('CLI projection payload must be a native dictionary')
    if output_format == 'json':
        text = json.dumps(snapshot_native_projection(payload), sort_keys=True)
        print(text)
    else:
        lines = [_native_text(key, set()) + ': ' + _native_text(value, set())
                 for key, value in cast(dict[object, object], payload).items()]
        for line in lines:
            print(line)

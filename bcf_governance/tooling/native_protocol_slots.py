"""Read native type storage without invoking project attribute protocols.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

from collections.abc import Mapping
from types import GetSetDescriptorType
from typing import cast


def native_class_attribute(kind: type[object], name: str) -> object:
    if type(name) is not str:
        raise TypeError('native slot names must be plain strings')
    mro = cast(GetSetDescriptorType, type.__dict__['__mro__']).__get__(kind)
    for base in mro:
        namespace = cast(Mapping[object, object], cast(GetSetDescriptorType, type.__dict__['__dict__']).__get__(base))
        found = False
        result: object = None
        for key, value in namespace.items():
            if type(key) is not str:
                raise TypeError('native slot namespaces require plain string keys')
            if key == name:
                found, result = True, value
        if found:
            return result
    return None


def native_class_name(kind: type[object]) -> str:
    name = cast(GetSetDescriptorType, type.__dict__['__name__']).__get__(kind)
    if type(name) is not str:
        raise TypeError('native class names must be plain strings')
    return name

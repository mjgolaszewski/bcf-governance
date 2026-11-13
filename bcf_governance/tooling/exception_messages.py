"""Read native exception messages without invoking arbitrary formatters.

Copyright 2026 Michael Golaszewski. Licensed under the MIT License.
"""
from __future__ import annotations

from inspect import getattr_static
from types import GetSetDescriptorType, MemberDescriptorType
from typing import cast


def _native_scalar(value: object) -> bool:
    kind = type(value)
    return (kind is str or kind is bytes or kind is int or kind is float
            or kind is complex or kind is bool or kind is type(None))


def native_exception_message(error: BaseException) -> str:
    """Admit native formatters only after their entire input surface is native.

    Native args/OS fields are read through their actual storage descriptors;
    user properties, overridden getters and custom formatters are never called.
    """
    formatter = getattr_static(type(error), '__str__')
    if formatter is not BaseException.__str__ and formatter is not OSError.__str__:
        raise TypeError('exception requires an unqualified custom message formatter')
    arguments = cast(GetSetDescriptorType, BaseException.args).__get__(error)
    if any(not _native_scalar(value) for value in arguments):
        raise TypeError('exception message contains a non-native argument')
    if formatter is BaseException.__str__:
        return BaseException.__str__(error)
    for descriptor in (OSError.errno, OSError.strerror, OSError.filename, OSError.filename2,
                       getattr_static(OSError, 'winerror', None)):
        if descriptor is None:
            continue
        if not _native_scalar(cast(MemberDescriptorType, descriptor).__get__(error)):
            raise TypeError('OS exception message contains a non-native field')
    return OSError.__str__(error)

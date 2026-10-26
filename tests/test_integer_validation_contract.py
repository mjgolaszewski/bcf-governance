"""Keep Python integer coercion and failure semantics at the typed YAML boundary."""
from __future__ import annotations

from collections.abc import Callable

import pytest

from bcf_governance.tooling.governance_validation.common import (
    GovernanceValidationError,
    _require_non_negative_int,
    _require_positive_int,
)


class _IntValue:
    def __int__(self) -> int:
        return 7


class _IndexValue:
    def __index__(self) -> int:
        return 9


@pytest.mark.parametrize("value,expected", [
    ("12", 12), (b"13", 13), (bytearray(b"14"), 14),
    (memoryview(b"15"), 15), (3.9, 3), (True, 1),
    (_IntValue(), 7), (_IndexValue(), 9),
])
def test_existing_integer_coercions_remain_supported(value: object, expected: int) -> None:
    assert _require_positive_int(value, context="setting") == expected
    assert _require_non_negative_int(value, context="setting") == expected


@pytest.mark.parametrize("value", [None, object(), "not-an-integer", float("nan")])
@pytest.mark.parametrize("validator", [_require_positive_int, _require_non_negative_int])
def test_invalid_conversion_keeps_domain_error(value: object, validator: Callable[..., int]) -> None:
    with pytest.raises(GovernanceValidationError, match="setting must be"):
        validator(value, context="setting")


@pytest.mark.parametrize("validator", [_require_positive_int, _require_non_negative_int])
def test_overflow_remains_an_unwrapped_python_conversion_error(validator: Callable[..., int]) -> None:
    with pytest.raises(OverflowError):
        validator(float("inf"), context="setting")


def test_zero_and_negative_fraction_keep_original_threshold_semantics() -> None:
    assert _require_non_negative_int(False, context="setting") == 0
    assert _require_non_negative_int(-0.5, context="setting") == 0
    with pytest.raises(GovernanceValidationError, match="positive integer"):
        _require_positive_int(False, context="setting")
    with pytest.raises(GovernanceValidationError, match="non-negative integer"):
        _require_non_negative_int(-1, context="setting")

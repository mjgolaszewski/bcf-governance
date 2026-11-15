"""A shared scalar validator must preserve fresh receiver ownership, not purify effects."""
import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from tests.test_consumer_callback_contracts import OPERATION, inventory, witness


def test_actual_shared_capacity_validator_preserves_fresh_ledger(tmp_path):
    source = '"""Bounded attempt-local duplicate admission; never source coverage or publication authority."""\n\nfrom __future__ import annotations\n\nDEFAULT_SAVED_EXPORT_MAX_IDENTITIES = 100_000\n\n\ndef require_export_identity_capacity(max_identities: int) -> None:\n    """Apply the shared bounded budget to an actual attempt and durable queued intent."""\n    if type(max_identities) is not int or not 1 <= max_identities <= 1_000_000:\n        raise ValueError("export_identity_capacity")\n\n\nclass BatchExportIdentityLedger:\n    """Keep exact selected identities until the owning export attempt ends."""\n\n    def __init__(self, max_identities: int) -> None:\n        require_export_identity_capacity(max_identities)\n        self._capacity = max_identities\n        self._accounts: set[str | int] = set()\n        self._transactions: set[str | int] = set()\n        self._account_type: type[str] | type[int] | None = None\n        self._transaction_type: type[str] | type[int] | None = None\n        self._failed = False\n\n    @property\n    def account_count(self) -> int:\n        """Return identities observed, never a claim about unobserved source records."""\n        return len(self._accounts)\n\n    @property\n    def transaction_count(self) -> int:\n        """Return admitted transaction identities within this one attempt."""\n        return len(self._transactions)\n\n    def observe_account(self, identity: object) -> None:\n        """Reject duplicate account identity across every selected source member."""\n        self._observe(identity, transaction=False)\n\n    def observe_transaction(self, identity: object) -> None:\n        """Reject duplicate TransactionID across selected accounts and source members."""\n        self._observe(identity, transaction=True)\n\n    def require_nonempty(self) -> None:\n        """Reject failed attempts and empty selected-account populations before publication."""\n        if self._failed:\n            raise ValueError("export_identity_failed")\n        if not self._accounts:\n            raise ValueError("export_selection_empty")\n\n    def _observe(self, identity: object, *, transaction: bool) -> None:\n        """Apply one exact identity rule to the two real entity admission paths.\n\n        owning_context_or_shared_kernel: batch_exports\n        owning_layer: domain\n        rationale: Both account and transaction admission require the same bounded\n            exact-value rule, combined capacity and permanent attempt failure.\n        tests: test_batch_export_identity_ledger.py\n        """\n        if self._failed:\n            raise ValueError("export_identity_failed")\n        if type(identity) is int:\n            valid = -(1 << 63) <= identity < (1 << 63)\n        elif type(identity) is str:\n            try:\n                valid = 0 < len(identity.encode("utf-8")) <= 256\n            except UnicodeError:\n                valid = False\n        else:\n            valid = False\n        if not valid:\n            self._failed = True\n            raise ValueError("export_identity_value")\n        assert isinstance(identity, str | int)\n        observed = self._transactions if transaction else self._accounts\n        identity_type = self._transaction_type if transaction else self._account_type\n        if identity_type is not None and type(identity) is not identity_type:\n            self._failed = True\n            raise ValueError("export_identity_mixed_type")\n        if identity in observed:\n            self._failed = True\n            raise ValueError("export_identity_duplicate")\n        if len(self._accounts) + len(self._transactions) >= self._capacity:\n            self._failed = True\n            raise ValueError("export_identity_capacity")\n        observed.add(identity)\n        if transaction:\n            self._transaction_type = type(identity)\n        else:\n            self._account_type = type(identity)\n\n\ndef make_batch_export_identity_ledger(*, max_identities: int) -> BatchExportIdentityLedger:\n    """Sole construction site; caller must explicitly select the bounded attempt budget."""\n    return BatchExportIdentityLedger(max_identities)\n'
    path, facts = inventory(tmp_path, source + "\ndef read():\n ledger=BatchExportIdentityLedger(7)\n return 7\n")
    assert witness(path) == [7, 7]
    assert validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False) == (0, 0)


@pytest.mark.parametrize("helper, invocation", [
    ("def check(value):\n EVENTS.append(value)", "check(value)"),
    ("def check(value):\n EVENTS.append(value)", "check(self)"),
    ("def check(value):\n unknown(value)", "check(value)"),
])
def test_initializer_validator_does_not_hide_external_or_unknown_effects(tmp_path, helper, invocation):
    source = "EVENTS=[]\n" + helper + "\nclass Record:\n def __init__(self,value):\n  " + invocation + "\n  self.value=value\ndef read():\n Record(7)\n return 7\n"
    _, facts = inventory(tmp_path, source)
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False)


@pytest.mark.parametrize("declarations, expression", [
    ("def source():\n EVENTS.append(7)\n return 7", "type(source()) is not int or value < 1"),
    ("def type(value):\n EVENTS.append(7)\n return int", "type(value) is not int or value < 1"),
])
def test_native_type_guard_never_hides_operand_or_rebound_effects(tmp_path, declarations, expression):
    source = "EVENTS=[]\n" + declarations + "\ndef check(value):\n if " + expression + ":\n  raise ValueError('invalid')\nclass Record:\n def __init__(self,value):\n  check(value)\n  self.value=value\ndef read():\n Record(7)\n return len(EVENTS)\n"
    path, facts = inventory(tmp_path, source)
    assert witness(path) == [1, 2]
    with pytest.raises(SemanticOperationEffectError):
        validate_operation_effects(OPERATION, "consumer.py::read", facts, experimental_protocols=False)

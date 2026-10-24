"""Characterize the maintained typed-read gap without waiving unsafe dispatch."""

from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source,
    resolve_python_imports,
)


def _inventory(tmp_path: Path, source: str) -> dict:
    path = tmp_path / "service.py"
    path.write_text(source, encoding="utf-8")
    return resolve_python_imports(
        tmp_path, discover_python_source(tmp_path, files=[path]), (".",)
    )


def _operation() -> dict:
    return {
        "id": "maintained.read.v1",
        "authoritative_read": True,
        "allowed_mutation_ports": [],
        "allowed_authority_ports": [],
        "non_authoritative_output_effects": [],
    }


def test_typed_read_result_currently_carries_receiver_provenance(tmp_path: Path) -> None:
    """Reduced real handler shape; this is a limitation receipt, not acceptance."""
    inventory = _inventory(
        tmp_path,
        "from typing import Protocol\n"
        "class Manifest:\n"
        "    def to_public_payload(self) -> dict:\n"
        "        return {'status': 'ready'}\n"
        "class ReadPort(Protocol):\n"
        "    async def load_latest_manifest(self) -> Manifest | None: ...\n"
        "class Handler:\n"
        "    def __init__(self, store: ReadPort):\n"
        "        self._store = store\n"
        "    async def handle(self):\n"
        "        manifest = await self._store.load_latest_manifest()\n"
        "        return None if manifest is None else manifest.to_public_payload()\n",
    )
    handler = next(
        row for row in inventory["functions"]
        if row["symbol"] == "service.py::Handler.handle"
    )
    projection = next(
        row for row in handler["calls"] if row["call_name"] == "to_public_payload"
    )
    assert projection["method_dispatch"]["kind"] == "receiver_alias"
    assert projection["dispatch_port_eligible"] is False
    with pytest.raises(SemanticOperationEffectError, match="unresolved effect call path"):
        validate_operation_effects(_operation(), handler["symbol"], inventory)


def test_call_result_can_really_be_self_and_must_not_erase_provenance(tmp_path: Path) -> None:
    inventory = _inventory(
        tmp_path,
        "from pathlib import Path\n"
        "class Handler:\n"
        "    def identity(self):\n"
        "        return self\n"
        "    def handle(self):\n"
        "        result = self.identity()\n"
        "        return result.save()\n"
        "    def save(self):\n"
        "        Path('state').write_text('changed')\n",
    )
    with pytest.raises(SemanticOperationEffectError, match="unresolved effect call path"):
        validate_operation_effects(_operation(), "service.py::Handler.handle", inventory)

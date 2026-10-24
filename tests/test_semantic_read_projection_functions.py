"""Trace genuine domain projection bodies after a declared read boundary."""

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


def _inventory(tmp_path: Path, projection: str, nested: str = "return model.value") -> dict:
    source = tmp_path / "models.py"
    source.write_text(
        "from pathlib import Path\n"
        "class ReadModel:\n"
        "    value: str\n"
        "    def to_public_payload(self):\n"
        "        return project_public_payload(self)\n"
        "def project_public_payload(model):\n"
        f"    {projection}\n"
        "def project_value(model):\n"
        f"    {nested}\n",
        encoding="utf-8",
    )
    handler = tmp_path / "handlers.py"
    handler.write_text(
        "from models import project_public_payload\n"
        "class Handler:\n"
        "    async def handle(self):\n"
        "        model = await self.store.load()\n"
        "        return None if model is None else project_public_payload(model)\n",
        encoding="utf-8",
    )
    return resolve_python_imports(
        tmp_path, discover_python_source(tmp_path, files=[source, handler]), (".",)
    )


def _validate(inventory: dict, *, declared: bool = True) -> tuple[int, int]:
    return validate_operation_effects(
        {
            "id": "example.canonical-query.v1",
            "authoritative_read": True,
            "allowed_read_ports": ["handlers.py::self.store.load"] if declared else [],
            "allowed_mutation_ports": [],
            "allowed_authority_ports": [],
            "non_authoritative_output_effects": [],
        },
        "handlers.py::Handler.handle",
        inventory,
    )


def test_real_domain_projection_body_is_traced_after_read(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path, "return {'value': project_value(model)}")
    assert _validate(inventory) == (0, 0)
    handler = next(row for row in inventory["functions"] if row["symbol"] == "handlers.py::Handler.handle")
    assert any(call["called_symbol"] == "models.py::project_public_payload" for call in handler["calls"])


def test_functional_projection_does_not_waive_missing_read_boundary(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path, "return {'value': project_value(model)}")
    with pytest.raises(SemanticOperationEffectError, match="unresolved effect call path"):
        _validate(inventory, declared=False)


@pytest.mark.parametrize("body,diagnostic", [
    ("Path('state').write_text('changed')", "undeclared write effects"),
    ("publish_status()", "undeclared authority effects"),
])
def test_projection_body_cannot_hide_write_or_authority(tmp_path: Path, body: str, diagnostic: str) -> None:
    inventory = _inventory(tmp_path, body)
    with pytest.raises(SemanticOperationEffectError, match=diagnostic):
        _validate(inventory)


@pytest.mark.parametrize("body,diagnostic", [
    ("Path('state').write_text('changed')", "undeclared write effects"),
    ("publish_status()", "undeclared authority effects"),
])
def test_nested_projection_owner_cannot_hide_effect(tmp_path: Path, body: str, diagnostic: str) -> None:
    inventory = _inventory(tmp_path, "return {'value': project_value(model)}", nested=body)
    with pytest.raises(SemanticOperationEffectError, match=diagnostic):
        _validate(inventory)

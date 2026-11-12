"""Real source-consumer controls; constructor/type observations never grant SDK authority."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    _sdk_decoder_shape,
    validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source,
    resolve_python_imports,
)

PREFIX = "backend/src/demo/"
CONSTRUCTORS = {
    "plain": "class Owner:\n    def __init__(self, tenant, subject):\n        pass\n",
    "init-write": "class Owner:\n    def __init__(self, tenant, subject):\n        Path('state').write_text('changed')\n",
    "new-write": "class Owner:\n    def __new__(cls, tenant, subject):\n        Path('state').write_text('changed')\n        return object.__new__(cls)\n",
    "post-init-write": "class Owner:\n    def __post_init__(self):\n        Path('state').write_text('changed')\n",
    "setattr-write": "class Owner:\n    def __setattr__(self, name, value):\n        Path('state').write_text('changed')\n",
    "getattribute": "class Owner:\n    def __getattribute__(self, name):\n        return None\n",
    "property": "class Owner:\n    @property\n    def tenant(self):\n        return 'tenant'\n",
    "external-base": "class Owner(ExternalBase):\n    pass\n",
    "base-write": "class Base:\n    def __init__(self, tenant, subject):\n        Path('state').write_text('changed')\nclass Owner(Base):\n    pass\n",
    "decorated": "def model(cls):\n    return cls\n@model\nclass Owner:\n    pass\n",
    "metaclass": "class Meta(type):\n    pass\nclass Owner(metaclass=Meta):\n    pass\n",
    "lifecycle-rebound": "def custom(self, tenant, subject):\n    pass\nclass Owner:\n    __init__ = custom\n",
    "cycle": "class Base(Owner):\n    pass\nclass Owner(Base):\n    pass\n",
    "descriptor-binding": "class Owner:\n    field = custom_descriptor()\n",
}
CONTEXTS = ("local", "imported", "imported-alias", "declared-read")


def _inventory(tmp_path: Path, sources: dict[str, str]) -> dict:
    paths = []
    for relative, source in sources.items():
        path = tmp_path / (PREFIX + relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        paths.append(path)
    return resolve_python_imports(
        tmp_path, discover_python_source(tmp_path, files=sorted(paths)), ("backend/src",)
    )


def _operation(*, read_port: str | None = None) -> dict:
    return {
        "id": "source-obligations.query.v1",
        "allowed_mutation_ports": [],
        "allowed_authority_ports": [],
        "non_authoritative_output_effects": [],
        **({"authoritative_read": True, "allowed_read_ports": [read_port]} if read_port else {}),
    }


def _decoder(owner: str) -> str:
    return (
        "from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser\n"
        "class Observation:\n"
        f"    def read_principal(self, user: object) -> {owner} | None:\n"
        "        if not isinstance(user, AuthenticatedUser):\n"
        "            return None\n"
        "        token = user.access_token\n"
        "        tenant, subject = getattr(token, 'tenant_id', None), getattr(token, 'principal_id', None)\n"
        "        if not isinstance(tenant, str) or not isinstance(subject, str):\n"
        "            return None\n"
        "        try:\n"
        f"            return {owner}(tenant, subject)\n"
        "        except ValueError:\n"
        "            return None\n"
    )


@pytest.mark.parametrize("context", CONTEXTS)
@pytest.mark.parametrize("case", tuple(CONSTRUCTORS))
def test_decoder_construction_traces_source_or_keeps_missing_provenance(
    tmp_path: Path, context: str, case: str
) -> None:
    owner = "Alias" if context == "imported-alias" else "Owner"
    declaration = "from pathlib import Path\n" + CONSTRUCTORS[case]
    if context in {"imported", "imported-alias"}:
        sources = {
            "owner.py": declaration,
            "service.py": f"from demo.owner import Owner as {owner}\n" + _decoder(owner),
        }
        constructor = PREFIX + "owner.py::Owner"
    else:
        sources = {"service.py": declaration + _decoder(owner)}
        constructor = PREFIX + "service.py::Owner"
    inventory = _inventory(tmp_path, sources)
    module = ast.parse(sources["service.py"])
    observation_class = next(
        row for row in module.body if isinstance(row, ast.ClassDef) and row.name == "Observation"
    )
    assert _sdk_decoder_shape(observation_class.body[0]) == ("AuthenticatedUser", owner)
    entry = PREFIX + "service.py::Observation.read_principal"
    function = next(row for row in inventory["functions"] if row["symbol"] == entry)
    site = next(
        row for row in function["constructors"] if row["constructed_symbol"] == constructor
    )
    facts = site["construction_effect_observation"]
    assert facts["authority"] is False and facts["source_class_resolved"] is True
    assert constructor in facts["class_candidates"]
    operation = _operation(read_port=constructor if context == "declared-read" else None)
    if case == "plain":
        assert validate_operation_effects(operation, entry, inventory) == (0, 0)
    else:
        with pytest.raises(SemanticOperationEffectError, match="(construction|undeclared write)"):
            validate_operation_effects(operation, entry, inventory)
    # Shape, constructor and source-effect results never grant runtime SDK authority.
    assert all(
        row.get("typed_receiver_observation", {}).get("authority", False) is False
        for row in function["calls"]
    )


FLOW_BODIES = {
    "parameter": "def query(port: Port):\n    return port.read()\n",
    "alias": "def query(port: Port):\n    alias = port\n    return alias.read()\n",
    "union": "def query(port: Port | Other):\n    return port.read()\n",
    "optional": "def query(port: Port | None):\n    return port.read()\n",
    "factory": "def make() -> Port:\n    return Port()\ndef query():\n    return make().read()\n",
    "injected": "class Handler:\n    def __init__(self, port: Port):\n        self.port = port\n    def query(self):\n        return self.port.read()\n",
    "awaited": "async def make() -> Port:\n    return Port()\nasync def query():\n    return (await make()).read()\n",
    "destructured": "def query(port: Port):\n    alias, absent = port, None\n    return alias.read()\n",
    "method-factory": "class Factory:\n    def build(self) -> Port:\n        return Port()\ndef query(factory: Factory):\n    return factory.build().read()\n",
    "reassigned-union": "def query(port: Port):\n    alias = port\n    alias = Other()\n    return alias.read()\n",
}


@pytest.mark.parametrize("effect", ("pure", "write", "authority"))
@pytest.mark.parametrize("flow", tuple(FLOW_BODIES))
def test_typed_source_alternatives_add_effect_obligations(
    tmp_path: Path, flow: str, effect: str
) -> None:
    statement = {
        "pure": "return 1",
        "write": "Path('state').write_text('changed')",
        "authority": "publish_status()",
    }[effect]
    source = (
        "from pathlib import Path\n"
        "class Port:\n"
        f"    def read(self):\n        {statement}\n"
        "class Other:\n"
        "    def read(self):\n        return 2\n"
        + FLOW_BODIES[flow]
    )
    inventory = _inventory(tmp_path, {"service.py": source})
    entry = PREFIX + "service.py::" + ("Handler.query" if flow == "injected" else "query")
    function = next(row for row in inventory["functions"] if row["symbol"] == entry)
    read = next(row for row in function["calls"] if row["call_name"] == "read")
    facts = read["typed_receiver_observation"]
    assert facts["authority"] is False
    assert PREFIX + "service.py::Port.read" in facts["method_candidates"]
    operation = _operation(read_port=read["called_symbol"])
    if effect == "pure":
        assert validate_operation_effects(operation, entry, inventory) == (0, 0)
    else:
        with pytest.raises(SemanticOperationEffectError, match="undeclared (write|authority)"):
            validate_operation_effects(operation, entry, inventory)


def test_duplicate_class_population_retains_constructor_uncertainty(tmp_path: Path) -> None:
    inventory = _inventory(tmp_path, {
        "service.py": "class Owner:\n    pass\nclass Owner:\n    pass\ndef query():\n    return Owner()\n",
    })
    entry = PREFIX + "service.py::query"
    function = next(row for row in inventory["functions"] if row["symbol"] == entry)
    facts = function["constructors"][0]["construction_effect_observation"]
    assert "ambiguous_source_symbol_population" in facts["unresolved"]
    with pytest.raises(SemanticOperationEffectError, match="construction.*provenance"):
        validate_operation_effects(_operation(), entry, inventory)


@pytest.mark.parametrize("category", (
    "allowed_mutation_ports", "allowed_authority_ports",
    "non_authoritative_output_effects", "allowed_read_ports",
))
def test_neutral_targets_cannot_satisfy_required_port_reachability(
    tmp_path: Path, category: str
) -> None:
    inventory = _inventory(tmp_path, {
        "service.py": (
            "def emit_effect():\n    return None\n"
            "class Port:\n    def read(self):\n        return emit_effect()\n"
            "def query(port: Port):\n    return port.read()\n"
        ),
    })
    entry = PREFIX + "service.py::query"
    function = next(row for row in inventory["functions"] if row["symbol"] == entry)
    read = next(row for row in function["calls"] if row["call_name"] == "read")
    operation = _operation(read_port=read["called_symbol"])
    port = PREFIX + "service.py::emit_effect"
    operation[category] = [*(operation.get(category, [])), port]
    with pytest.raises(SemanticOperationEffectError, match="unreachable effect ports"):
        validate_operation_effects(operation, entry, inventory)

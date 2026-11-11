"""Construction observations cannot hide effects or grant runtime authority."""
from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError, validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source, resolve_python_imports,
)

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


@pytest.mark.parametrize("context", ("local", "imported", "imported-alias"))
@pytest.mark.parametrize("case", tuple(CONSTRUCTORS))
def test_source_constructor_obligations_are_consumed(tmp_path: Path, context: str, case: str):
    """Source-only proof; uncertain lifecycle mechanisms require conservative refusal."""
    prefix = "backend/src/demo/"
    name = "Alias" if context == "imported-alias" else "Owner"
    declaration = "from pathlib import Path\n" + CONSTRUCTORS[case]
    query = f"def query():\n    return {name}('tenant', 'subject')\n"
    if context == "local":
        sources = {"service.py": declaration + query}
        owner = prefix + "service.py::Owner"
    else:
        sources = {
            "owner.py": declaration,
            "service.py": f"from demo.owner import Owner as {name}\n" + query,
        }
        owner = prefix + "owner.py::Owner"
    files = []
    for relative, source in sources.items():
        path = tmp_path / (prefix + relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
        files.append(path)
    inventory = resolve_python_imports(
        tmp_path, discover_python_source(tmp_path, files=sorted(files)), ("backend/src",),
    )
    assert any(row["symbol"] == owner for row in inventory["classes"])
    if case.endswith("-write"):
        assert any(
            call.get("call_name") == "write_text"
            for function in inventory["functions"] for call in function["calls"]
        )
    operation = {
        "id": "source-construction.query.v1",
        "allowed_mutation_ports": [], "allowed_authority_ports": [],
        "non_authoritative_output_effects": [],
    }
    entry = prefix + "service.py::query"
    if case == "plain":
        assert validate_operation_effects(operation, entry, inventory) == (0, 0)
    else:
        with pytest.raises(
            SemanticOperationEffectError, match="(construction|undeclared write|unresolved)",
        ):
            validate_operation_effects(operation, entry, inventory)

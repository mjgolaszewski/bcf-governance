from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling import semantic_authority_contracts as contracts
from bcf_governance.tooling.semantic_operation_effects import (
    SemanticOperationEffectError,
    validate_operation_effects,
)
from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source,
    resolve_python_imports,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _inventory(tmp_path: Path, source: str) -> dict:
    path = tmp_path / "backend/src/demo/service.py"
    path.parent.mkdir(parents=True)
    path.write_text(source, encoding="utf-8")
    return resolve_python_imports(
        tmp_path,
        discover_python_source(tmp_path, files=sorted(tmp_path.rglob("*.py"))),
        ("backend/src",),
    )


def _operation(**values: object) -> dict:
    return {
        "id": "example.query.v1",
        "allowed_mutation_ports": [],
        "allowed_authority_ports": [],
        "non_authoritative_output_effects": [],
        **values,
    }


def _validate(
    inventory: dict, method: str, operation: dict | None = None
) -> tuple[int, int]:
    return validate_operation_effects(
        operation or _operation(),
        f"backend/src/demo/service.py::Service.{method}",
        inventory,
    )


def test_public_operation_rejects_write_hidden_by_same_instance_method(
    tmp_path: Path,
) -> None:
    """Issue #164's complete public contract path must fail for the real cause."""
    inventory = _inventory(
        tmp_path,
        "from pathlib import Path\n"
        "class Service:\n"
        "    def query(self):\n"
        "        return self._save()\n"
        "    def _save(self):\n"
        "        Path('state').write_text('changed')\n",
    )
    schema_dir = tmp_path / "schemas"
    schema_dir.mkdir()
    shutil.copyfile(
        REPO_ROOT / "schemas/application-operations.schema.json",
        schema_dir / "application-operations.schema.json",
    )
    entrypoint = "backend/src/demo/service.py::Service.query"
    (tmp_path / "operations.yml").write_text(
        yaml.safe_dump({"operations": {"query": entrypoint}}), encoding="utf-8"
    )
    payload = {
        "schema_version": "1.0",
        "document": {
            "kind": "application_operation_registry",
            "id": "fixture-operations",
            "version": "1.0.0",
            "status": "active",
            "path": "governance/application-operations.yml",
        },
        "populations": [
            {
                "id": "api",
                "adapter": "canonical_yaml_catalog",
                "source": "operations.yml",
                "symbol": "operations",
                "public_only": True,
                "catalog_path": ["operations"],
            }
        ],
        "operations": [
            {
                **_operation(),
                "population": "api",
                "population_key": "query",
                "family": "example",
                "bounded_context": "example",
                "entrypoints": [entrypoint],
                "semantic_kind": "query",
                "authoritative_read": True,
                "authoritative_mutation": False,
                "authority_conferral": False,
                "produces_projection": False,
                "model_callable": False,
            }
        ],
        "migrations": [],
    }

    with pytest.raises(contracts.SemanticAuthorityError, match="undeclared write effects"):
        contracts._validate_operations(tmp_path, payload, inventory)

    query = next(
        row for row in inventory["functions"] if row["symbol"] == entrypoint
    )
    assert query["calls"][0]["called_symbol"] == (
        "backend/src/demo/service.py::Service._save"
    )
    assert query["calls"][0]["dispatch_resolution"] == "exact_same_instance"


def test_same_instance_effects_preserve_pure_and_declared_port_boundaries(
    tmp_path: Path,
) -> None:
    inventory = _inventory(
        tmp_path,
        "from pathlib import Path\n"
        "def publish_status(): pass\n"
        "class Service:\n"
        "    def pure(self):\n"
        "        return self._read()\n"
        "    def _read(self):\n"
        "        return 1\n"
        "    def write(self):\n"
        "        return self._save()\n"
        "    def _save(self):\n"
        "        Path('state').write_text('changed')\n"
        "    def authority(self):\n"
        "        return self._publish()\n"
        "    def _publish(self):\n"
        "        publish_status()\n",
    )

    assert _validate(inventory, "pure") == (0, 0)
    with pytest.raises(SemanticOperationEffectError, match="undeclared write effects"):
        _validate(inventory, "write")
    with pytest.raises(SemanticOperationEffectError, match="undeclared authority effects"):
        _validate(inventory, "authority")

    helper = "backend/src/demo/service.py::Service._save"
    assert _validate(
        inventory,
        "write",
        _operation(allowed_mutation_ports=[helper]),
    ) == (1, 0)


def test_declared_component_port_is_reached_but_alias_cannot_conceal_source(
    tmp_path: Path,
) -> None:
    component_inventory = _inventory(
        tmp_path / "component",
        "class Service:\n"
        "    def query(self):\n"
        "        return self.store.save()\n",
    )
    component_port = (
        "backend/src/demo/service.py::self.store.save"
    )
    assert _validate(
        component_inventory,
        "query",
        _operation(allowed_mutation_ports=[component_port]),
    ) == (1, 0)

    alias_inventory = _inventory(
        tmp_path / "alias",
        "class Service:\n"
        "    def query(self):\n"
        "        alias = self\n"
        "        return alias._save()\n"
        "    def _save(self):\n"
        "        return 1\n",
    )
    with pytest.raises(SemanticOperationEffectError, match="unresolved effect call path"):
        _validate(
            alias_inventory,
            "query",
            _operation(
                allowed_mutation_ports=[
                    "backend/src/demo/service.py::alias._save"
                ]
            ),
        )


@pytest.mark.parametrize(
    "body",
    [
        "    def query(self):\n        alias = self\n        return alias._save()\n",
        "    def query(self, other):\n        self = other\n        return self._save()\n",
        "    def query(self):\n        save = self._save\n        return save()\n",
        "    @classmethod\n    def query(cls):\n        return cls._save()\n",
        "    def query(self):\n        return self.repository._save()\n",
        "    def query(self):\n        return self.missing()\n",
        "    def query(self):\n        return getattr(self, '_save')()\n",
        "    def query(self):\n        return type(self)._save(self)\n",
        "    def query(self):\n        return self.__class__._save(self)\n",
        "    def query(self):\n        return self.__dict__['_save']()\n",
        "    def query(self):\n        return self.__getattribute__('_save')()\n",
    ],
    ids=[
        "receiver-alias",
        "receiver-rebinding",
        "bound-method-alias",
        "class-dispatch",
        "chained-receiver",
        "missing-method",
        "dynamic-getattr",
        "dynamic-receiver-type",
        "dynamic-receiver-dunder-class",
        "dynamic-receiver-dunder-dict",
        "dynamic-receiver-dunder-getattribute",
    ],
)
def test_unsupported_same_instance_dispatch_fails_closed(
    tmp_path: Path, body: str
) -> None:
    inventory = _inventory(
        tmp_path,
        "class Service:\n"
        f"{body}"
        "    def _save(self):\n"
        "        return 1\n",
    )

    with pytest.raises(
        SemanticOperationEffectError, match=r"unresolved (?:dynamic|effect) call path"
    ):
        _validate(inventory, "query")


def test_super_and_override_dispatch_fail_closed_without_name_guessing(
    tmp_path: Path,
) -> None:
    inventory = _inventory(
        tmp_path,
        "class Base:\n"
        "    def inherited(self):\n"
        "        return self._save()\n"
        "    def _save(self):\n"
        "        return 1\n"
        "class Service(Base):\n"
        "    def query(self):\n"
        "        return super().inherited()\n"
        "    def _save(self):\n"
        "        return 2\n",
    )
    operation = _operation()

    for symbol in (
        "backend/src/demo/service.py::Base.inherited",
        "backend/src/demo/service.py::Service.query",
    ):
        with pytest.raises(
            SemanticOperationEffectError, match="unresolved effect call path"
        ):
            validate_operation_effects(operation, symbol, inventory)


def test_imported_base_identity_is_exact_and_dispatch_remains_closed(
    tmp_path: Path,
) -> None:
    base = tmp_path / "backend/src/demo/base.py"
    base.parent.mkdir(parents=True)
    base.write_text("class Base:\n    pass\n", encoding="utf-8")
    service = tmp_path / "backend/src/demo/service.py"
    service.write_text(
        "from demo.base import Base\n"
        "class Service(Base):\n"
        "    def query(self):\n"
        "        return self._read()\n"
        "    def _read(self):\n"
        "        return 1\n",
        encoding="utf-8",
    )
    inventory = resolve_python_imports(
        tmp_path,
        discover_python_source(tmp_path, files=[base, service]),
        ("backend/src",),
    )
    service_class = next(
        row
        for row in inventory["classes"]
        if row["symbol"] == "backend/src/demo/service.py::Service"
    )

    assert service_class["bases"][0]["called_symbol"] == (
        "backend/src/demo/base.py::Base"
    )
    with pytest.raises(SemanticOperationEffectError, match="unresolved effect call path"):
        _validate(inventory, "query")


def test_unconventional_instance_receiver_is_resolved_exactly(tmp_path: Path) -> None:
    inventory = _inventory(
        tmp_path,
        "class Service:\n"
        "    def query(instance):\n"
        "        return instance._read()\n"
        "    def _read(instance):\n"
        "        return 1\n",
    )

    assert _validate(inventory, "query") == (0, 0)


def test_same_named_methods_resolve_by_lexical_class_not_suffix(
    tmp_path: Path,
) -> None:
    inventory = _inventory(
        tmp_path,
        "class First:\n"
        "    def query(self):\n"
        "        return self._value()\n"
        "    def _value(self):\n"
        "        return 1\n"
        "class Service:\n"
        "    def query(self):\n"
        "        return self._value()\n"
        "    def _value(self):\n"
        "        return 2\n",
    )
    functions = {row["symbol"]: row for row in inventory["functions"]}

    assert functions["backend/src/demo/service.py::First.query"]["calls"][0][
        "called_symbol"
    ] == "backend/src/demo/service.py::First._value"
    assert functions["backend/src/demo/service.py::Service.query"]["calls"][0][
        "called_symbol"
    ] == "backend/src/demo/service.py::Service._value"


def test_async_same_instance_method_is_resolved_exactly(tmp_path: Path) -> None:
    inventory = _inventory(
        tmp_path,
        "class Service:\n"
        "    async def query(self):\n"
        "        return await self._read()\n"
        "    async def _read(self):\n"
        "        return 1\n",
    )

    assert _validate(inventory, "query") == (0, 0)


@pytest.mark.parametrize(
    "source",
    [
        (
            "def decorate(function):\n    return function\n"
            "@decorate\n"
            "class Service:\n"
            "    def query(self):\n        return self._read()\n"
            "    def _read(self):\n        return 1\n"
        ),
        (
            "def decorate(function):\n    return function\n"
            "class Service:\n"
            "    def query(self):\n        return self._read()\n"
            "    @decorate\n"
            "    def _read(self):\n        return 1\n"
        ),
        (
            "def decorate(function):\n    return function\n"
            "class Service:\n"
            "    @decorate\n"
            "    def query(self):\n        return 1\n"
        ),
        (
            "class Meta(type):\n    pass\n"
            "class Service(metaclass=Meta):\n"
            "    def query(self):\n        return self._read()\n"
            "    def _read(self):\n        return 1\n"
        ),
        (
            "class Service:\n"
            "    def __getattribute__(self, name):\n"
            "        return object.__getattribute__(self, name)\n"
            "    def query(self):\n        return self._read()\n"
            "    def _read(self):\n        return 1\n"
        ),
        (
            "class Service:\n"
            "    def configure(self, callback):\n        self._read = callback\n"
            "    def query(self):\n        return self._read()\n"
            "    def _read(self):\n        return 1\n"
        ),
        (
            "class Service:\n"
            "    def configure(self, callback):\n        setattr(self, '_read', callback)\n"
            "    def query(self):\n        return self._read()\n"
            "    def _read(self):\n        return 1\n"
        ),
    ],
    ids=[
        "class-decorator",
        "method-decorator",
        "entrypoint-decorator",
        "metaclass",
        "dynamic-attribute-lookup",
        "instance-method-rebinding",
        "setattr-method-rebinding",
    ],
)
def test_dynamic_method_ownership_fails_closed(tmp_path: Path, source: str) -> None:
    inventory = _inventory(tmp_path, source)

    with pytest.raises(SemanticOperationEffectError, match="unresolved effect call path"):
        _validate(inventory, "query")

from dataclasses import replace
from pathlib import Path

import pytest

from bcf_governance.tooling.semantic_ownership_inventory import (
    SemanticInventoryError,
    discover_python_source,
    resolve_python_imports,
)
from bcf_governance.tooling.semantic_ownership_registry import Registry, RegistryEntry
from bcf_governance.tooling.semantic_ownership_scan import evaluate_discovery


def _discover(root: Path, source: str) -> dict:
    (root / "owner.py").write_text("class PrincipalOwner:\n    pass\n")
    (root / "consumer.py").write_text(source)
    return resolve_python_imports(
        root, discover_python_source(root, sorted(root.glob("*.py"))), (".",)
    )


def _registry(authorized: str) -> Registry:
    return Registry(
        phase="P31", mode="declared_families_blocking",
        unresolved_dynamic_policy="fail_closed", authoritative_python_roots=("owner.py", "consumer.py"),
        generated_mirror_roots=(), raw={},
        entries=(RegistryEntry(
            semantic_id="principal.owner.v1", family="principal-owner",
            lifecycle="enforced", canonical_symbol="owner.py::PrincipalOwner",
            owner_symbol="owner.py::PrincipalOwner",
            authorized_constructors=frozenset({authorized}),
            authorized_delegates=frozenset(), blocking=True, raw={},
        ),),
    )


def test_existing_function_and_method_facts_remain_distinct(tmp_path: Path) -> None:
    value = _discover(tmp_path, "def factory(value: str) -> str:\n    return value.strip()\n"
                      "class Service:\n    def load(self):\n        return factory('ok')\n")
    rows = {row["symbol"]: row for row in value["functions"]}
    assert set(rows) == {"consumer.py::factory", "consumer.py::Service.load"}
    assert rows["consumer.py::factory"]["parameters"] == {"value": "str"}
    assert [call["call_name"] for call in rows["consumer.py::factory"]["calls"]] == ["strip"]
    assert rows["consumer.py::Service.load"]["calls"][0]["called_symbol"] == "consumer.py::factory"


@pytest.mark.parametrize("import_line,expression", [
    ("from owner import PrincipalOwner", "PrincipalOwner"),
    ("from owner import PrincipalOwner as principal", "principal"),
    ("import owner as identity", "identity.PrincipalOwner"),
])
def test_module_constructor_is_authorized_by_exact_initializer(
    tmp_path: Path, import_line: str, expression: str,
) -> None:
    value = _discover(tmp_path, f"{import_line}\nSERVICE_SESSION_OWNER = {expression}("
                      "'bdmcp-service', 'blackdiamond-shared', authority='local')\n")
    assert len(value["constructors"]) == 1
    fact = value["constructors"][0]
    assert fact["constructed_symbol"] == "owner.py::PrincipalOwner"
    assert fact["caller"] == "consumer.py::<module>.SERVICE_SESSION_OWNER"
    assert evaluate_discovery(value, _registry(fact["caller"]))["verdict"] == "conformant"
    negative = evaluate_discovery(value, _registry("consumer.py::some_other_factory"))
    assert any(row["kind"] == "unauthorized_constructor" for row in negative["violations"])


def test_unauthorized_module_constructor_cannot_hide_behind_authorized_one(tmp_path: Path) -> None:
    value = _discover(tmp_path, "from owner import PrincipalOwner\n"
                      "ALLOWED = PrincipalOwner('local')\nROGUE = PrincipalOwner('forged')\n")
    report = evaluate_discovery(value, _registry("consumer.py::<module>.ALLOWED"))
    failures = [row for row in report["violations"] if row["kind"] == "unauthorized_constructor"]
    assert [row["symbol"] for row in failures] == ["consumer.py::<module>.ROGUE"]


def test_class_initializer_and_function_default_are_not_function_body_calls(tmp_path: Path) -> None:
    value = _discover(tmp_path, "from owner import PrincipalOwner\n"
                      "class Service:\n    OWNER = PrincipalOwner('class')\n"
                      "def load(owner=PrincipalOwner('default')):\n"
                      "    return PrincipalOwner('body')\n")
    assert len(value["constructors"]) == 3
    function = next(row for row in value["functions"] if row["symbol"] == "consumer.py::load")
    assert len(function["constructors"]) == 1
    assert {row["caller"] for row in value["constructors"]} == {
        "consumer.py::Service.<class>.OWNER", "consumer.py::<module>.load", "consumer.py::load",
    }


def test_dynamic_initializer_is_blocking_unresolved(tmp_path: Path) -> None:
    value = _discover(tmp_path, "from owner import PrincipalOwner\n"
                      "OWNER = getattr(__import__('owner'), 'PrincipalOwner')('forged')\n")
    report = evaluate_discovery(value, _registry("consumer.py::<module>.OWNER"))
    assert report["verdict"] == "non_conformant"
    assert any(row["symbol"] == "consumer.py::<module>.OWNER"
               for row in report["unresolved_dynamic_flows"])


def test_local_alias_cannot_hide_a_material_constructor(tmp_path: Path) -> None:
    value = _discover(tmp_path, "from owner import PrincipalOwner\n"
                      "alias = PrincipalOwner\nOWNER = alias('forged')\n")
    assert value["constructors"][0]["constructed_symbol"] == "owner.py::PrincipalOwner"
    assert evaluate_discovery(value, _registry("consumer.py::other"))["verdict"] == "non_conformant"


def test_rebound_constructor_import_is_explicitly_unsupported(tmp_path: Path) -> None:
    with pytest.raises(SemanticInventoryError, match="rebound initializer import"):
        _discover(tmp_path, "from owner import PrincipalOwner\n"
                  "PrincipalOwner = factory()\nOWNER = PrincipalOwner('forged')\n")


def test_relative_import_initializer_is_resolved_under_declared_root(tmp_path: Path) -> None:
    package = tmp_path / "src/demo"
    package.mkdir(parents=True)
    (package / "owner.py").write_text("class PrincipalOwner: pass\n")
    (package / "consumer.py").write_text("from .owner import PrincipalOwner as owner\n"
                                         "SERVICE_OWNER = owner('local')\n")
    value = resolve_python_imports(tmp_path, discover_python_source(
        tmp_path, sorted(package.glob("*.py"))), ("src",))
    assert value["constructors"][0]["constructed_symbol"] == "src/demo/owner.py::PrincipalOwner"


def test_initializer_can_be_an_explicit_discovered_owner(tmp_path: Path) -> None:
    value = _discover(tmp_path, "from owner import PrincipalOwner\nOWNER = PrincipalOwner('local')\n")
    site = "consumer.py::<module>.OWNER"
    registry = _registry(site)
    entry = replace(registry.entries[0], owner_symbol=site)
    assert evaluate_discovery(value, replace(registry, entries=(entry,)))["verdict"] == "conformant"


def test_attribute_constructor_alias_is_not_lost(tmp_path: Path) -> None:
    value = _discover(tmp_path, "import owner as identity\n"
                      "constructor = identity.PrincipalOwner\nOWNER = constructor('forged')\n")
    assert value["constructors"][0]["constructed_symbol"] == "owner.py::PrincipalOwner"


def test_local_class_alias_is_not_lost(tmp_path: Path) -> None:
    value = _discover(tmp_path, "class LocalOwner: pass\nconstructor = LocalOwner\nOWNER = constructor()\n")
    assert any(row["constructed_symbol"] == "consumer.py::LocalOwner" for row in value["constructors"])


def test_conditional_unresolved_factory_is_not_silently_omitted(tmp_path: Path) -> None:
    value = _discover(tmp_path, "from owner import PrincipalOwner\n"
                      "if condition:\n    factory = PrincipalOwner\nOWNER = factory('forged')\n")
    assert any(row["kind"] == "unsupported_initializer_callee" for row in value["unresolved"])

import sys
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


def test_mixed_language_merge_preserves_initializer_ownership_facts(tmp_path: Path) -> None:
    from bcf_governance.tooling.semantic_source_discovery import merge_inventories
    value = _discover(tmp_path, "from owner import PrincipalOwner\nOWNER = PrincipalOwner('local')\n")
    combined = merge_inventories([value, {"files": [{"path": "view.ts", "sha256": "0" * 64}]}])
    assert combined["initializers"] == value["initializers"]
    assert evaluate_discovery(combined, _registry("consumer.py::other"))["verdict"] == "non_conformant"


def test_repeated_binding_requires_two_distinct_construction_authorizations(tmp_path: Path) -> None:
    value = _discover(tmp_path, "from owner import PrincipalOwner\n"
                      "OWNER = PrincipalOwner('allowed'); OWNER = PrincipalOwner('forged')\n")
    callers = [row["caller"] for row in value["constructors"]]
    assert len(set(callers)) == 2
    report = evaluate_discovery(value, _registry(callers[0]))
    assert [row["symbol"] for row in report["violations"]
            if row["kind"] == "unauthorized_constructor"] == [callers[1]]


def test_nested_class_initializers_keep_their_enclosing_identity(tmp_path: Path) -> None:
    value = _discover(tmp_path, "from owner import PrincipalOwner\n"
                      "class First:\n    class Inner:\n        OWNER = PrincipalOwner('one')\n"
                      "class Second:\n    class Inner:\n        OWNER = PrincipalOwner('two')\n")
    assert {row["caller"] for row in value["constructors"]} == {
        "consumer.py::First.Inner.<class>.OWNER", "consumer.py::Second.Inner.<class>.OWNER",
    }


def test_context_manager_and_match_guard_construction_are_not_omitted(tmp_path: Path) -> None:
    value = _discover(tmp_path, "from owner import PrincipalOwner\n"
                      "def factory(value):\n    yield value\n"
                      "with factory(PrincipalOwner('context')):\n    pass\n"
                      "match value:\n    case _ if PrincipalOwner('guard'):\n        pass\n")
    assert len([row for row in value["constructors"]
                if row["constructed_symbol"] == "owner.py::PrincipalOwner"]) == 2


def test_builtin_system_exit_keeps_nested_constructor_authorization(tmp_path: Path) -> None:
    value = _discover(tmp_path, "from owner import PrincipalOwner\n"
                      "raise SystemExit(PrincipalOwner('local'))\n")
    report = evaluate_discovery(value, _registry("consumer.py::other"))
    assert not any(row["kind"] == "unsupported_initializer_callee"
                   for row in report["violations"])
    assert any(row["kind"] == "unauthorized_constructor"
               for row in report["violations"])


def test_shadowed_system_exit_still_requires_constructor_authorization(tmp_path: Path) -> None:
    value = _discover(tmp_path, "from owner import PrincipalOwner as SystemExit\n"
                      "raise SystemExit('local')\n")
    report = evaluate_discovery(value, _registry("consumer.py::other"))
    assert any(row["kind"] == "unauthorized_constructor"
               for row in report["violations"])


def test_deferred_lambda_body_has_its_own_constructor_site(tmp_path: Path) -> None:
    value = _discover(tmp_path, "from owner import PrincipalOwner\n"
                      "FACTORY = lambda: PrincipalOwner('deferred')\n")
    assert not value["initializers"]
    assert len(value["constructors"]) == 1
    fact = value["constructors"][0]
    assert fact["caller"] == "consumer.py::<module>.FACTORY.<lambda@2.10>"
    report = evaluate_discovery(value, _registry("consumer.py::<module>.FACTORY"))
    assert any(row["kind"] == "unauthorized_constructor" for row in report["violations"])


def test_lambda_defaults_execute_in_enclosing_initializer(tmp_path: Path) -> None:
    value = _discover(tmp_path, "from owner import PrincipalOwner\n"
                      "FACTORY = lambda value=PrincipalOwner('eager'): value\n")
    assert value["constructors"][0]["caller"] == "consumer.py::<module>.FACTORY"


def test_immediately_invoked_lambda_remains_explicit_dynamic_dispatch(tmp_path: Path) -> None:
    value = _discover(tmp_path, "from owner import PrincipalOwner\n"
                      "OWNER = (lambda: PrincipalOwner('eager'))()\n")
    report = evaluate_discovery(value, _registry("consumer.py::other"))
    assert any(row["kind"] == "unsupported_initializer_dispatch"
               for row in report["violations"])
    assert any(row["kind"] == "unauthorized_constructor" for row in report["violations"])


@pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 695 syntax")
def test_plain_source_generic_constructor_retains_exact_owner_site(tmp_path: Path) -> None:
    (tmp_path / "owner.py").write_text("class PrincipalOwner[T]:\n    pass\n")
    (tmp_path / "consumer.py").write_text(
        "from owner import PrincipalOwner\nOWNER = PrincipalOwner[str]()\n")
    value = resolve_python_imports(tmp_path, discover_python_source(
        tmp_path, sorted(tmp_path.glob("*.py"))), (".",))
    report = evaluate_discovery(value, _registry("consumer.py::other"))
    assert [row["kind"] for row in report["violations"]] == ["unauthorized_constructor"]
    assert value["constructors"][0]["constructed_symbol"] == "owner.py::PrincipalOwner"


@pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 695 syntax")
@pytest.mark.parametrize("extra", [
    "    def __class_getitem__(cls, key):\n        return lambda: object()\n",
    "    __class_getitem__ = choose_factory()\n",
])
def test_source_generic_custom_subscription_stays_unresolved(tmp_path: Path, extra: str) -> None:
    (tmp_path / "owner.py").write_text("class PrincipalOwner[T]:\n" + extra)
    (tmp_path / "consumer.py").write_text(
        "from owner import PrincipalOwner\nOWNER = PrincipalOwner[str]()\n")
    value = resolve_python_imports(tmp_path, discover_python_source(
        tmp_path, sorted(tmp_path.glob("*.py"))), (".",))
    report = evaluate_discovery(value, _registry("consumer.py::<module>.OWNER"))
    assert any(row["kind"] == "unsupported_initializer_subscription"
               for row in report["violations"])


def test_fallback_imports_must_resolve_to_identical_source(tmp_path: Path) -> None:
    (tmp_path / "package").mkdir()
    (tmp_path / "package/__init__.py").write_text("")
    (tmp_path / "package/owner.py").write_text("def factory():\n    return object()\n")
    consumer = tmp_path / "package/consumer.py"
    consumer.write_text("try:\n    from .owner import factory\n"
                        "except ImportError:\n    from package.owner import factory\n"
                        "VALUE = factory()\n")
    value = resolve_python_imports(tmp_path, discover_python_source(
        tmp_path, sorted(tmp_path.rglob("*.py"))), (".",))
    row = next(row for row in value["initializers"] if row["symbol"].endswith(".VALUE"))
    assert row["calls"][0]["called_symbol"] == "package/owner.py::factory"
    assert not row["unresolved"]
    (tmp_path / "package/other.py").write_text("def factory():\n    return object()\n")
    consumer.write_text(consumer.read_text().replace("from package.owner", "from package.other"))
    with pytest.raises(SemanticInventoryError, match="ambiguous initializer fallback"):
        resolve_python_imports(tmp_path, discover_python_source(
            tmp_path, sorted(tmp_path.rglob("*.py"))), (".",))


def test_exact_yaml_metadata_method_alias_resolves_without_callable_name_grant(tmp_path: Path) -> None:
    value = _discover(tmp_path, "import yaml\nclass Loader(yaml.SafeLoader):\n    pass\n"
                      "configure = Loader.add_implicit_resolver\nconfigure('tag', None, [])\n")
    assert not value["unresolved"]
    assert any(call["called_symbol"] == "yaml::module.SafeLoader.add_implicit_resolver"
               for row in value["initializers"] for call in row["calls"])


def test_replaced_yaml_metadata_method_does_not_get_inherited_identity(tmp_path: Path) -> None:
    with pytest.raises(SemanticInventoryError, match="unsupported initializer source alias"):
        _discover(tmp_path, "import yaml\nclass Loader(yaml.SafeLoader):\n"
                  "    add_implicit_resolver = choose_factory()\n"
                  "configure = Loader.add_implicit_resolver\nconfigure('tag', None, [])\n")


def test_runtime_fallback_inside_standard_type_checking_else(tmp_path: Path) -> None:
    value = _discover(tmp_path, "from typing import TYPE_CHECKING\n"
                      "if TYPE_CHECKING:\n    from owner import PrincipalOwner\n"
                      "else:\n    try:\n        from owner import PrincipalOwner\n"
                      "    except ImportError:\n        from owner import PrincipalOwner\n"
                      "OWNER = PrincipalOwner('local')\n")
    assert not value["unresolved"]
    assert value["constructors"][0]["constructed_symbol"] == "owner.py::PrincipalOwner"


def test_exact_sibling_standalone_fallback_keeps_competing_root_refusal(tmp_path: Path) -> None:
    (tmp_path / "package").mkdir()
    (tmp_path / "package/__init__.py").write_text("")
    (tmp_path / "package/owner.py").write_text("def factory():\n    return object()\n")
    (tmp_path / "package/consumer.py").write_text(
        "try:\n    from .owner import factory\nexcept ImportError:\n"
        "    from owner import factory\nVALUE = factory()\n")
    value = resolve_python_imports(tmp_path, discover_python_source(
        tmp_path, sorted(tmp_path.rglob("*.py"))), (".",))
    row = next(row for row in value["initializers"] if row["symbol"].endswith(".VALUE"))
    assert row["calls"][0]["called_symbol"] == "package/owner.py::factory"
    (tmp_path / "owner.py").write_text("def factory():\n    return object()\n")
    with pytest.raises(SemanticInventoryError, match="ambiguous initializer fallback"):
        resolve_python_imports(tmp_path, discover_python_source(
            tmp_path, sorted(tmp_path.rglob("*.py"))), (".",))


def test_deferred_parameter_dispatch_remains_unresolved(tmp_path: Path) -> None:
    value = _discover(tmp_path, "FACTORY = lambda make: make()\n")
    report = evaluate_discovery(value, _registry("consumer.py::other"))
    assert any(row["kind"] == "unsupported_deferred_callable_dispatch"
               for row in report["violations"])


@pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 695 syntax")
def test_rebound_generic_decorator_cannot_prove_standard_subscription(tmp_path: Path) -> None:
    (tmp_path / "owner.py").write_text(
        "from dataclasses import dataclass\ndataclass = choose_decorator()\n"
        "@dataclass\nclass PrincipalOwner[T]:\n    pass\n")
    (tmp_path / "consumer.py").write_text(
        "from owner import PrincipalOwner\nOWNER = PrincipalOwner[str]()\n")
    value = resolve_python_imports(tmp_path, discover_python_source(
        tmp_path, sorted(tmp_path.glob("*.py"))), (".",))
    report = evaluate_discovery(value, _registry("consumer.py::<module>.OWNER"))
    assert any(row["kind"] == "unsupported_initializer_subscription"
               for row in report["violations"])


@pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 695 syntax")
def test_generic_module_hook_replacement_stays_unresolved(tmp_path: Path) -> None:
    (tmp_path / "owner.py").write_text("class PrincipalOwner[T]:\n    pass\n"
        "PrincipalOwner.__class_getitem__ = make_subscription\n")
    (tmp_path / "consumer.py").write_text(
        "from owner import PrincipalOwner\nOWNER = PrincipalOwner[str]()\n")
    value = resolve_python_imports(tmp_path, discover_python_source(
        tmp_path, sorted(tmp_path.glob("*.py"))), (".",))
    report = evaluate_discovery(value, _registry("consumer.py::<module>.OWNER"))
    assert any(row["kind"] == "unsupported_initializer_subscription"
               for row in report["violations"])


def test_redefined_type_checking_name_cannot_hide_executed_constructor(tmp_path: Path) -> None:
    value = _discover(tmp_path, "from typing import TYPE_CHECKING\n"
                      "from owner import PrincipalOwner\n"
                      "def TYPE_CHECKING():\n    pass\n"
                      "if TYPE_CHECKING:\n    OWNER = PrincipalOwner('local')\n")
    assert value["constructors"][0]["constructed_symbol"] == "owner.py::PrincipalOwner"


def test_standard_typing_generic_constructor_keeps_exact_owner_identity(tmp_path: Path) -> None:
    (tmp_path / "owner.py").write_text("from typing import Generic, TypeVar\n"
        "T = TypeVar('T')\nclass PrincipalOwner(Generic[T]):\n    pass\n")
    (tmp_path / "consumer.py").write_text(
        "from owner import PrincipalOwner\nOWNER = PrincipalOwner[str]()\n")
    value = resolve_python_imports(tmp_path, discover_python_source(
        tmp_path, sorted(tmp_path.glob("*.py"))), (".",))
    report = evaluate_discovery(value, _registry("consumer.py::other"))
    assert [row["kind"] for row in report["violations"]] == ["unauthorized_constructor"]

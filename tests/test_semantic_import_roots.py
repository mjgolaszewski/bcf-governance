from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from bcf_governance.tooling.semantic_ownership_inventory import (
    SemanticInventoryError,
    discover_python_source,
    resolve_python_imports,
)
from bcf_governance.tooling.semantic_ownership_registry import (
    Registry,
    RegistryEntry,
    SemanticOwnershipRegistryError,
    load_registry,
)
from bcf_governance.tooling.semantic_ownership_scan import evaluate_discovery


REPO_ROOT = Path(__file__).resolve().parents[1]


def _write(path: Path, source: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _inventory(root: Path, import_roots: tuple[str, ...]) -> dict[str, object]:
    files = sorted(root.rglob("*.py"))
    discovered = discover_python_source(root, files=files)
    return resolve_python_imports(root, discovered, import_roots)


def _registry(package: Path, *, authorized: str) -> Registry:
    canonical = f"{package.as_posix()}/domain.py::Record"
    entry = RegistryEntry(
        semantic_id="example.record.v1",
        family="record",
        lifecycle="enforced",
        canonical_symbol=canonical,
        owner_symbol=authorized,
        authorized_constructors=frozenset({authorized}),
        authorized_delegates=frozenset(),
        blocking=True,
        raw={},
    )
    return Registry(
        phase="P22",
        mode="declared_families_blocking",
        unresolved_dynamic_policy="fail_closed",
        authoritative_python_roots=(package.as_posix(),),
        generated_mirror_roots=(),
        entries=(entry,),
        raw={},
    )


def test_import_root_normalization_rejects_masked_unauthorized_constructor(
    tmp_path: Path,
) -> None:
    layouts = (
        (Path(), "."),
        (Path("src"), "src"),
        (Path("backend/src"), "backend/src"),
    )
    for prefix, import_root in layouts:
        root = tmp_path / (import_root.replace("/", "-") or "flat")
        package = prefix / "demo"
        _write(
            root / package / "domain.py",
            "class Record:\n    pass\n\ndef create():\n    return Record()\n",
        )
        _write(
            root / package / "client.py",
            "from demo.domain import Record\n\ndef rogue():\n    return Record()\n",
        )
        inventory = _inventory(root, (import_root,))
        owner = f"{package.as_posix()}/domain.py::create"
        result = evaluate_discovery(inventory, _registry(package, authorized=owner))

        assert result["verdict"] == "non_conformant"
        assert any(
            value["kind"] == "unauthorized_constructor"
            and value["symbol"] == f"{package.as_posix()}/client.py::rogue"
            for value in result["violations"]
        )


def test_authorized_imported_constructor_satisfies_coverage(tmp_path: Path) -> None:
    package = Path("backend/src/demo")
    _write(tmp_path / package / "domain.py", "class Record:\n    pass\n")
    _write(
        tmp_path / package / "factory.py",
        "from demo.domain import Record as ImportedRecord\n\n"
        "def create():\n    return ImportedRecord()\n",
    )
    inventory = _inventory(tmp_path, ("backend/src",))
    owner = f"{package.as_posix()}/factory.py::create"

    result = evaluate_discovery(inventory, _registry(package, authorized=owner))

    assert result["verdict"] == "conformant"
    assert result["registry_coverage"][0]["constructor_count"] == 1


def test_function_local_import_is_qualified_through_declared_root(
    tmp_path: Path,
) -> None:
    package = Path("src/demo")
    _write(
        tmp_path / package / "domain.py",
        "class Record:\n    pass\n\ndef create():\n    return Record()\n",
    )
    _write(
        tmp_path / package / "client.py",
        "def rogue():\n"
        "    from demo.domain import Record\n"
        "    return Record()\n",
    )
    inventory = _inventory(tmp_path, ("src",))
    owner = f"{package.as_posix()}/domain.py::create"
    registry = _registry(package, authorized=owner)

    result = evaluate_discovery(inventory, registry)

    assert any(
        value["kind"] == "unauthorized_constructor"
        and value["symbol"] == "src/demo/client.py::rogue"
        for value in result["violations"]
    )


def test_module_import_aliases_resolve_without_name_guessing(tmp_path: Path) -> None:
    package = Path("src/demo")
    _write(
        tmp_path / package / "domain.py",
        "class Record:\n    pass\n\ndef create():\n    return Record()\n",
    )
    _write(tmp_path / package / "other.py", "class Other:\n    pass\n")
    for name, statement, expression in (
        ("aliased", "import demo.domain as domain", "domain.Record()"),
        (
            "qualified",
            "import demo.domain\nimport demo.other",
            "demo.domain.Record()",
        ),
    ):
        _write(
            tmp_path / package / f"{name}.py",
            f"{statement}\n\ndef rogue():\n    return {expression}\n",
        )
    inventory = _inventory(tmp_path, ("src",))
    constructed = {
        value["caller"]: value["constructed_symbol"]
        for value in inventory["constructors"]
    }

    assert constructed["src/demo/aliased.py::rogue"] == "src/demo/domain.py::Record"
    assert constructed["src/demo/qualified.py::rogue"] == "src/demo/domain.py::Record"


def test_package_init_reexport_and_relative_alias_resolve_exact_source(
    tmp_path: Path,
) -> None:
    package = Path("src/demo")
    _write(
        tmp_path / package / "__init__.py",
        "from .domain import Record as PublicRecord\n",
    )
    _write(tmp_path / package / "domain.py", "class Record:\n    pass\n")
    _write(
        tmp_path / package / "factory.py",
        "from demo import PublicRecord as ImportedRecord\n\n"
        "def create():\n    return ImportedRecord()\n",
    )
    inventory = _inventory(tmp_path, ("src",))
    owner = f"{package.as_posix()}/factory.py::create"

    assert inventory["constructors"][0]["constructed_symbol"] == (
        "src/demo/domain.py::Record"
    )
    assert evaluate_discovery(inventory, _registry(package, authorized=owner))[
        "verdict"
    ] == "conformant"


def test_multiple_disjoint_import_roots_resolve_without_suffix_guessing(
    tmp_path: Path,
) -> None:
    _write(tmp_path / "backend/src/app/model.py", "class Record:\n    pass\n")
    _write(
        tmp_path / "backend/src/app/use.py",
        "from app.model import Record\n\ndef create():\n    return Record()\n",
    )
    _write(tmp_path / "tools/src/helper/model.py", "class ToolRecord:\n    pass\n")
    _write(tmp_path / "unlisted/observed.py", "class StillInventoried:\n    pass\n")
    inventory = _inventory(tmp_path, ("backend/src", "tools/src"))

    assert inventory["constructors"][0]["constructed_symbol"] == (
        "backend/src/app/model.py::Record"
    )
    assert {str(value["path"]) for value in inventory["files"]} == {
        "backend/src/app/model.py",
        "backend/src/app/use.py",
        "tools/src/helper/model.py",
        "unlisted/observed.py",
    }


def test_import_roots_reject_ambiguous_modules_and_overlaps(tmp_path: Path) -> None:
    _write(tmp_path / "one/demo/model.py", "class Record:\n    pass\n")
    _write(tmp_path / "two/demo/model.py", "class Record:\n    pass\n")
    discovered = discover_python_source(tmp_path, files=sorted(tmp_path.rglob("*.py")))

    with pytest.raises(SemanticInventoryError, match="ambiguous between"):
        resolve_python_imports(tmp_path, discovered, ("one", "two"))
    with pytest.raises(SemanticInventoryError, match="overlap"):
        resolve_python_imports(tmp_path, discovered, (".", "one"))


def test_import_roots_reject_missing_symlinked_and_empty_roots(tmp_path: Path) -> None:
    _write(tmp_path / "src/demo/model.py", "class Record:\n    pass\n")
    discovered = discover_python_source(tmp_path, files=sorted(tmp_path.rglob("*.py")))

    with pytest.raises(SemanticInventoryError, match="existing regular directory"):
        resolve_python_imports(tmp_path, discovered, ("missing",))
    (tmp_path / "empty").mkdir()
    with pytest.raises(SemanticInventoryError, match="contains no discovered"):
        resolve_python_imports(tmp_path, discovered, ("empty",))
    (tmp_path / "linked").symlink_to(tmp_path / "src", target_is_directory=True)
    with pytest.raises(SemanticInventoryError, match="existing regular directory"):
        resolve_python_imports(tmp_path, discovered, ("linked",))
    (tmp_path / "parent-link").symlink_to(tmp_path / "src", target_is_directory=True)
    with pytest.raises(SemanticInventoryError, match="existing regular directory"):
        resolve_python_imports(tmp_path, discovered, ("parent-link/demo",))


def test_registry_defaults_legacy_consumers_to_repository_import_root(
    tmp_path: Path,
) -> None:
    (tmp_path / "governance").mkdir()
    (tmp_path / "schemas").mkdir()
    payload = yaml.safe_load(
        (REPO_ROOT / "governance/canonical-representations.yml").read_text(
            encoding="utf-8"
        )
    )
    payload["source_authority"].pop("python_import_roots")
    (tmp_path / "governance/canonical-representations.yml").write_text(
        yaml.safe_dump(payload, sort_keys=False), encoding="utf-8"
    )
    (tmp_path / "schemas/canonical-representations.schema.json").write_bytes(
        (REPO_ROOT / "schemas/canonical-representations.schema.json").read_bytes()
    )

    assert load_registry(tmp_path).python_import_roots == (".",)


def test_registry_rejects_unsafe_import_root_before_source_evaluation(
    tmp_path: Path,
) -> None:
    (tmp_path / "governance").mkdir()
    (tmp_path / "schemas").mkdir()
    payload = yaml.safe_load(
        (REPO_ROOT / "governance/canonical-representations.yml").read_text(
            encoding="utf-8"
        )
    )
    payload["source_authority"]["python_import_roots"] = ["../outside"]
    (tmp_path / "governance/canonical-representations.yml").write_text(
        yaml.safe_dump(payload, sort_keys=False), encoding="utf-8"
    )
    (tmp_path / "schemas/canonical-representations.schema.json").write_bytes(
        (REPO_ROOT / "schemas/canonical-representations.schema.json").read_bytes()
    )

    with pytest.raises(SemanticOwnershipRegistryError, match="unsafe path"):
        load_registry(tmp_path)

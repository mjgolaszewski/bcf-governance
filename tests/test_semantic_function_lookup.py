"""Portable exact-resolver regression controls; no external corpus required."""
from pathlib import Path
from typing import Any

import pytest

from bcf_governance.tooling.semantic_operation_effects import (
    _FunctionLookup,
    _resolve_function,
)
from bcf_governance.tooling.semantic_ownership_inventory import (
    discover_python_source,
    resolve_python_imports,
)


@pytest.mark.parametrize("keys,queries", [
    (["src/a.py::f"], ["a.py::f", "other/a.py::f", "a.py::missing", "a::f", "a.ts::f", "no-separator"]),
    (["a.py::f", "src/a.py::f"], ["a.py::f", "elsewhere/a.py::f"]),
    (["one/a.py::f", "two/a.py::f"], ["a.py::f", "one/a.py::f", "two/a.py::f"]),
    (["src/a.py::Owner.method", "src/a.py::other"], ["a.py::Owner.method", "a.py::method", "a.py::other"]),
    (["prefix/a.py::f/inner.py::g"], ["a.py::f/inner.py::g", "inner.py::g"]),
    (["a.ts::f", "not-a-symbol", "x/a.py::f", "xa.py::f"], ["a.ts::f", "not-a-symbol", "a.py::f", "xa.py::f"]),
    (["/.py::f", ".py::f", "x/a.py::f::g"], [".py::f", "other/.py::f", "a.py::f::g"]),
    (["windows\\a.py::f", "a.py::f"], ["windows\\a.py::f", "other/a.py::f", "other/windows\\a.py::f"]),
    (["x/a.py::f", "x/aa.py::f", "x/a.py::fmore"], ["a.py::f", "a.py::fmore", "aa.py::f", "a.py::"]),
    ([], ["a.py::f", "a.ts::f", "", "::", ".py::"]),
])
def test_lookup_is_exact_original_oracle(keys: list[str], queries: list[str]) -> None:
    functions: dict[str, dict[str, Any]] = {key: {} for key in keys}
    lookup = _FunctionLookup(functions)
    for value in [*keys, *queries]:
        assert lookup.resolve(value) == _resolve_function(value, functions)


def test_new_inventory_never_reuses_old_snapshot() -> None:
    first: dict[str, dict[str, Any]] = {"one/a.py::f": {}}
    second: dict[str, dict[str, Any]] = {**first, "two/a.py::f": {}}
    old, new = _FunctionLookup(first), _FunctionLookup(second)
    assert old.resolve("a.py::f") == "one/a.py::f"
    assert new.resolve("a.py::f") is None
    assert old.resolve("a.py::f") == "one/a.py::f"


def test_native_discovery_lookup_uses_only_explicit_source(tmp_path: Path) -> None:
    package = tmp_path / "src" / "example"
    package.mkdir(parents=True)
    domain = package / "domain.py"
    client = package / "client.py"
    domain.write_text(
        "class Record:\n    pass\n\ndef create():\n    return Record()\n",
        encoding="utf-8",
    )
    client.write_text(
        "from example.domain import create\n\ndef run():\n    return create()\n",
        encoding="utf-8",
    )
    sentinel = tmp_path / "executed"
    excluded = tmp_path / "excluded.py"
    excluded.write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).touch()\n",
        encoding="utf-8",
    )
    inventory = resolve_python_imports(
        tmp_path,
        discover_python_source(tmp_path, files=[domain, client]),
        ("src",),
    )
    functions = {str(row["symbol"]): row for row in inventory["functions"]}
    owner = "src/example/domain.py::create"
    caller = "src/example/client.py::run"
    assert owner in functions and caller in functions
    assert any(call.get("called_symbol") == owner for call in functions[caller]["calls"])
    assert all(not symbol.startswith("excluded.py::") for symbol in functions)
    assert not sentinel.exists()
    lookup = _FunctionLookup(functions)
    assert lookup.resolve("domain.py::create") == owner
    assert lookup.resolve("client.py::run") == caller
    assert lookup.resolve("domain.py::missing") is None
    queries = [
        *functions,
        "domain.py::create",
        "client.py::run",
        "other/domain.py::create",
        "domain.py::missing",
        "domain.ts::create",
    ]
    for symbol in queries:
        assert lookup.resolve(symbol) == _resolve_function(symbol, functions)

"""Definition-time effects distinguish imports, script entry and deferred annotations."""
from pathlib import Path
from typing import Any

from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source


def discover(tmp_path: Path, source: str) -> dict[str, Any]:
    path = tmp_path / "subject.py"
    path.write_text(source)
    return discover_python_source(tmp_path, files=[path])


def test_script_guard_keeps_body_as_separate_execution_root(tmp_path: Path) -> None:
    found = discover(tmp_path, 'def work(): pass\nif __name__ == "__main__":\n    work()\n')
    calls = [(row["symbol"], call["call_name"]) for row in found["functions"] for call in row["calls"]]
    assert ("subject.py::<script-body>", "work") in calls
    assert ("subject.py::<module>", "work") not in calls


def test_script_guard_else_stays_import_time(tmp_path: Path) -> None:
    found = discover(tmp_path, 'def work(): pass\nif __name__ == "__main__":\n    pass\nelse:\n    work()\n')
    module = next(row for row in found["functions"] if row["symbol"] == "subject.py::<module>")
    assert any(call["call_name"] == "work" for call in module["calls"])


def test_rebound_module_name_cannot_discharge_guard(tmp_path: Path) -> None:
    found = discover(tmp_path, '__name__ = "__main__"\ndef work(): pass\nif __name__ == "__main__":\n    work()\n')
    module = next(row for row in found["functions"] if row["symbol"] == "subject.py::<module>")
    assert any(call["call_name"] == "work" for call in module["calls"])


def test_future_annotation_retains_deferred_obligation(tmp_path: Path) -> None:
    found = discover(tmp_path, 'from __future__ import annotations\ndef factory(): pass\ndef work(value: factory()): pass\n')
    deferred = next(row for row in found["functions"] if row["symbol"] == "subject.py::<deferred-annotations>")
    assert any(call["call_name"] == "factory" for call in deferred["calls"])
    assert deferred["definition_time_obligations"]
    assert deferred["unresolved"] == []
    assert not any(call["call_name"] == "factory" for row in found["functions"] if row["symbol"] == "subject.py::<module>" for call in row["calls"])

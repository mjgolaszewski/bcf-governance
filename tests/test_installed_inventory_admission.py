"""Installed metadata ambiguity must fail before an audit can be allocated."""
from types import SimpleNamespace
import pytest
from bcf_governance.tooling import dependency_assurance as owner


def distribution(name, version="1.0", requires=()):
    return SimpleNamespace(metadata={"Name": name}, version=version, requires=requires)


def collect(tmp_path, monkeypatch, rows):
    (tmp_path / "pyproject.toml").write_text('[build-system]\nrequires=["example-package>=1"]\n')
    (tmp_path / "requirements-governance.txt").write_text("")
    monkeypatch.setattr(owner.metadata, "distributions", lambda: iter(rows))
    return owner.collect_installed_inventory(tmp_path)


@pytest.mark.parametrize("name,version", [
    ("example-package", "1.0"), ("Example_Package", "1.0"), ("example.package", "2.0"),
])
def test_duplicate_installed_identity_cannot_be_overwritten(tmp_path, monkeypatch, name, version):
    with pytest.raises(owner.DependencyAssuranceError, match="ambiguous installed dependency"):
        collect(tmp_path, monkeypatch, [distribution("example-package"), distribution(name, version)])


@pytest.mark.parametrize("name", [None, "", 12, "not a package", "-invalid"])
def test_malformed_discovered_identity_cannot_be_silently_omitted(tmp_path, monkeypatch, name):
    with pytest.raises(owner.DependencyAssuranceError, match="installed dependency name"):
        collect(tmp_path, monkeypatch, [distribution("example-package"), distribution(name)])


def test_distinct_valid_canonical_inventory_is_deterministic(tmp_path, monkeypatch):
    rows = [distribution("Example_Package", requires=["other-dependency>=1"]), distribution("Other_Dependency")]
    first = collect(tmp_path, monkeypatch, rows)
    second = collect(tmp_path, monkeypatch, list(reversed(rows)))
    assert first == second
    assert {row["name"] for row in first.components} == {"example-package", "other-dependency"}

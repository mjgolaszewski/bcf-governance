"""A named installed package does not satisfy a contradictory requirement."""
import json
from types import SimpleNamespace

import pytest

from bcf_governance.tooling import dependency_assurance as owner


def distribution(name, version="1.0", requires=()):
    return SimpleNamespace(metadata={"Name":name},version=version,requires=requires)


def collect(tmp_path, monkeypatch, rows, roots=("example>=2",), kind="build"):
    encoded = json.dumps(list(roots))
    project = {
        "build":"[build-system]\nrequires=" + encoded + "\n",
        "project":"[project]\ndependencies=" + encoded + "\n",
        "optional":"[project.optional-dependencies]\ndev=" + encoded + "\n",
        "governance":"[build-system]\nrequires=[]\n",
    }[kind]
    (tmp_path/"pyproject.toml").write_text(project)
    (tmp_path/"requirements-governance.txt").write_text("\n".join(roots) if kind=="governance" else "")
    monkeypatch.setattr(owner.metadata,"distributions",lambda:iter(rows))
    return owner.collect_installed_inventory(tmp_path)


@pytest.mark.parametrize("kind", ["build","project","optional","governance"])
def test_each_declared_root_source_requires_its_actual_version(tmp_path, monkeypatch, kind):
    with pytest.raises(owner.DependencyAssuranceError,match="violates declared requirement"):
        collect(tmp_path,monkeypatch,[distribution("example")],kind=kind)


@pytest.mark.parametrize("roots", [("example>=2","example>=1"),("example>=1","example>=2")])
def test_repeated_root_constraint_is_checked_before_traversal_deduplication(tmp_path, monkeypatch, roots):
    with pytest.raises(owner.DependencyAssuranceError,match="violates declared requirement"):
        collect(tmp_path,monkeypatch,[distribution("example")],roots)


def test_transitive_requirement_checks_version_not_just_package_presence(tmp_path, monkeypatch):
    rows = [distribution("example","2.0",["child>=2"]),distribution("child")]
    with pytest.raises(owner.DependencyAssuranceError,match="violates declared requirement"):
        collect(tmp_path,monkeypatch,rows)


@pytest.mark.parametrize("roots", [("example>=2","parent>=1"),("parent>=1","example>=2")])
def test_already_selected_distribution_cannot_erase_transitive_conflict(tmp_path, monkeypatch, roots):
    rows = [distribution("example","2.0"),distribution("parent",requires=["example<2"])]
    with pytest.raises(owner.DependencyAssuranceError,match="violates declared requirement"):
        collect(tmp_path,monkeypatch,rows,roots)


def test_dependency_cycle_retains_incoming_constraint(tmp_path, monkeypatch):
    rows = [distribution("example","2.0",["child>=1"]),distribution("child",requires=["example>=3"])]
    with pytest.raises(owner.DependencyAssuranceError,match="violates declared requirement"):
        collect(tmp_path,monkeypatch,rows)


def test_requested_extra_cannot_erase_its_dependency_constraint(tmp_path, monkeypatch):
    rows = [distribution("example","2.0",["child>=2; extra == 'feature'"]),distribution("child")]
    with pytest.raises(owner.DependencyAssuranceError,match="violates declared requirement"):
        collect(tmp_path,monkeypatch,rows,("example[feature]>=2",))


@pytest.mark.parametrize("version", [None,True,12,""," 2.0","2.0 ","not-a-version"])
def test_malformed_selected_version_blocks_before_inventory_output(tmp_path, monkeypatch, version):
    with pytest.raises(owner.DependencyAssuranceError,match="installed dependency version"):
        collect(tmp_path,monkeypatch,[distribution("example",version)],("example",))


def test_malformed_transitive_requirement_is_a_typed_admission_failure(tmp_path, monkeypatch):
    rows = [distribution("example","2.0",["not a valid requirement !!!"])]
    with pytest.raises(owner.DependencyAssuranceError,match="installed dependency requirement"):
        collect(tmp_path,monkeypatch,rows)


@pytest.mark.parametrize("version", ["2.0","2.0+vendor.1","3.0rc1"])
def test_valid_installed_versions_preserve_exact_inventory_bytes(tmp_path, monkeypatch, version):
    rows = [distribution("Example",version)]
    first = collect(tmp_path,monkeypatch,rows,("example>=2","example<4"))
    second = collect(tmp_path,monkeypatch,rows,("example<4","example>=2"))
    assert first == second
    assert first.components == ({"type":"library","name":"example","version":version,
        "bom-ref":"pkg:pypi/example@"+version},)


def test_existing_inactive_transitive_marker_is_not_a_conflicting_constraint(tmp_path, monkeypatch):
    rows = [distribution("example","2.0",["child<1; python_version < '1.0'"]),distribution("child","2.0")]
    result = collect(tmp_path,monkeypatch,rows)
    assert [row["name"] for row in result.components] == ["example"]


def test_valid_extra_and_cyclic_closure_stays_deterministic(tmp_path, monkeypatch):
    rows = [distribution("example","2.0",["child>=2; extra == 'feature'"]),
        distribution("child","2.0",["example>=2"])]
    result = collect(tmp_path,monkeypatch,rows,("example[feature]>=2",))
    assert {row["name"] for row in result.components} == {"example","child"}
    assert len(result.dependencies) == 2


def test_moving_version_metadata_cannot_change_the_captured_inventory(tmp_path, monkeypatch):
    class MovingDistribution:
        metadata = {"Name":"example"}
        requires = []
        reads = 0

        @property
        def version(self):
            self.reads += 1
            return "2.0" if self.reads == 1 else "3.0"

    with pytest.raises(owner.DependencyAssuranceError,match="installed dependency version changed"):
        collect(tmp_path,monkeypatch,[MovingDistribution()],("example>=1","example>=1"))

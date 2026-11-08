"""Real source-discovery failure boundaries; original 93 cases remain unchanged."""
import os

import pytest

from test_architecture_native_inventory import commit
# Separate runtime namespaces below preserve the original93 module fixture.
from test_architecture_native_inventory import subject as subject


def test_real_unreadable_new_branch_is_refused_and_restored(subject, native):
    directory = subject / "src/unreadable_boundary"
    directory.mkdir()
    member = directory / "member.py"
    member.write_text("BOUNDARY_CONTROL = True\n")
    commit(subject)
    healthy = native.build_native_inventory(subject)
    assert "src/unreadable_boundary/member.py" in {row.path for row in healthy.members}
    directory.chmod(0)
    try:
        assert not os.access(directory, os.R_OK | os.X_OK), "host cannot enforce unreadable-directory control"
        with pytest.raises(native.ArchitectureInventoryError, match="production directory unreadable") as failure:
            native._admitted_production_paths(subject, healthy.policy)
        assert isinstance(failure.value.__cause__, PermissionError)
        assert str(failure.value.__cause__.filename) == str(directory)
    finally:
        directory.chmod(0o700)
    restored = native.build_native_inventory(subject)
    assert restored.members == healthy.members and restored.observation == healthy.observation
    assert restored.contexts == healthy.contexts


def test_real_directory_cannot_be_classified_as_a_file(subject, native):
    path = subject / "src/bootstrap"
    assert native._classify_production_entry(path, [path.name], []) == "directory"
    with pytest.raises(native.ArchitectureInventoryError, match="production directory classification disagrees"):
        native._classify_production_entry(path, [], [path.name])
    assert native._classify_production_entry(path, [path.name], []) == "directory"


def test_real_file_cannot_be_classified_as_a_directory(subject, native):
    path = subject / "src/loose.py"
    assert native._classify_production_entry(path, [], [path.name]) == "file"
    with pytest.raises(native.ArchitectureInventoryError, match="production file classification disagrees"):
        native._classify_production_entry(path, [path.name], [])
    assert native._classify_production_entry(path, [], [path.name]) == "file"


@pytest.fixture(scope="module", params=["canonical", "template", "packaged_template"])
def native(request):
    """Load the real runtimes independently of the original93 module fixture."""
    import importlib
    import importlib.util
    from pathlib import Path
    import sys

    repository = Path(__file__).resolve().parents[1]
    if request.param == "canonical":
        module = importlib.import_module("bcf_governance.tooling.architecture_native_inventory")
        expected = repository / "bcf_governance/tooling/architecture_native_inventory.py"
    else:
        relative = "template-repo" if request.param == "template" else "bcf_governance/pack/template-repo"
        runtime = repository / relative / "scripts/_bcf_runtime"
        name = "_architecture_boundary_" + request.param
        assert name not in sys.modules
        specification = importlib.util.spec_from_file_location(
            name, runtime / "__init__.py", submodule_search_locations=[str(runtime)])
        assert specification is not None and specification.loader is not None
        package = importlib.util.module_from_spec(specification)
        sys.modules[name] = package
        specification.loader.exec_module(package)
        module = importlib.import_module(name + ".architecture_native_inventory")
        expected = runtime / "architecture_native_inventory.py"
    assert Path(module.__file__).resolve() == expected
    return module

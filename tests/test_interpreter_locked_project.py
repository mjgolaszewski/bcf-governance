"""Selected locked-project contracts, independent of the installed environment."""
from pathlib import Path
import json
import subprocess
import sys

import pytest
import yaml

from bcf_governance.tooling.interpreter_environment import (
    InterpreterEnvironmentError,
    derive_interpreter_environment,
    materialize_interpreter_environment,
    verify_interpreter_environment_projection,
)


ENVIRONMENT = {
    "implementation_name": "cpython", "implementation_version": "3.14.5",
    "os_name": "posix", "platform_machine": "x86_64",
    "platform_release": "6.12.0", "platform_system": "Linux",
    "platform_version": "fixture", "python_full_version": "3.14.5",
    "platform_python_implementation": "CPython", "python_version": "3.14",
    "sys_platform": "linux",
}


def _fixture(root: Path, *, groups: list[str] | None = None) -> None:
    (root / "governance").mkdir()
    registry = {
        "interpreter_contract": {"locked_project": {
            "lockfile": "uv.lock", "dependency_groups": groups if groups is not None else ["dev"],
            "optional_extras": [], "marker_environment": ENVIRONMENT,
            "runtime_platform": {"sysconfig_platform": "linux-x86_64", "libc_name": "glibc", "libc_version": "2.36"},
        }},
        "gates": {},
    }
    (root / "governance/gate-contracts.yml").write_text(yaml.safe_dump(registry))
    (root / "pyproject.toml").write_text('''[project]
name = "fixture"
version = "1.0"
requires-python = ">=3.12"
dependencies = ["driver[binary]>=3,<4", "forked>=1,<5"]
[dependency-groups]
dev = ["pip>=26.2.2,<27", {include-group = "checks"}]
checks = ["pytest>=9,<10"]
identity-e2e = ["provider-only>=1"]
''')
    (root / "uv.lock").write_text('''version = 1
revision = 5
requires-python = ">=3.12"
resolution-markers = ["python_full_version < '3.13'", "python_full_version == '3.13.*'", "python_full_version == '3.14.*'", "python_full_version >= '3.15'"]
[[package]]
name = "fixture"
version = "1.0"
source = { editable = "." }
dependencies = [{name = "driver", extra = ["binary"]}, {name = "forked"}]
[package.dev-dependencies]
dev = [{name = "pip"}, {name = "pytest"}]
checks = [{name = "pytest"}]
identity-e2e = [{name = "provider-only"}]
[package.metadata]
requires-dist = [{name = "driver", extras = ["binary"], specifier = ">=3,<4"}, {name = "forked", specifier = ">=1,<5"}]
[package.metadata.requires-dev]
dev = [{name = "pip", specifier = ">=26.2.2,<27"}, {name = "pytest", specifier = ">=9,<10"}]
checks = [{name = "pytest", specifier = ">=9,<10"}]
identity-e2e = [{name = "provider-only", specifier = ">=1"}]
[[package]]
name = "driver"
version = "3.3.3"
source = { registry = "https://pypi.org/simple" }
[package.optional-dependencies]
binary = [{name = "driver-binary", marker = "sys_platform == 'linux'"}]
[[package]]
name = "driver-binary"
version = "3.3.3"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "forked"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
resolution-markers = ["python_full_version < '3.13'"]
[[package]]
name = "forked"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
resolution-markers = ["python_full_version == '3.13.*'"]
[[package]]
name = "forked"
version = "3.0"
source = { registry = "https://pypi.org/simple" }
resolution-markers = ["python_full_version == '3.14.*'"]
[[package]]
name = "forked"
version = "4.0"
source = { registry = "https://pypi.org/simple" }
resolution-markers = ["python_full_version >= '3.15'"]
[[package]]
name = "pip"
version = "26.2.2"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "pytest"
version = "9.0.3"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "provider-only"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
''')


def test_selected_lock_closure_expands_extras_and_pep735_groups(tmp_path: Path) -> None:
    _fixture(tmp_path)
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    assert plan.requirements == (
        "driver==3.3.3", "driver-binary==3.3.3", "forked==3.0",
        "pip==26.2.2", "pytest==9.0.3",
    )
    assert plan.source_kind == "locked_project"
    assert plan.requires_python == "==3.14.5"
    assert plan.pip_arguments() == plan.requirements
    assert not (tmp_path / ".artifacts").exists()


def test_unselected_provider_group_is_not_in_the_projection(tmp_path: Path) -> None:
    _fixture(tmp_path, groups=[])
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    assert plan.distribution_names == {"driver", "driver-binary", "forked", "pip"}


@pytest.mark.parametrize("version,pin", [("3.12.14", "1.0"), ("3.13.7", "2.0"), ("3.15.0", "4.0")])
def test_python_branch_selection_does_not_union_lock_forks(
    tmp_path: Path, version: str, pin: str,
) -> None:
    _fixture(tmp_path)
    path = tmp_path / "governance/gate-contracts.yml"
    registry = yaml.safe_load(path.read_text())
    env = registry["interpreter_contract"]["locked_project"]["marker_environment"]
    env.update(python_full_version=version, python_version=".".join(version.split(".")[:2]), implementation_version=version)
    path.write_text(yaml.safe_dump(registry))
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    assert [row for row in plan.requirements if row.startswith("forked==")] == ["forked==" + pin]


@pytest.mark.parametrize("floor", ["driver[binary]>=4,<5", "driver[binary]>=3.1,<4"], ids=["incompatible", "compatible"])
def test_changed_authored_floor_invalidates_stale_lock(tmp_path: Path, floor: str) -> None:
    _fixture(tmp_path)
    path = tmp_path / "pyproject.toml"
    path.write_text(path.read_text().replace("driver[binary]>=3,<4", floor))
    with pytest.raises(InterpreterEnvironmentError):
        derive_interpreter_environment(tmp_path)


def test_ambiguous_matching_lock_nodes_fail_closed(tmp_path: Path) -> None:
    _fixture(tmp_path)
    path = tmp_path / "uv.lock"
    path.write_text(path.read_text() + '''\n[[package]]
name = "driver"
version = "3.4.0"
source = { registry = "https://pypi.org/simple" }
''')
    with pytest.raises(InterpreterEnvironmentError):
        derive_interpreter_environment(tmp_path)


@pytest.mark.parametrize("defect", ["url", "cycle", "marker", "symlink", "extra", "format"])
def test_unsafe_or_incomplete_lock_inputs_fail_closed(tmp_path: Path, defect: str) -> None:
    _fixture(tmp_path)
    project, lock, registry = (tmp_path / name for name in ("pyproject.toml", "uv.lock", "governance/gate-contracts.yml"))
    if defect == "url":
        lock.write_text(lock.read_text().replace('registry = "https://pypi.org/simple"', 'git = "https://example.invalid/repo"'))
    elif defect == "cycle":
        project.write_text(project.read_text().replace('checks = ["pytest>=9,<10"]', 'checks = ["pytest>=9,<10", {include-group = "dev"}]'))
    elif defect == "marker":
        payload = yaml.safe_load(registry.read_text())
        payload["interpreter_contract"]["locked_project"]["marker_environment"].pop("platform_machine")
        registry.write_text(yaml.safe_dump(payload))
    elif defect == "symlink":
        original = lock.read_bytes()
        lock.unlink()
        target = tmp_path / "alternate.lock"
        target.write_bytes(original)
        lock.symlink_to(target)
    elif defect == "extra":
        lock.write_text(lock.read_text().replace('binary = [{name = "driver-binary", marker = "sys_platform == \'linux\'"}]', 'binary-other = []'))
    else:
        lock.write_text(lock.read_text().replace("version = 1\n", "version = true\n", 1))
    with pytest.raises(InterpreterEnvironmentError):
        derive_interpreter_environment(tmp_path)


def test_lock_bytes_are_reauthenticated_after_derivation(tmp_path: Path) -> None:
    _fixture(tmp_path)
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    lock = tmp_path / "uv.lock"
    lock.write_text(lock.read_text() + "\n# source changed\n")
    with pytest.raises(InterpreterEnvironmentError, match="changed after derivation"):
        verify_interpreter_environment_projection(plan)


@pytest.mark.parametrize("mismatch", ["python", "platform", "libc"])
def test_runtime_cohort_mismatch_blocks_before_allocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mismatch: str,
) -> None:
    from bcf_governance.tooling import interpreter_environment as owner
    from bcf_governance.tooling import interpreter_locked_project as locked

    _fixture(tmp_path)
    observed = {"markers": dict(ENVIRONMENT), "runtime_platform": {
        "sysconfig_platform": "linux-x86_64", "libc_name": "glibc", "libc_version": "2.36",
    }}
    if mismatch == "python":
        observed["markers"]["python_full_version"] = "3.12.14"
    elif mismatch == "platform":
        observed["markers"]["platform_machine"] = "aarch64"
    else:
        observed["runtime_platform"]["libc_version"] = "2.35"

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("mismatched cohort reached allocation")

    monkeypatch.setattr(owner, "select_materialization_base", lambda *_: Path(sys.executable))
    monkeypatch.setattr(owner, "allocate_execution_state", forbidden)
    monkeypatch.setattr(locked.subprocess, "run", lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, json.dumps(observed), ""))
    with pytest.raises(InterpreterEnvironmentError, match="runtime marker environment differs"):
        materialize_interpreter_environment(tmp_path, Path(sys.executable))
    assert not (tmp_path / ".artifacts").exists()


def test_runtime_312_cannot_silently_select_314_lock_cohort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from packaging.version import Version
    from bcf_governance.tooling import python_runtime_selection

    _fixture(tmp_path)
    monkeypatch.setattr(python_runtime_selection, "_python_runtime_version", lambda *_: Version("3.12.14"))
    with pytest.raises(InterpreterEnvironmentError, match="incompatible.*fallback minor"):
        materialize_interpreter_environment(tmp_path, Path(sys.executable))
    assert not (tmp_path / ".artifacts").exists()


def test_root_optional_extra_is_distinct_from_dependency_group(tmp_path: Path) -> None:
    _fixture(tmp_path, groups=[])
    project, lock, registry = (tmp_path / name for name in ("pyproject.toml", "uv.lock", "governance/gate-contracts.yml"))
    project.write_text(project.read_text().replace('[dependency-groups]', '[project.optional-dependencies]\ndev = ["provider-only>=1"]\n[dependency-groups]'))
    text = lock.read_text().replace('[package.dev-dependencies]', '[package.optional-dependencies]\ndev = [{name = "provider-only"}]\n[package.dev-dependencies]', 1)
    text = text.replace('{name = "forked", specifier = ">=1,<5"}]', '{name = "forked", specifier = ">=1,<5"}, {name = "provider-only", specifier = ">=1", marker = "extra == \'dev\'"}]', 1)
    lock.write_text(text)
    payload = yaml.safe_load(registry.read_text())
    payload['interpreter_contract']['locked_project']['optional_extras'] = ['dev']
    registry.write_text(yaml.safe_dump(payload))
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    assert 'provider-only==1.0' in plan.requirements
    assert 'pytest' not in plan.distribution_names


def test_locked_contract_has_a_canonical_profile_projection(tmp_path: Path) -> None:
    from bcf_governance.tooling.interpreter_contract_projection import project_interpreter_contract

    _fixture(tmp_path)
    registry = yaml.safe_load((tmp_path / 'governance/gate-contracts.yml').read_text())
    assert project_interpreter_contract({}, registry['interpreter_contract'], default_if_required=False) == registry['interpreter_contract']


@pytest.mark.parametrize("defect", [None, "extra", "missing", "version", "check"])
def test_installed_metadata_is_verification_only_and_must_match_selected_closure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, defect: str | None,
) -> None:
    from bcf_governance.tooling import interpreter_locked_project as locked

    _fixture(tmp_path)
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    observed = dict(row.split("==") for row in plan.requirements)
    if defect == "extra":
        observed["unbound-dependency"] = "99"
    elif defect == "missing":
        observed.pop("driver-binary")
    elif defect == "version":
        observed["driver"] = "3.3.2"

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if argv[1:] == ["-m", "pip", "check"]:
            return subprocess.CompletedProcess(argv, 1 if defect == "check" else 0, "", "")
        return subprocess.CompletedProcess(argv, 0, json.dumps(observed), "")

    monkeypatch.setattr(locked.subprocess, "run", run)
    if defect is None:
        locked.verify_locked_installed_closure(plan, Path(sys.executable))
    else:
        with pytest.raises(InterpreterEnvironmentError):
            locked.verify_locked_installed_closure(plan, Path(sys.executable))


def test_locked_install_disables_resolving_and_consumes_exact_tuple(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bcf_governance.tooling import interpreter_environment as owner
    from bcf_governance.tooling.runtime_capacity import EXECUTION_STATE_POLICY

    _fixture(tmp_path)
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    (tmp_path / "governance/ci-runtime.yml").write_text(yaml.safe_dump({
        "schema_version": "1.1", "runtime_root": ".artifacts/runtime", "minimum_free_bytes": 1,
        "maximum_owned_containers": 1,
        "database": {"storage": "repository_bind_mount", "relative_path": ".artifacts/runtime/database"},
        "cleanup": {"caller_globs": False, "daemon_global_prune": False,
                    "exact_owner_revalidation": True, "remove_anonymous_volumes": True},
        "execution_state": EXECUTION_STATE_POLICY,
    }))
    calls: list[list[str]] = []
    verified: list[object] = []

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[1:3] == ["-m", "venv"]:
            root = Path(argv[-1])
            (root / "bin").mkdir(parents=True)
            (root / "bin/python").symlink_to(sys.executable)
            (root / "pyvenv.cfg").write_text("home = fixture\n")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(owner, "select_materialization_base", lambda *_: Path(sys.executable))
    monkeypatch.setattr(owner, "verify_locked_runtime", lambda *_: None)
    monkeypatch.setattr(owner, "verify_locked_installed_closure", lambda value, *_: verified.append(value))
    monkeypatch.setattr(owner, "_installed_inventory", lambda *_: plan.rendered_requirements())
    monkeypatch.setattr(subprocess, "run", run)
    assert materialize_interpreter_environment(tmp_path, Path(sys.executable)).is_file()
    install = calls[1]
    assert install[1:4] == ["-m", "pip", "install"]
    assert install[install.index("--disable-pip-version-check") + 1:] == ["--no-deps", *plan.requirements]
    assert verified == [plan]


@pytest.mark.parametrize("mismatch", ["platform", "libc"])
def test_existing_interpreter_probe_rejects_wrong_locked_cohort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mismatch: str,
) -> None:
    from bcf_governance.tooling import interpreter_environment as owner

    _fixture(tmp_path)
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    versions = dict(row.split("==") for row in plan.requirements)
    runtime = {"markers": dict(ENVIRONMENT), "runtime_platform": {
        "sysconfig_platform": "linux-x86_64", "libc_name": "glibc", "libc_version": "2.36",
    }}
    if mismatch == "platform":
        runtime["markers"]["platform_machine"] = "aarch64"
    else:
        runtime["runtime_platform"]["libc_version"] = "2.35"

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        code = argv[3] if argv[1:3] == ["-I", "-c"] else ""
        value = runtime if "sysconfig.get_platform" in code else versions
        return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(InterpreterEnvironmentError, match="runtime marker environment differs"):
        owner.probe_interpreter_environment(plan, Path(sys.executable))
    assert not (tmp_path / ".artifacts").exists()


def test_existing_interpreter_probe_accepts_exact_locked_cohort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from bcf_governance.tooling import interpreter_environment as owner

    _fixture(tmp_path)
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    versions = dict(row.split("==") for row in plan.requirements)
    runtime = {"markers": dict(ENVIRONMENT), "runtime_platform": {
        "sysconfig_platform": "linux-x86_64", "libc_name": "glibc", "libc_version": "2.36",
    }}

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        code = argv[3] if argv[1:3] == ["-I", "-c"] else ""
        value = runtime if "sysconfig.get_platform" in code else versions
        return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

    monkeypatch.setattr(subprocess, "run", run)
    assert owner.probe_interpreter_environment(plan, Path(sys.executable)) == versions
    assert not (tmp_path / ".artifacts").exists()


@pytest.mark.parametrize("configuration", ["source_override", "lock_options"])
def test_unqualified_resolution_configuration_is_not_silently_ignored(
    tmp_path: Path, configuration: str,
) -> None:
    _fixture(tmp_path)
    if configuration == "source_override":
        path = tmp_path / "pyproject.toml"
        path.write_text(path.read_text() + '\n[tool.uv.sources]\ndriver = {git = "https://example.invalid/driver"}\n')
    else:
        path = tmp_path / "uv.lock"
        path.write_text(path.read_text() + '\n[options]\nexclude-newer = "2026-01-01T00:00:00Z"\n')
    with pytest.raises(InterpreterEnvironmentError, match="unsupported.*configuration"):
        derive_interpreter_environment(tmp_path)


def test_authoring_uv_version_pin_does_not_change_selected_graph(tmp_path: Path) -> None:
    _fixture(tmp_path)
    path = tmp_path / "pyproject.toml"
    path.write_text(path.read_text() + '\n[tool.uv]\nrequired-version = "==0.13.4"\n')
    plan = derive_interpreter_environment(tmp_path)
    assert plan is not None
    assert 'driver-binary==3.3.3' in plan.requirements

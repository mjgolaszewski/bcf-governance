"""Installed evaluator owns source admission with no source SDK available."""
import json
import subprocess
import sys

from test_installed_evidence_storage import (
    _environment, _record, installed_consumer, isolated_python,
)


PROBE = r'''import importlib.util, json, subprocess, sys
from pathlib import Path
assert importlib.util.find_spec('bcf_governance') is None
root = Path.cwd()
sys.path.insert(0, str(root / 'scripts'))
from _bcf_runtime.governance_validation import preflight_distribution as owner
assert Path(owner.__file__).resolve().is_relative_to(root)
assert Path(owner.validate_package_data_contract.__globals__['__file__']).resolve().is_relative_to(
    root / 'scripts/_bcf_runtime')
project_python = Path(sys.argv[1])
fixture = root / 'framework-fixture'
fixture.mkdir()
project = '[build-system]\nrequires=["setuptools"]\nbuild-backend="setuptools.build_meta"\n'
project += '[project]\nname="fixture"\nversion="1.0"\n[tool.setuptools]\npackages=[]\n'
project += '[tool.setuptools.package-data]\nbcf_governance=["pack/template-repo/**/*"]\n'
# Convert explicit serialized newlines in this fixture data, not executable code.
project = project.replace('\\n', '\n')
files = {
    'pyproject.toml': project,
    'MANIFEST.in': 'global-exclude *\n',
    'owned.txt': 'exact\n',
    'bcf_governance/pack/template-repo/owned.txt': 'template\n',
    '.github/scripts/release_source_inventory.py':
        "from pathlib import Path\nPath('candidate-executed').touch()\n"
        "print('{\"authority\":false,\"built_bytes_verified\":false,"
        "\"scope\":\"static_source_declaration_coverage\",\"file_count\":1}')\n",
}
for name, value in files.items():
    path = fixture / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.replace('\\n', '\n'))
subprocess.run(['git', 'init', '-q', str(fixture)], check=True)
subprocess.run(['git', '-C', str(fixture), 'add', '.'], check=True)
availability = subprocess.run([str(project_python), '-I', '-c',
    "import importlib.util; assert importlib.util.find_spec('bcf_governance') is None; import setuptools"],
    cwd=fixture, capture_output=True, text=True)
assert availability.returncode == 0, availability.stderr
project_path = fixture / 'pyproject.toml'
complete_project = project_path.read_bytes()
project_path.write_text(project_path.read_text().split('[tool.setuptools.package-data]')[0])
try:
    owner.validate_source_distribution(fixture, python_executable=Path('/unused/project-python'))
except ValueError as error:
    assert 'package data excludes runtime assets' in str(error)
else:
    raise AssertionError('installed runtime allocated interpreter before metadata rejection')
project_path.write_bytes(complete_project)
try:
    owner.validate_source_distribution(fixture, python_executable=project_python)
except ValueError as error:
    assert 'omits tracked source' in str(error)
else:
    raise AssertionError('installed runtime accepted forged candidate coverage')
assert not (fixture / 'candidate-executed').exists()
(fixture / 'MANIFEST.in').write_text('global-include *\n'.replace('\\n', '\n'))
(fixture / '.github/scripts/release_source_inventory.py').write_text(
    "raise SystemExit('candidate evaluator must not run')\n".replace('\\n', '\n'))
shadow = "from pathlib import Path\nPath('shadow-executed').touch()\nraise RuntimeError('shadow imported')\n"
for name in ['setuptools.py', 'sitecustomize.py']:
    (fixture / name).write_text(shadow.replace('\\n', '\n'))
subprocess.run(['git', '-C', str(fixture), 'add', '.'], check=True)
result = owner.validate_source_distribution(fixture, python_executable=project_python)
assert result == {'authority': False, 'built_bytes_verified': False,
                  'scope': 'static_source_declaration_coverage', 'file_count': 7,
                  'applicable': True}
assert not (fixture / 'candidate-executed').exists()
assert not (fixture / 'shadow-executed').exists()
print(json.dumps({'source_sdk_absent': True, 'project_sdk_absent': True,
                  'missing_resource_metadata_rejected_before_project_interpreter': True,
                  'forged_report_rejected': True, 'candidate_and_shadow_not_executed': True,
                  'valid_file_count': result['file_count']}, sort_keys=True))
'''
compile(PROBE, 'installed-source-admission-probe', 'exec')


def test_installed_source_query_uses_runtime_owner_and_selected_project_interpreter(
    installed_consumer, isolated_python,
):
    result = subprocess.run(
        [str(isolated_python), '-I', '-c', PROBE, sys.executable],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True,
    )
    assert result.returncode == 0, _record(result)
    assert json.loads(result.stdout) == {
        'source_sdk_absent': True, 'project_sdk_absent': True,
        'missing_resource_metadata_rejected_before_project_interpreter': True,
        'forged_report_rejected': True, 'candidate_and_shadow_not_executed': True,
        'valid_file_count': 7,
    }


def test_installed_source_discovery_never_executes_repository_fsmonitor(
    installed_consumer, isolated_python,
):
    from semantic_typescript_fixture import compiler
    node_fixture = installed_consumer / 'native-typescript-fixture'
    engine = compiler(node_fixture)
    (node_fixture / 'src').mkdir()
    (node_fixture / 'src/value.ts').write_text('export function value(): number { return 1; }\n')
    code = r'''import importlib.util, json, subprocess, sys, os, fcntl
from pathlib import Path
assert importlib.util.find_spec('bcf_governance') is None
installed = Path.cwd()
sys.path.insert(0, str(installed / 'scripts'))
from _bcf_runtime import semantic_source_paths as paths
from _bcf_runtime import evidence_process_supervisor as custody
from _bcf_runtime.semantic_ownership_inventory import discover_python_source
from _bcf_runtime import test_manifests, semantic_ownership_typescript as typescript
from _bcf_runtime.governance_validation import preflight_distribution, source_inventory
from _bcf_runtime.governance_validation import preflight_repository_context as repository_context, ci_state_matrix
assert Path(paths.__file__).resolve().is_relative_to(installed / 'scripts/_bcf_runtime')
fixture = installed / 'git-discovery-fixture'
fixture.mkdir()
def git(*args):
    return subprocess.check_output(['git', *args], cwd=fixture, text=True).strip()
git('init', '-q')
git('config', 'user.name', 'Installed Fixture')
git('config', 'user.email', 'installed@example.invalid')
(fixture / 'source.py').write_text("raise RuntimeError('candidate source executed')\n")
git('add', '.')
git('commit', '-qm', 'fixture')
identity = {'commit_sha': git('rev-parse', 'HEAD'), 'tree_sha': git('rev-parse', 'HEAD^{tree}')}
marker = installed / 'candidate-fsmonitor-executed'
monitor = installed / 'candidate-fsmonitor'
monitor.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\nprintf "token\\0"\n')
monitor.chmod(0o700)
git('config', 'core.fsmonitor', str(monitor))
assert paths.candidate_source_files(fixture, ('*.py',), label='Python', error=ValueError) == [fixture / 'source.py']
for subject in (None, identity):
    result = discover_python_source(fixture, source_subject=subject)
    assert [row['path'] for row in result['files']] == ['source.py']
assert Path(custody.__file__).resolve().is_relative_to(installed / 'scripts/_bcf_runtime')
for module in (test_manifests, typescript, preflight_distribution, source_inventory, repository_context, ci_state_matrix):
    assert Path(module.__file__).resolve().is_relative_to(installed / 'scripts/_bcf_runtime')
project_python = Path(sys.argv[1])
engine = json.loads(sys.argv[2])
node_fixture = Path(sys.argv[3])
distribution = installed / 'native-distribution-fixture'
distribution.mkdir()
project_lines = ['[build-system]', 'requires=["setuptools"]', 'build-backend="setuptools.build_meta"',
                 '[project]', 'name="fixture"', 'version="1.0"', '[tool.setuptools]', 'packages=[]',
                 '[tool.setuptools.package-data]', 'bcf_governance=["pack/template-repo/**/*"]']
files = {'pyproject.toml': chr(10).join(project_lines)+chr(10),
         'MANIFEST.in': 'global-include *'+chr(10), 'owned.txt': 'owned'+chr(10),
         'bcf_governance/pack/template-repo/owned.txt': 'template'+chr(10),
         '.github/scripts/release_source_inventory.py': "raise SystemExit('candidate evaluator must not run')"+chr(10)}
for name, value in files.items():
    destination = distribution / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(value)
subprocess.run(['git', 'init', '-q', str(distribution)], check=True)
subprocess.run(['git', '-C', str(distribution), 'add', '.'], check=True)
subprocess.run(['git', '-C', str(distribution), 'config', 'core.fsmonitor', str(monitor)], check=True)
collection = installed / 'native-collection-fixture'
collection.mkdir()
(collection / 'test_value.py').write_text("def test_value():"+chr(10)+"    raise AssertionError('collection ran test body')"+chr(10))
def repository_queries():
    assert repository_context.git_value(fixture, 'status', '--porcelain=v1', '--untracked-files=all') == ''
    assert repository_context.tracked_files(fixture) == [fixture / 'source.py']
    observed = repository_context.git_state(fixture)
    assert observed['commit_sha'] == identity['commit_sha'] and observed['tree_sha'] == identity['tree_sha']
    os.environ.update(BCF_PROVIDER_EVENT='pull_request', GITHUB_EVENT_NAME='pull_request',
        BCF_INVOCATION_KIND='direct_event', BCF_COMPARISON_BASE_SHA=identity['commit_sha'],
        BCF_ORIGIN_COMPARISON_BASE_SHA=identity['commit_sha'], BCF_PR_BASE_SHA=identity['commit_sha'],
        BCF_CALLER_COMPARISON_BASE_SHA='')
    assert repository_context.pr_context(fixture, 'pr')['base_sha'] == identity['commit_sha']
    assert ci_state_matrix._git(fixture, 'diff', '--name-only', identity['commit_sha'], '--') == ''
repository_queries()
guardians = []
receive = custody._receive
descriptor = os.open(installed / 'native-reader-lease', os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
lease = os.fstat(descriptor)
fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
def observe(connection, deadline):
    value = receive(connection, deadline)
    if value.get('type') == 'ready':
        actual = Path('/proc', str(value['supervisor_pid']), 'fd', str(descriptor)).stat()
        assert (actual.st_dev, actual.st_ino) == (lease.st_dev, lease.st_ino)
        guardians.append(value['supervisor_pid'])
    return value
custody._receive = observe
try:
    with custody.native_lease_custody(descriptor, timeout_seconds=30, cleanup_seconds=10):
        assert paths.candidate_source_files(fixture, ('*.py',), label='Python', error=ValueError) == [fixture / 'source.py']
        assert [row[0] for row in paths.committed_python_source_population(fixture, **identity)['python_blobs']] == ['source.py']
        observed = preflight_distribution.validate_source_distribution(distribution, python_executable=project_python)
        assert observed['file_count'] == 5 and observed['authority'] is False
        assert test_manifests._collect_raw_nodes(collection, ['test_value.py'], python_executable=project_python) == ['test_value.py::test_value']
        typed = typescript.discover_typescript_source(node_fixture, typescript.contract_from_mapping(engine), [node_fixture / 'src/value.ts'])
        assert typed['compiler_version'] == '6.0.3'
        assert any(row['symbol'] == 'src/value.ts::value' for row in typed['functions'])
        assert len(source_inventory.tracked_source_inventory(distribution)) == 5
        repository_queries()
finally:
    os.close(descriptor)
assert len(guardians) == 17 and all(not Path('/proc', str(pid)).exists() for pid in guardians)
assert not marker.exists(), 'installed source discovery executed candidate fsmonitor'
assert git('config', '--get', 'core.fsmonitor') == str(monitor)
assert not any(name.startswith('bcf_governance') for name in sys.modules)
print(json.dumps({'source_sdk_absent': True, 'private_origin_verified': True,
                  'consumers': 3, 'fsmonitor_not_executed': True,
                  'bound_preflight_guardians_verified_and_reaped': 17,
                  'repository_configuration_preserved': True}, sort_keys=True))
'''
    compile(code, 'installed-semantic-git-discovery', 'exec')
    result = subprocess.run(
        [str(isolated_python), '-I', '-c', code, sys.executable, json.dumps(engine), str(node_fixture)],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True,
    )
    assert result.returncode == 0, _record(result)
    assert json.loads(result.stdout) == {
        'source_sdk_absent': True, 'private_origin_verified': True,
        'consumers': 3, 'fsmonitor_not_executed': True,
        'bound_preflight_guardians_verified_and_reaped': 17,
        'repository_configuration_preserved': True,
    }

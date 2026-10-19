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
    code = r'''import importlib.util, json, subprocess, sys
from pathlib import Path
assert importlib.util.find_spec('bcf_governance') is None
installed = Path.cwd()
sys.path.insert(0, str(installed / 'scripts'))
from _bcf_runtime import semantic_source_paths as paths
from _bcf_runtime.semantic_ownership_inventory import discover_python_source
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
assert not marker.exists(), 'installed source discovery executed candidate fsmonitor'
assert git('config', '--get', 'core.fsmonitor') == str(monitor)
assert not any(name.startswith('bcf_governance') for name in sys.modules)
print(json.dumps({'source_sdk_absent': True, 'private_origin_verified': True,
                  'consumers': 3, 'fsmonitor_not_executed': True,
                  'repository_configuration_preserved': True}, sort_keys=True))
'''
    compile(code, 'installed-semantic-git-discovery', 'exec')
    result = subprocess.run(
        [str(isolated_python), '-I', '-c', code],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True,
    )
    assert result.returncode == 0, _record(result)
    assert json.loads(result.stdout) == {
        'source_sdk_absent': True, 'private_origin_verified': True,
        'consumers': 3, 'fsmonitor_not_executed': True,
        'repository_configuration_preserved': True,
    }

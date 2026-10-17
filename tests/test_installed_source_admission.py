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
project_python = Path(sys.argv[1])
fixture = root / 'framework-fixture'
fixture.mkdir()
project = '[build-system]\nrequires=["setuptools"]\nbuild-backend="setuptools.build_meta"\n'
project += '[project]\nname="fixture"\nversion="1.0"\n[tool.setuptools]\npackages=[]\n'
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
        'forged_report_rejected': True, 'candidate_and_shadow_not_executed': True,
        'valid_file_count': 7,
    }

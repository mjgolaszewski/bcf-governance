"""Real Git and selected-interpreter controls for source admission ownership."""
from pathlib import Path
import subprocess
import sys

import pytest

from bcf_governance.tooling.governance_validation.preflight_distribution import (
    validate_source_distribution,
)


def _fixture(root, *, coverage, program):
    files = {
        'pyproject.toml': '[build-system]\nrequires=["setuptools"]\nbuild-backend="setuptools.build_meta"\n'
                          '[project]\nname="fixture"\nversion="1.0"\n[tool.setuptools]\npackages=[]\n'
                          '[tool.setuptools.package-data]\nbcf_governance=["pack/template-repo/**/*"]\n',
        'MANIFEST.in': 'global-include *\n' if coverage else 'global-exclude *\n',
        'owned.txt': 'exact\n',
        'bcf_governance/pack/template-repo/owned.txt': 'exact template\n',
        '.github/scripts/release_source_inventory.py': program,
    }
    for name, value in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)


def test_candidate_success_report_cannot_admit_missing_manifest_coverage(tmp_path):
    program = """from pathlib import Path
Path('candidate-executed').write_text('unauthorized evaluator')
print('{"authority":false,"built_bytes_verified":false,"scope":"static_source_declaration_coverage","file_count":1}')
"""
    _fixture(tmp_path, coverage=False, program=program)
    with pytest.raises(ValueError, match='omits tracked source'):
        validate_source_distribution(tmp_path, python_executable=Path(sys.executable))
    assert not (tmp_path / 'candidate-executed').exists()


@pytest.mark.parametrize('shadow', [False, True])
def test_valid_declarations_do_not_execute_candidate_evaluator_or_import_shadow(tmp_path, shadow):
    program = "from pathlib import Path\nPath('candidate-executed').touch()\nraise SystemExit('candidate code must not run')\n"
    _fixture(tmp_path, coverage=True, program=program)
    if shadow:
        marker = "from pathlib import Path\nPath('shadow-executed').touch()\nraise RuntimeError('candidate shadow imported')\n"
        for name in ['setuptools.py', 'sitecustomize.py']:
            (tmp_path / name).write_text(marker)
        subprocess.run(['git', '-C', str(tmp_path), 'add', '.'], check=True)
    result = validate_source_distribution(tmp_path, python_executable=Path(sys.executable))
    assert result['authority'] is False and result['built_bytes_verified'] is False
    assert result['scope'] == 'static_source_declaration_coverage'
    assert result['file_count'] == (7 if shadow else 5)
    assert not (tmp_path / 'candidate-executed').exists()
    assert not (tmp_path / 'shadow-executed').exists()

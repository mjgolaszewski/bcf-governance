"""Private authority schemas belong to the loaded runtime, never the checkout."""

import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from bcf_governance.tooling.ci_github_authority import packaged_repo_root


ROOT = Path(__file__).resolve().parents[1]
PROBE = r'''
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from _bcf_runtime import ci_github_authority as owner
from _bcf_runtime.ci_authority_contracts import CIAuthorityContractError, validate_ci_contract
from _bcf_runtime.ci_github_api import GitHubContent
from _bcf_runtime.trusted_inputs import verify_required_phase_closure_inputs
resource = owner.packaged_repo_root()
assert resource.is_relative_to(Path(owner.__file__).resolve().parent)
assert resource != Path.cwd()
try:
    validate_ci_contract(resource, 'authority', {})
except CIAuthorityContractError:
    pass
else:
    raise AssertionError('candidate schema supplied authority')
class API:
    calls = []
    def repository(self, repository):
        assert repository == 'owner/repo'
        return {'id': 42, 'full_name': repository, 'default_branch': 'main'}
    def reference(self, repository, ref):
        assert repository == 'owner/repo' and ref == 'heads/main'
        return {'object': {'type': 'commit', 'sha': 'a'*40}}
    def commit(self, repository, sha):
        assert repository == 'owner/repo' and sha == 'a'*40
        return {'sha': sha, 'tree': {'sha': 'b'*40}}
    def content(self, repository, path, *, ref):
        assert repository == 'owner/repo' and ref == 'a'*40
        self.calls.append(path)
        data = {
            'plans/build-plan.yml': {'phase_sequence': [{'phase_id': 'P01', 'hard_dependencies': []}]},
            'plans/phase-ledger.yml': {'active_phase': {'id': 'P01'}},
            'plans/phase-history.yml': {'entries': []},
        }
        return GitHubContent(path, 'c'*40, json.dumps(data[path]).encode())
api = API()
subject, inputs = verify_required_phase_closure_inputs(api, repository='owner/repo', phase_id='P01')
assert subject.repository_id == '42' and subject.checkout_sha == 'a'*40
assert inputs == {} and len(api.calls) == 3
assert 'bcf_governance' not in sys.modules
print(json.dumps({'runtime_owned_schemas': True, 'candidate_schema_rejected': True,
                  'protected_empty_population_verified': True}))
'''
compile(PROBE, 'private-phase-authority-resources', 'exec')


@pytest.mark.parametrize('template', ['template-repo', 'bcf_governance/pack/template-repo'])
def test_private_phase_query_uses_loaded_runtime_schemas(tmp_path, template):
    (tmp_path / 'schemas').mkdir()
    (tmp_path / 'schemas/ci-authority.schema.json').write_text('{}')
    result = subprocess.run(
        [sys.executable, '-I', '-c', PROBE, str(ROOT / template / 'scripts')],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)['protected_empty_population_verified']


def test_private_schema_population_is_canonical():
    canonical = {p.name: p.read_bytes() for p in (ROOT / 'schemas').glob('*.json')}
    for template in ['template-repo', 'bcf_governance/pack/template-repo']:
        resources = ROOT / template / 'scripts/_bcf_runtime/resources/schemas'
        assert {p.name: p.read_bytes() for p in resources.glob('*.json')} == canonical


def test_missing_private_resources_cannot_fall_back_to_candidate(tmp_path):
    scripts = tmp_path / 'scripts'
    runtime = scripts / '_bcf_runtime'
    shutil.copytree(ROOT / 'template-repo/scripts/_bcf_runtime', runtime,
                    ignore=shutil.ignore_patterns('resources', '__pycache__', '*.pyc'))
    (tmp_path / 'schemas').mkdir()
    (tmp_path / 'schemas/ci-authority.schema.json').write_text('{}')
    code = """import sys
sys.path.insert(0, sys.argv[1])
from _bcf_runtime.ci_github_authority import packaged_repo_root
from _bcf_runtime.ci_github_identity import GitHubControllerError
try:
    packaged_repo_root()
except GitHubControllerError:
    pass
else:
    raise AssertionError('missing runtime resources accepted candidate schemas')
"""
    result = subprocess.run([sys.executable, '-I', '-c', code, str(scripts)],
                            cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_sdk_schema_root_preserves_existing_package_location():
    assert packaged_repo_root() == ROOT / 'bcf_governance/pack/template-repo'

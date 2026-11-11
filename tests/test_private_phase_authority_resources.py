"""Private authority schemas belong to the loaded runtime, never the checkout."""

import json
import importlib.util
import importlib.resources
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from bcf_governance.tooling.ci_github_authority import packaged_repo_root
from bcf_governance.tooling import ci_github_authority


ROOT = Path(__file__).resolve().parents[1]
PROBE = r'''
import hashlib, importlib.util, json, sys
from pathlib import Path
if len(sys.argv) > 2:
    assert importlib.util.find_spec('bcf_governance') is None
sys.path.insert(0, sys.argv[1])
from _bcf_runtime import ci_github_authority as owner
from _bcf_runtime.ci_authority_contracts import CIAuthorityContractError, validate_ci_contract
from _bcf_runtime.ci_github_api import GitHubContent
from _bcf_runtime.ci_github_identity import GitHubControllerError
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
def oid(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
class API:
    documents = {
        'plans/build-plan.yml': {'phase_sequence': [{'phase_id': 'P01', 'hard_dependencies': []}]},
        'plans/phase-ledger.yml': {'active_phase': {'id': 'P01'}},
        'plans/phase-history.yml': {'entries': []},
    }
    def __init__(self, *, mode='100644', wrong=None, nonregular=None, oversized=False):
        self.calls = []
        self.mode, self.wrong, self.nonregular = mode, wrong, nonregular
        self.oversized = oversized
    def repository(self, repository):
        assert repository == 'owner/repo'
        return {'id': 42, 'full_name': repository, 'default_branch': 'main'}
    def reference(self, repository, ref):
        assert repository == 'owner/repo' and ref == 'heads/main'
        return {'object': {'type': 'commit', 'sha': 'a'*40}}
    def commit(self, repository, sha):
        assert repository == 'owner/repo' and sha == 'a'*40
        return {'sha': sha, 'tree': {'sha': 'b'*40}}
    def _raw(self, path):
        raw = json.dumps(self.documents[path]).encode()
        if self.oversized:
            raw += (b'\n#' + b'x'*897) * 1000
        return raw
    def complete_tree_with_modes(self, repository, tree):
        assert repository == 'owner/repo' and tree == 'b'*40
        return tuple((path, oid(self._raw(path)), '120000' if path == self.nonregular else self.mode)
                     for path in sorted(self.documents))
    def content(self, repository, path, *, ref):
        assert repository == 'owner/repo' and ref == 'a'*40
        self.calls.append(path)
        raw = self._raw(path)
        if path == self.wrong:
            raw += b'\n# self-consistent wrong-tree blob\n'
        return GitHubContent(path, oid(raw), raw)
controls = []
for mode in ('100644', '100755'):
    api = API(mode=mode)
    subject, inputs = verify_required_phase_closure_inputs(api, repository='owner/repo', phase_id='P01')
    assert subject.repository_id == '42' and subject.checkout_sha == 'a'*40
    assert inputs == {} and len(api.calls) == 3
    controls.append('valid-' + mode)
for kind in ('wrong', 'nonregular'):
    for path in API.documents:
        api = API(**{kind: path})
        try:
            verify_required_phase_closure_inputs(api, repository='owner/repo', phase_id='P01')
        except GitHubControllerError as error:
            assert ('blob' in str(error) or 'regular' in str(error)), str(error)
        else:
            raise AssertionError('private policy query accepted ' + kind + ': ' + path)
        controls.append(kind + ':' + path)
api = API(oversized=True)
try:
    verify_required_phase_closure_inputs(api, repository='owner/repo', phase_id='P01')
except GitHubControllerError as error:
    assert 'bounded input' in str(error), str(error)
else:
    raise AssertionError('private policy query accepted aggregate source overflow')
controls.append('aggregate-budget')
assert len(controls) == 9
assert 'bcf_governance' not in sys.modules
print(json.dumps({'runtime_owned_schemas': True, 'candidate_schema_rejected': True,
                  'protected_empty_population_verified': True,
                  'protected_policy_blob_custody_controls': len(controls)}))

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
    package = importlib.resources.files('bcf_governance')
    expected = Path(str(package.joinpath('pack', 'template-repo'))).resolve()
    assert packaged_repo_root() == expected


def test_loaded_private_context_binds_resources_before_checkout(tmp_path, monkeypatch):
    runtime = tmp_path / 'scripts/_bcf_runtime'
    schemas = runtime / 'resources/schemas'
    schemas.mkdir(parents=True)
    (schemas / 'ci-authority.schema.json').write_bytes(
        (ROOT / 'schemas/ci-authority.schema.json').read_bytes(),
    )
    candidate = tmp_path / 'schemas'
    candidate.mkdir()
    (candidate / 'ci-authority.schema.json').write_text('{}')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(ci_github_authority, '__file__', str(runtime / 'ci_github_authority.py'))
    monkeypatch.setattr(ci_github_authority, '__package__', '_bcf_runtime')
    assert packaged_repo_root() == runtime / 'resources'


def test_generator_discovers_private_schema_drift_independently(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        'private_schema_pack_generator', ROOT / '.github/scripts/build_pack_manifest.py',
    )
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    original = generator._tree_bytes
    def omit_private_population(root, *, suffixes):
        if root.parts[-3:] == ('_bcf_runtime', 'resources', 'schemas'):
            return {}
        return original(root, suffixes=suffixes)
    monkeypatch.setattr(generator, '_tree_bytes', omit_private_population)
    issues = generator.check()
    assert sum('private schemas differ from canonical schemas' in issue for issue in issues) == 2

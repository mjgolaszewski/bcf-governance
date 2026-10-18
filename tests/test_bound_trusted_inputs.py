"""External input authority comes from two authenticated provider namespaces."""
from copy import deepcopy
import hashlib
from io import BytesIO
from pathlib import Path
import zipfile

import pytest

from bcf_governance.tooling import trusted_inputs
from bcf_governance.tooling.ci_authority_contracts import validate_ci_contract, CIAuthorityContractError
from bcf_governance.tooling.ci_github_api import GitHubContent
from tests.test_ci_github_controller import FakeAPI, SHA_A, SHA_B, _prepare_v11_run


class InputAPI:
    def __init__(self):
        self.consumer = FakeAPI()
        self.source = FakeAPI()
        for api, identity in ((self.consumer, 42), (self.source, 101)):
            _prepare_v11_run(api)
            api.authority['repository']['repository_id'] = str(identity)
            for run in api.runs.values():
                run['repository'] = {'id': identity}
                run['head_repository'] = {'id': identity}
        self.source.runs['400'].update(status='completed', conclusion='success')
        self.source.run_job_names['400'] = ('Finalize',)
        workflow = b'name: governed\non: workflow_run\njobs:\n  Finalize:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n'
        oid = hashlib.sha1(b'blob ' + str(len(workflow)).encode() + b'\0' + workflow).hexdigest()
        self.source.workflow_versions[SHA_A] = (oid, workflow)
        rule = self.source.authority['workflow_registry']['finalizer']
        rule.update(trusted_workflow_blob_oid=oid, trusted_workflow_sha256=hashlib.sha256(workflow).hexdigest())
        self.contract = {
            'input_id': 'identity-contracts',
            'source_repository': {'provider': 'github', 'repository_id': '101'},
            'producer_ref': SHA_A, 'artifact_name': 'contracts',
            'digest_algorithm': 'sha256', 'required': True,
            'acquisition': {'schema_version': '1.0', 'role': 'finalizer', 'event': 'workflow_run',
                            'payload': {'kind': 'archive_member', 'path': 'contracts.tar'}},
        }
        self.consumer.authority['trusted_external_inputs'] = [deepcopy(self.contract)]
        self.payload = b'contract bytes'
        self.members = {'contracts.tar': self.payload}
        self.downloads = 0
        self.fault = None
        self.after_read = None

    def archive(self):
        stream = BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            for name, data in self.members.items():
                archive.writestr(name, data)
        return stream.getvalue()

    def selected(self, repository):
        assert repository in {'owner/consumer', 'owner/source'}
        return self.consumer if repository == 'owner/consumer' else self.source

    def repository(self, repository):
        self.selected(repository)
        return {'full_name': repository, 'id': 42 if repository == 'owner/consumer' else 101,
                'default_branch': 'main'}

    def reference(self, repository, ref):
        return self.selected(repository).reference('owner/repo', ref)

    def commit(self, repository, sha):
        result = self.selected(repository).commit('owner/repo', sha)
        if self.fault == 'invalid_tree' and repository == 'owner/source':
            result['tree'] = {'sha': 'not-a-tree'}
        return result

    def content(self, repository, path, *, ref):
        result = self.selected(repository).content('owner/repo', path, ref=ref)
        raw = result.content
        oid = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        return GitHubContent(path, oid, raw)

    def compare_commits(self, repository, *, base, head):
        result = self.selected(repository).compare_commits('owner/repo', base=base, head=head)
        if self.fault == 'lineage':
            result.update(status='diverged', merge_base_commit={'sha': SHA_B})
        return result

    def workflow(self, repository, workflow_id):
        return self.selected(repository).workflow('owner/repo', workflow_id)

    def run(self, repository, run_id):
        return self.selected(repository).run('owner/repo', run_id)

    def workflow_runs(self, repository, workflow_id, *, head_sha, event):
        assert repository == 'owner/source' and str(workflow_id) == '98'
        assert head_sha == SHA_A and event == 'workflow_run'
        rows = [deepcopy(self.source.runs['400'])]
        if self.fault in {'latest_failure', 'latest_incomplete'}:
            latest = {**rows[0], 'id': 401, 'conclusion': 'failure'}
            if self.fault == 'latest_incomplete':
                latest.update(status='in_progress', conclusion=None)
            self.source.runs['401'] = latest
            self.source.run_job_names['401'] = ('Finalize',)
            rows.append(latest)
        if self.fault == 'duplicate_run':
            rows.append(deepcopy(rows[0]))
        return tuple(rows)

    def jobs(self, repository, run_id, *, attempt):
        return self.selected(repository).jobs('owner/repo', run_id, attempt=attempt)

    def artifacts(self, repository, run_id):
        assert repository == 'owner/source' and str(run_id) == '400'
        row = {'id': 800, 'name': 'contracts', 'expired': self.fault == 'expired',
               'digest': 'sha256:' + hashlib.sha256(self.archive()).hexdigest(),
               'workflow_run': {'id': 400, 'repository_id': 101, 'head_repository_id': 101,
                                'head_branch': 'main', 'head_sha': SHA_A}}
        if self.fault == 'artifact_subject':
            row['workflow_run']['head_repository_id'] = 999
        if self.fault == 'provider_digest':
            row['digest'] = 'sha256:' + '0' * 64
        if self.fault == 'artifact_changed':
            row['id'] = 801
        return () if self.fault == 'missing_artifact' else (row, row) if self.fault == 'duplicate_artifact' else (row,)

    def artifact_bytes(self, repository, artifact_id, *, maximum_bytes):
        assert repository == 'owner/source' and str(artifact_id) == '800'
        raw = self.archive()
        assert len(raw) <= maximum_bytes
        self.downloads += 1
        if self.after_read == 'source_moved':
            self.source.main = SHA_B
        elif self.after_read == 'consumer_moved':
            self.consumer.main = SHA_B
        elif self.after_read:
            self.fault = self.after_read
        return raw


@pytest.fixture
def bound_input(tmp_path):
    api = InputAPI()
    path = tmp_path / 'contracts.tar'
    path.write_bytes(api.payload)
    return api, path


def verify_bound(api, path, *, contract=None, handoff=None, **kwargs):
    selected = deepcopy(api.contract if contract is None else contract)
    record = {**selected, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
              'provider_authenticated': True} if handoff is None else handoff
    return trusted_inputs.verify_trusted_input(
        api=api, repository='owner/consumer', source_repository='owner/source',
        contract=selected, handoff=record, artifact_path=path,
        executor_role='trusted-collector', **kwargs,
    )


@pytest.mark.parametrize('flag', [True, False, None])
def test_provider_custody_succeeds_independently_of_caller_authentication_flag(bound_input, flag):
    api, path = bound_input
    handoff = {**api.contract, 'sha256': hashlib.sha256(api.payload).hexdigest()}
    if flag is not None:
        handoff['provider_authenticated'] = flag
    result = verify_bound(api, path, handoff=handoff)
    assert result.verified_by == 'provider-state'
    assert result.source_repository_id == '101'
    assert result.sha256 == handoff['sha256'] and api.downloads == 1


def test_explicit_whole_provider_archive_domain(bound_input):
    api, path = bound_input
    api.contract['acquisition']['payload'] = {'kind': 'provider_archive'}
    api.consumer.authority['trusted_external_inputs'] = [deepcopy(api.contract)]
    path.write_bytes(api.archive())
    assert verify_bound(api, path).sha256 == hashlib.sha256(api.archive()).hexdigest()


@pytest.mark.parametrize('fault', ['lineage', 'invalid_tree', 'latest_failure', 'latest_incomplete',
                                 'duplicate_run', 'missing_artifact', 'expired', 'artifact_subject',
                                 'duplicate_artifact', 'provider_digest'])
def test_false_provider_facts_cannot_be_replaced_by_true_caller_flag(bound_input, fault):
    api, path = bound_input
    api.fault = fault
    with pytest.raises(trusted_inputs.TrustedInputError):
        verify_bound(api, path)
    assert api.downloads == (1 if fault == 'provider_digest' else 0)


@pytest.mark.parametrize('change', ['source_moved', 'consumer_moved', 'latest_failure', 'artifact_changed'])
def test_consuming_boundary_reauthenticates_provider_frontiers(bound_input, change):
    api, path = bound_input
    api.after_read = change
    with pytest.raises(trusted_inputs.TrustedInputError):
        verify_bound(api, path)
    assert api.downloads == 1


@pytest.mark.parametrize('mutation', ['source_id', 'contract_ref', 'unregistered', 'missing_binding',
                                    'handoff_source', 'handoff_digest', 'fork', 'job_inventory', 'job_failure',
                                    'wrong_event', 'policy_event', 'policy_workflow'])
def test_deterministic_admission_rejects_before_download(bound_input, mutation):
    api, path = bound_input
    contract = deepcopy(api.contract)
    handoff = {**contract, 'sha256': hashlib.sha256(api.payload).hexdigest(), 'provider_authenticated': True}
    if mutation == 'source_id':
        api.consumer.authority['trusted_external_inputs'][0]['source_repository']['repository_id'] = '999'
        contract['source_repository'] = {'provider': 'github', 'repository_id': '999'}
        handoff = {**handoff, **contract}
    elif mutation == 'contract_ref':
        contract['producer_ref'] = SHA_B
    elif mutation == 'unregistered':
        api.consumer.authority['trusted_external_inputs'] = []
    elif mutation == 'missing_binding':
        del api.contract['acquisition']
        del api.consumer.authority['trusted_external_inputs'][0]['acquisition']
        contract = deepcopy(api.contract)
        handoff = {**contract, 'sha256': hashlib.sha256(api.payload).hexdigest()}
    elif mutation == 'handoff_source':
        handoff['source_repository'] = {'provider': 'github', 'repository_id': '999'}
    elif mutation == 'handoff_digest':
        handoff['sha256'] = 'not-a-digest'
    elif mutation == 'fork':
        api.source.runs['400']['head_repository'] = {'id': 999}
    elif mutation == 'job_inventory':
        api.source.run_job_names['400'] = ('Finalize', 'Unexpected')
    elif mutation == 'job_failure':
        api.source.run_job_conclusions['400'] = {'Finalize': 'failure'}
    elif mutation == 'wrong_event':
        api.source.runs['400']['event'] = 'push'
    elif mutation == 'policy_event':
        api.source.authority['workflow_registry']['finalizer']['allowed_events'] = ['push']
    else:
        api.source.authority['workflow_registry']['finalizer']['trusted_workflow_sha256'] = '0' * 64
    with pytest.raises(trusted_inputs.TrustedInputError):
        verify_bound(api, path, contract=contract, handoff=handoff)
    assert api.downloads == 0


@pytest.mark.parametrize('kind', ['missing_member', 'unsafe_member', 'different_payload', 'symlink'])
def test_authenticated_archive_does_not_authorize_wrong_local_payload(bound_input, kind):
    api, path = bound_input
    if kind == 'missing_member':
        api.members = {'other.tar': api.payload}
    elif kind == 'unsafe_member':
        api.members['../escape'] = b'escape'
    elif kind == 'different_payload':
        api.members['contracts.tar'] = b'other bytes'
    else:
        target = path.with_suffix('.original')
        path.rename(target)
        path.symlink_to(target)
    with pytest.raises(trusted_inputs.TrustedInputError):
        verify_bound(api, path)
    if kind == 'symlink':
        assert api.downloads == 0


@pytest.mark.parametrize('path', ['', '/contracts.tar', '../contracts.tar', 'a/../b', './a', 'a/./b',
                                 'a//b', 'a\\b', 'a\0b', 'a/'])
def test_acquisition_member_selector_is_canonical(path):
    root = Path(__file__).resolve().parents[1]
    api = InputAPI()
    api.consumer.authority['trusted_external_inputs'][0]['acquisition']['payload']['path'] = path
    with pytest.raises(CIAuthorityContractError):
        validate_ci_contract(root, 'authority', api.consumer.authority)


def test_required_population_is_derived_before_any_download(bound_input):
    api, path = bound_input
    kwargs = {'repository': 'owner/consumer', 'handoffs': {}, 'artifact_paths': {}, 'source_repositories': {}}
    with pytest.raises(trusted_inputs.TrustedInputError):
        trusted_inputs.verify_required_trusted_inputs(api, **kwargs)
    assert api.downloads == 0
    handoff = {**api.contract, 'sha256': hashlib.sha256(api.payload).hexdigest()}
    kwargs.update(handoffs={'identity-contracts': handoff}, artifact_paths={'identity-contracts': path},
                  source_repositories={'identity-contracts': 'owner/source'})
    result = trusted_inputs.verify_required_trusted_inputs(api, **kwargs)
    assert set(result) == {'identity-contracts'} and api.downloads == 1

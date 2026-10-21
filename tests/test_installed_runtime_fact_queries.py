"""SDK-absent private runtime consumes facts rather than reported authority."""
from __future__ import annotations

import json
import subprocess

from test_installed_evidence_storage import (
    _environment, _record, installed_consumer, isolated_python,
)


PROBE = r'''import copy, fcntl, hashlib, importlib.util, io, json, sys, tarfile, tempfile, zipfile
from pathlib import Path
assert importlib.util.find_spec('bcf_governance') is None
root = Path.cwd().resolve()
sys.path.insert(0, str(root / 'scripts'))
from _bcf_runtime import release_runtime_verification as runtime
from _bcf_runtime import local_execution_admission as admission
from _bcf_runtime import ci_graph_timeouts as deadlines
from _bcf_runtime import ci_graph_defaults as graph_defaults
from _bcf_runtime import interpreter_environment as interpreter
for owner in (runtime, admission, deadlines, graph_defaults, interpreter):
    assert Path(owner.__file__).resolve().is_relative_to(root / 'scripts/_bcf_runtime')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def forbidden(*args, **kwargs):
    raise AssertionError('fact recomputation executed a subprocess')

with tempfile.TemporaryDirectory(prefix='bcf-private-fact-query-') as temporary:
    fixture = Path(temporary)
    from types import SimpleNamespace
    from _bcf_runtime import evidence_shards as planned
    from _bcf_runtime.ci_graph_execution import declared_workflow_context
    from _bcf_runtime.ci_graph_errors import CIGraphError
    assert Path(planned.__file__).resolve().is_relative_to(root / 'scripts/_bcf_runtime')
    budget_root = fixture / 'deadline-context'
    (budget_root / 'governance').mkdir(parents=True)
    (budget_root / 'governance/gate-contracts.yml').write_text(json.dumps({'execution_policy': {
        'default_timeout_seconds': 200, 'default_cleanup_timeout_seconds': 10}}))
    graph = {'policy': {'minimum_gate_timeout_headroom_seconds': 60}, 'workflows': [{
        'id': 'periodic', 'path': '.github/workflows/periodic.yml', 'events': [{'type': 'schedule'}],
        'jobs': [{'id': 'evidence', 'timeout_minutes': 10, 'executor': {
            'kind': 'gate_shard', 'gates': ['first', 'second'], 'shard_count': 1}}]}]}
    dag = {'nodes': [{'id': name, 'producer': name, 'assigned_shard': 0, 'depends_on': []}
                     for name in ('first', 'second')], 'edges': []}
    context = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'fixture/repo',
        'GITHUB_WORKFLOW_REF': 'fixture/repo/.github/workflows/caller.yml@refs/heads/main',
        'GITHUB_JOB': 'evidence', 'BCF_JOB_WORKFLOW_REPOSITORY': 'trusted/evaluator',
        'BCF_JOB_WORKFLOW_FILE_PATH': '.github/workflows/periodic.yml',
        'BCF_JOB_WORKFLOW_REF': 'trusted/evaluator/.github/workflows/periodic.yml@refs/heads/main',
        'BCF_JOB_WORKFLOW_SHA': 'b' * 40}
    assert declared_workflow_context(graph, context) == 'periodic'
    saved_api, saved_environment = planned.GitHubAPI, dict(planned.os.environ)
    class DeadlineAPI:
        def __init__(self, **kwargs): pass
        def content(self, repository, path, *, ref):
            assert (repository, path, ref) == ('trusted/evaluator', '.github/workflows/periodic.yml', 'b' * 40)
            return SimpleNamespace(path=path, content=physical_raw, blob_oid=hashlib.sha1(
                b'blob ' + str(len(physical_raw)).encode() + b'\0' + physical_raw).hexdigest())
    try:
        planned.GitHubAPI = DeadlineAPI
        planned.os.environ.update(context)
        physical_raw = b'jobs:\n  evidence:\n    timeout-minutes: 10\n'
        bounded = planned._physical_deadline_graph(graph, 'periodic')
        planned.validate_planned_shard_deadlines(budget_root, bounded, ['first', 'second'], dag,
            shard_count=1, workflow_id='periodic')
        physical_raw = b'jobs:\n  evidence:\n    timeout-minutes: 9\n'
        bounded = planned._physical_deadline_graph(graph, 'periodic')
        try:
            planned.validate_planned_shard_deadlines(budget_root, bounded, ['first', 'second'], dag,
                shard_count=1, workflow_id='periodic')
        except CIGraphError as error: assert 'cannot contain' in str(error)
        else: raise AssertionError('private runtime borrowed declared timeout over shorter physical source')
        assert graph['workflows'][0]['jobs'][0]['timeout_minutes'] == 10
    finally:
        planned.GitHubAPI = saved_api
        planned.os.environ.clear(); planned.os.environ.update(saved_environment)
    wheel, sdist = fixture / 'fixture.whl', fixture / 'fixture.tar.gz'
    evidence_dir = fixture / 'evidence'
    evidence_dir.mkdir()
    report, output = evidence_dir / 'report.json', evidence_dir / 'wheel-venv.stdout'
    # Synthetic query inputs, not a claim that this code was executed.
    package = b"raise RuntimeError('candidate code executed')\n"
    output.write_bytes(b'synthetic fact-query fixture\n')
    def archives(change=None):
        with zipfile.ZipFile(wheel, 'w') as archive:
            name = 'bcf_governance/generated.py' if change == 'unowned' else 'bcf_governance/__init__.py'
            if change == 'empty-package':
                archive.writestr('fixture.dist-info/METADATA', b'Name: fixture\n')
            elif change == 'unsafe-wheel':
                archive.writestr('../escaped.py', package)
            else:
                archive.writestr(name, b'changed\n' if change == 'substitution' else package)
                if change == 'duplicate-wheel':
                    archive.writestr(name, package)
        with tarfile.open(sdist, 'w:gz') as archive:
            info = tarfile.TarInfo('source/bcf_governance/__init__.py')
            info.size = len(package)
            archive.addfile(info, io.BytesIO(package))
        if change == 'invalid-sdist':
            sdist.write_bytes(b'not an archive')
    def payload():
        labels = ('wheel-venv', 'wheel-closure-install', 'twine-check', 'wheel-install',
                  'wheel-smoke', 'sdist-venv', 'sdist-closure-install', 'sdist-install',
                  'wheel-installed-consumer', 'sdist-smoke')
        commands, evidence = [], {}
        for label in labels:
            row = {'label': label, 'argv': ['/fixture/python', '-c', 'pass'], 'exit_code': 0}
            for stream in ('stdout', 'stderr'):
                path = evidence_dir / (label + '.' + stream)
                if path != output: path.write_bytes(b'synthetic fact-query fixture\n')
                row[stream] = path.name
                evidence[path.name] = sha(path)
            commands.append(row)
        return {'schema_version': '1.0', 'status': 'passed',
                'environment': {'python_version': '3.12.14', 'platform': 'linux_x86_64'},
                'source_mapping': {'status': 'exact', 'mapped_files': 1},
                'release_artifacts': {wheel.name: sha(wheel), sdist.name: sha(sdist)},
                'commands': commands, 'evidence': evidence}
    def consume(value, paths=None):
        report.write_text(json.dumps(value))
        if paths is None:
            paths = runtime.runtime_evidence_paths(report, evidence_dir)
        return runtime.verify_runtime_evidence(report, paths, wheel=wheel, sdist=sdist)
    previous_run, previous_popen = runtime.subprocess.run, runtime.subprocess.Popen
    runtime.subprocess.run = runtime.subprocess.Popen = forbidden
    try:
        archives()
        original = payload()
        assert consume(original) == original
        rejected = []
        for defect in ('substitution', 'unowned', 'false-count', 'boolean-count',
                       'extra-authority', 'unsafe-wheel', 'invalid-sdist',
                       'empty-package', 'duplicate-wheel', 'empty-evidence', 'raw-output'):
            archives(defect)
            output.write_bytes(b'synthetic fact-query fixture\n')
            value = payload()
            if defect == 'false-count': value['source_mapping']['mapped_files'] = 2
            if defect == 'boolean-count': value['source_mapping']['mapped_files'] = True
            if defect == 'extra-authority': value['source_mapping']['authority'] = True
            if defect == 'empty-evidence': value['evidence'] = {}
            if defect == 'raw-output': output.write_bytes(b'substituted output')
            try:
                consume(value, () if defect == 'empty-evidence' else None)
            except runtime.GitHubControllerError as error:
                assert ('source mapping' in str(error) or 'evidence inventory' in str(error)), str(error)
                rejected.append(defect)
            else:
                raise AssertionError('private runtime accepted forged fact: ' + defect)
        assert len(rejected) == 11
        command_rejections = 0
        for defect in ('missing', 'empty', 'duplicate', 'dropped-with-streams', 'unknown',
                       'failed', 'boolean-exit', 'empty-argv', 'nonstring-argv',
                       'unbound-stream', 'reused-stream', 'orphan-stream',
                       'install-before-closure', 'consumer-before-install',
                       'twine-before-closure', 'smoke-after-consumer'):
            archives()
            output.write_bytes(b'synthetic fact-query fixture\n')
            value = payload()
            rows = value['commands']
            extra = None
            if defect == 'missing': del value['commands']
            elif defect == 'empty': value['commands'] = []
            elif defect == 'duplicate': rows.append(copy.deepcopy(rows[0]))
            elif defect == 'dropped-with-streams':
                removed = rows.pop()
                for stream in ('stdout', 'stderr'): del value['evidence'][removed[stream]]
            elif defect == 'unknown': rows[0]['label'] = 'invented-success'
            elif defect == 'failed': rows[0]['exit_code'] = 1
            elif defect == 'boolean-exit': rows[0]['exit_code'] = False
            elif defect == 'empty-argv': rows[0]['argv'] = []
            elif defect == 'nonstring-argv': rows[0]['argv'][0] = True
            elif defect == 'unbound-stream': rows[0]['stdout'] = 'unbound.stdout'
            elif defect == 'reused-stream': rows[1]['stdout'] = rows[0]['stdout']
            elif defect == 'orphan-stream':
                extra = evidence_dir / 'unclaimed.stdout'; extra.write_bytes(b'unclaimed')
                value['evidence'][extra.name] = sha(extra)
            elif defect == 'install-before-closure': rows[1], rows[3] = rows[3], rows[1]
            elif defect == 'consumer-before-install': rows[7], rows[8] = rows[8], rows[7]
            elif defect == 'twine-before-closure': rows.insert(0, rows.pop(2))
            else: rows.insert(8, rows.pop(4))
            try:
                consume(value, tuple(evidence_dir / name for name in value['evidence']))
            except runtime.GitHubControllerError as error:
                assert 'runtime command' in str(error), str(error)
                command_rejections += 1
            else:
                raise AssertionError('private runtime accepted forged command: ' + defect)
            finally:
                if extra is not None: extra.unlink()
        assert command_rejections == 16
        forged = payload()
        forged['commands'][0]['exit_code'] = 1
        command_validator = runtime._validate_runtime_commands
        try:
            runtime._validate_runtime_commands = lambda report: None
            assert consume(forged, tuple(evidence_dir / name for name in forged['evidence'])) == forged
        finally:
            runtime._validate_runtime_commands = command_validator
        value = payload()
        value['schema_version'] = '1.1'
        value['commands'].insert(8, value['commands'].pop())
        row = {'label': 'sdist-installed-consumer', 'argv': ['/fixture/python', '-c', 'pass'], 'exit_code': 0}
        for stream in ('stdout', 'stderr'):
            path = evidence_dir / ('sdist-installed-consumer.' + stream)
            path.write_bytes(b'synthetic fact-query fixture\n')
            row[stream] = path.name
            value['evidence'][path.name] = sha(path)
        value['commands'].append(row)
        execution = fixture / 'execution'
        selected = '/opt/python/bin/python'
        value['environment']['python_executable'] = selected
        wp, sp = str(execution / 'wheel-env/bin/python'), str(execution / 'sdist-env/bin/python')
        source = execution / 'source/exact-sdist'
        closure = ['-m', 'pip', 'install', '--no-index', '--find-links', str(execution / 'wheelhouse'),
                   '--require-hashes', '-r', str(execution / 'closure.lock')]
        smoke = ['-m', 'bcf_governance.cli', '--version']
        consumer = [str(source / '.github/scripts/verify_installed_consumer.py'), '--source-root', str(source)]
        arguments = {
            'wheel-venv': [selected, '-m', 'venv', str(execution / 'wheel-env')],
            'sdist-venv': [selected, '-m', 'venv', str(execution / 'sdist-env')],
            'wheel-closure-install': [wp, *closure], 'sdist-closure-install': [sp, *closure],
            'wheel-install': [wp, '-m', 'pip', 'install', '--no-index', '--no-deps', str(wheel)],
            'sdist-install': [sp, '-m', 'pip', 'install', '--no-index', '--no-deps', '--no-build-isolation', str(sdist)],
            'twine-check': [wp, '-m', 'twine', 'check', '--strict', str(wheel), str(sdist)],
            'wheel-smoke': [wp, *smoke], 'sdist-smoke': [sp, *smoke],
            'wheel-installed-consumer': [wp, *consumer], 'sdist-installed-consumer': [sp, *consumer],
        }
        for command in value['commands']: command['argv'] = arguments[command['label']]
        assert consume(value) == value
        argument_rejections = 0
        for defect in ('generic-success', 'wrong-interpreter', 'wrong-asset', 'different-lock',
                       'different-wheelhouse', 'candidate-harness', 'different-consumer-source',
                       'no-offline-install', 'missing-strict-metadata', 'nul-argv'):
            forged = copy.deepcopy(value)
            rows = {command['label']: command for command in forged['commands']}
            if defect == 'generic-success': rows['wheel-install']['argv'] = ['/bin/true']
            elif defect == 'wrong-interpreter': rows['sdist-smoke']['argv'][0] = wp
            elif defect == 'wrong-asset': rows['wheel-install']['argv'][-1] = '/tmp/other.whl'
            elif defect == 'different-lock': rows['sdist-closure-install']['argv'][-1] = '/tmp/other.lock'
            elif defect == 'different-wheelhouse': rows['sdist-closure-install']['argv'][6] = '/tmp/other-wheelhouse'
            elif defect == 'candidate-harness': rows['wheel-installed-consumer']['argv'][1] = '/tmp/candidate/pass.py'
            elif defect == 'different-consumer-source': rows['sdist-installed-consumer']['argv'][-1] = '/tmp/other-source'
            elif defect == 'no-offline-install': rows['wheel-install']['argv'].remove('--no-index')
            elif defect == 'missing-strict-metadata': rows['twine-check']['argv'].remove('--strict')
            else: rows['wheel-install']['argv'][0] += '\0forged'
            try: consume(forged)
            except runtime.GitHubControllerError as error:
                assert 'runtime command arguments' in str(error), str(error)
                argument_rejections += 1
            else: raise AssertionError('private runtime accepted forged command argument: ' + defect)
        assert argument_rejections == 10
        policy_root = fixture / 'deadline-policy'
        policy_path = policy_root / 'governance/gate-contracts.yml'
        policy_path.parent.mkdir(parents=True)
        def policy(body=200, cleanup=10, overrides=None):
            policy_path.write_text(json.dumps({'execution_policy': {
                'default_timeout_seconds': body, 'default_cleanup_timeout_seconds': cleanup},
                'gates': {gate: {'invocation': {'timeout_seconds': value}}
                          for gate, value in (overrides or {}).items()}}))
        def graph(minutes, kind='gate_group'):
            return {'policy': {'minimum_gate_timeout_headroom_seconds': 60},
                    'workflows': [{'id': 'verify', 'jobs': [{'id': 'evidence',
                        'timeout_minutes': minutes, 'executor': {
                            'kind': kind, 'gates': ['first', 'second']}}]}]}
        deadline_rejections = 0
        def reject_deadline(subject, value):
            global deadline_rejections
            try: deadlines.validate_gate_job_timeouts(subject, value)
            except deadlines.CIGraphError as error:
                assert 'cannot contain' in str(error), str(error)
                deadline_rejections += 1
            else: raise AssertionError('private runtime admitted underbudget serial deadline')
        policy()
        reject_deadline(policy_root, graph(9))
        deadlines.validate_gate_job_timeouts(policy_root, graph(10))
        deadlines.validate_gate_job_timeouts(policy_root, graph(6, 'gate_shard'))
        siblings = graph(10)
        siblings['workflows'].append({'id': 'sibling', 'jobs': graph(9)['workflows'][0]['jobs']})
        reject_deadline(policy_root, siblings)
        policy(overrides={'second': 400})
        reject_deadline(policy_root, graph(12))
        deadlines.validate_gate_job_timeouts(policy_root, graph(13))
        policy(cleanup=30)
        reject_deadline(policy_root, graph(10))
        deadlines.validate_gate_job_timeouts(policy_root, graph(11))
        legacy_root = fixture / 'legacy-no-policy'
        reject_deadline(legacy_root, graph(65))
        deadlines.validate_gate_job_timeouts(legacy_root, graph(66))
        reference = graph_defaults.build_reference_ci_graph(
            project_id='private-deadline', profile='standard', profile_contract_version='3.0',
            gates=['governance-validate', 'architecture-test', 'lint', 'test',
                   'security-secret-scan', 'runtime-smoke'],
            candidate_labels=['ubuntu-24.04'], trusted_labels=['self-hosted'],
            candidate_hosted=True, trusted_hosted=False)
        deadlines.validate_gate_job_timeouts(legacy_root, reference)
        policy()
        serial_bound = deadlines.gate_sequence_deadline_ms
        try:
            deadlines.gate_sequence_deadline_ms = lambda bounds, **kw: serial_bound([max(bounds)], **kw)
            deadlines.validate_gate_job_timeouts(policy_root, graph(9))
        finally:
            deadlines.gate_sequence_deadline_ms = serial_bound
        assert deadline_rejections == 5
        # Synthetic producer metadata exercises the actual installed owners.
        classes = ('subject', 'detector', 'test_population', 'toolchain', 'trust')
        reference_contract = {'profile_contract_version': '3.0', 'target_profile': 'standard',
            'execution_policy': {'default_timeout_seconds': 1800, 'default_cleanup_timeout_seconds': 60},
            'gates': {gate: ({'invocation': {'timeout_seconds': 2400}} if gate == 'test' else {})
                      for gate in ('governance-validate', 'test', 'contract-test', 'runtime-smoke')},
            'claim_model': {'version': '1.0', 'dependency_sets': {'all': ['**']},
                'execution_groups': {
                    'preflight': {'producer': 'preflight', 'captured_by_preflight': True, 'claims': ['structure']},
                    'tests': {'producer': 'test', 'claims': ['unit', 'contract']},
                    'runtime': {'producer': 'runtime-smoke', 'claims': ['runtime']}},
                'claims': {cid: {'execution_group': group, 'legacy_gate': gate,
                                'dependencies': {name: [] for name in classes}}
                           for cid, group, gate in [('structure', 'preflight', 'governance-validate'),
                               ('unit', 'tests', 'test'), ('contract', 'tests', 'contract-test'),
                               ('runtime', 'runtime', 'runtime-smoke')]}}}
        def project(value, gates=None):
            return graph_defaults.build_reference_ci_graph(
                project_id='private-contract', profile='standard', profile_contract_version='3.0',
                gates=list(value['gates']) if gates is None else gates,
                candidate_labels=['ubuntu-24.04'], trusted_labels=['self-hosted'],
                candidate_hosted=True, trusted_hosted=False, gate_contract=value)
        original_contract = copy.deepcopy(reference_contract)
        projected = project(reference_contract)
        assert reference_contract == original_contract
        shard = next(job for workflow in projected['workflows'] for job in workflow['jobs']
                     if job['executor']['kind'] == 'gate_shard')
        assert shard['timeout_minutes'] == 80
        reference_rejections = 0
        for defect in ('missing-model', 'duplicate-producer', 'omitted-producer',
                       'boolean-body', 'wrong-profile', 'wrong-version'):
            value = copy.deepcopy(reference_contract)
            gates = None
            if defect == 'missing-model': del value['claim_model']
            elif defect == 'duplicate-producer': value['claim_model']['execution_groups']['runtime']['producer'] = 'test'
            elif defect == 'omitted-producer': gates = [g for g in value['gates'] if g != 'runtime-smoke']
            elif defect == 'boolean-body': value['execution_policy']['default_timeout_seconds'] = True
            elif defect == 'wrong-profile': value['target_profile'] = 'lite'
            else: value['profile_contract_version'] = '2.0'
            try: project(value, gates)
            except ValueError: reference_rejections += 1
            else: raise AssertionError('private runtime admitted contradictory reference facts: ' + defect)
        capped = {'policy': {'minimum_gate_timeout_headroom_seconds': 60}, 'workflows': [{'jobs': [
            {'timeout_minutes': 10, 'executor': {'kind': 'gate_group', 'gates': ['first']}},
            {'timeout_minutes': 10, 'executor': {'kind': 'gate_group', 'gates': ['g'+str(i) for i in range(26)]}}]}]}
        before = copy.deepcopy(capped)
        try: deadlines.project_reference_gate_deadlines(capped, None)
        except deadlines.CIGraphError as error: assert '360' in str(error)
        else: raise AssertionError('private runtime admitted provider-cap overflow')
        assert capped == before and reference_rejections == 6
        periodic_contract = copy.deepcopy(reference_contract)
        for index in range(16):
            gate, claim = 'periodic-' + str(index), 'periodic_claim_' + str(index)
            periodic_contract['gates'][gate] = {}
            periodic_contract['claim_model']['claims'][claim] = {
                **copy.deepcopy(periodic_contract['claim_model']['claims']['unit']), 'legacy_gate': gate}
            periodic_contract['claim_model']['execution_groups']['tests']['claims'].append(claim)
        before_periodic = copy.deepcopy(periodic_contract)
        periodic_graph = project(periodic_contract)
        assert periodic_contract == before_periodic
        modern_periodic_workflows = 0
        for workflow in periodic_graph['workflows']:
            if workflow['role'] != 'scheduled': continue
            evidence = [job for job in workflow['jobs'] if job['executor']['kind'] == 'gate_shard']
            assert len(evidence) == 1 and evidence[0]['executor']['gates'] == list(periodic_contract['gates'])
            assert evidence[0]['executor']['shard_count'] == 4 and evidence[0]['timeout_minutes'] <= 360
            assert workflow['jobs'][-1]['executor']['kind'] == 'terminal_truth'
            assert workflow['jobs'][-1]['consumes'] == [workflow['id'] + '-receipts']
            argv = periodic_graph['commands'][workflow['id'] + '-preflight']['argv']
            assert [argv[i+1] for i, value in enumerate(argv) if value == '--expected-producer'] == [evidence[0]['id']]
            modern_periodic_workflows += 1
        assert modern_periodic_workflows == 2
        legacy_gates = [prefix + str(index) for prefix in ('governance-', 'quality-', 'security-', 'runtime-') for index in range(5)]
        legacy_periodic = graph_defaults.build_reference_ci_graph(
            project_id='private-legacy-periodic', profile='standard', profile_contract_version='2.0',
            gates=legacy_gates, candidate_labels=['ubuntu-24.04'], trusted_labels=['self-hosted'],
            candidate_hosted=True, trusted_hosted=False)
        periodic_parts = 0
        for workflow in legacy_periodic['workflows']:
            if workflow['role'] != 'scheduled': continue
            parts = [job for job in workflow['jobs'] if job['executor']['kind'] == 'gate_group']
            assert len(parts) == 2
            assert [gate for part in parts for gate in part['executor']['gates']] == legacy_gates
            previous_job = workflow['jobs'][0]['id']
            previous_artifact = workflow['id'] + '-session'
            for part in parts:
                assert part['needs'] == [previous_job] and part['consumes'] == [previous_artifact]
                assert part['condition'] == 'success' and part['timeout_minutes'] <= 360
                assert legacy_periodic['artifacts'][part['produces'][0]]['path'] == '.artifacts/bcf/sessions'
                previous_job, previous_artifact = part['id'], part['produces'][0]
            assert previous_artifact == workflow['id'] + '-receipts'
            truth = workflow['jobs'][-1]
            assert truth['condition'] == 'always' and truth['needs'] == [part['id'] for part in parts]
            assert truth['consumes'] == [part['produces'][0] for part in parts]
            argv = legacy_periodic['commands'][workflow['id'] + '-preflight']['argv']
            assert [argv[i+1] for i, value in enumerate(argv) if value == '--expected-producer'] == [part['id'] for part in parts]
            periodic_parts += len(parts)
        assert periodic_parts == 4
        requirement_root = fixture / 'identical-requirements'
        (requirement_root / 'governance').mkdir(parents=True)
        requirement_policy = {'interpreter_contract': {'project_dependencies': True,
            'build_system_requirements': True, 'requirements_projection': 'requirements.txt',
            'optional_dependency_groups': [], 'gate_requirements': {'test': ['pip==26.2.2']}},
            'gates': {'test': {}}}
        (requirement_root / 'governance/gate-contracts.yml').write_text(json.dumps(requirement_policy))
        project = requirement_root / 'pyproject.toml'
        declaration = ('[build-system]\nrequires=["setuptools>=69","wheel"]\n'
            '[project]\nname="fixture"\nversion="1.0"\nrequires-python=">=3.11"\n'
            'dependencies=["setuptools>=69","pip==26.2.2","PyYAML>=6,<7"]\n')
        project.write_text(declaration)
        plan = interpreter.derive_interpreter_environment(requirement_root)
        assert plan.requirements.count('setuptools>=69') == plan.requirements.count('pip==26.2.2') == 1
        assert project.read_text() == declaration and not (requirement_root / 'requirements.txt').exists()
        project.write_text(declaration.replace('dependencies=["setuptools>=69",', 'dependencies=["setuptools>=68",'))
        try: interpreter.derive_interpreter_environment(requirement_root)
        except interpreter.InterpreterEnvironmentError as error: assert 'unique names' in str(error)
        else: raise AssertionError('private runtime accepted differing duplicate requirements')
        assert not (fixture.parent / 'escaped.py').exists()
    finally:
        runtime.subprocess.run, runtime.subprocess.Popen = previous_run, previous_popen
    gate = fixture / 'gate.lock'
    constructor = admission.Path
    namespace = admission.authenticated_execution_state_namespace
    expected = '/tmp/bcf-local-gate-' + str(admission.os.getuid()) + '.lock'
    admission.Path = lambda value: gate if str(value) == expected else constructor(value)
    admission.authenticated_execution_state_namespace = lambda _: None
    busy_cases = 0
    try:
        for retained in (b'a' * 40 + b'\n', b'\xff\xfe\n', b'untrusted-retained-data\n'):
            gate.write_bytes(retained)
            with gate.open('r+') as holder:
                fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                try:
                    with admission.local_gate_lease('b' * 40):
                        raise AssertionError('private busy gate entered work')
                except admission.LocalExecutionAdmissionError as error:
                    assert str(error) == 'local_execution_busy_deferred: shared local gate is locked; execution owner is unverified'
                else:
                    raise AssertionError('private busy gate did not reject')
                assert gate.read_bytes() == retained
                with gate.open('r+') as contender:
                    try: fcntl.flock(contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError: pass
                    else: raise AssertionError('refusal unlocked actual holder')
            busy_cases += 1
        inode = gate.stat().st_ino
        with admission.local_gate_lease('b' * 40):
            assert gate.stat().st_ino == inode and gate.read_text() == 'b' * 40 + '\n'
        with gate.open('r+') as contender:
            fcntl.flock(contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        admission.Path = constructor
        admission.authenticated_execution_state_namespace = namespace
print(json.dumps({'authority': False, 'scope': 'private_runtime_synthetic_fact_queries',
                  'physical_deadline_context_qualified': True,
                  'sdk_absent': True, 'runtime_owned_helpers': True,
                  'valid_mapping_returned_unchanged': True, 'forged_mapping_or_evidence_rejected': 11, 'forged_command_records_rejected': command_rejections,
                  'version_1_1_both_consumers_accepted': True, 'command_guard_causal': True,
                  'forged_command_arguments_rejected': argument_rejections,
                  'serial_deadline_underbudget_rejected': deadline_rejections,
                  'serial_deadline_guard_causal': True, 'reference_serial_defaults_accepted': True,
                  'reference_model_bound_budget_minutes': 80,
                  'reference_projection_invalid_facts_rejected': reference_rejections,
                  'reference_projection_cap_atomic': True,
                  'modern_periodic_planned_workflows': modern_periodic_workflows,
                  'periodic_literal_gates': 20, 'periodic_parts_across_two_schedules': periodic_parts,
                  'periodic_ordered_coverage_and_custody_preserved': True,
                  'identical_requirement_predicates_collapsed': 2,
                  'differing_requirement_strings_blocked': True, 'interpreter_projection_unallocated': True,
                  'busy_cases': busy_cases, 'holder_and_retained_bytes_preserved': True,
                  'exact_file_reused': True, 'candidate_or_subprocess_not_executed': True}, sort_keys=True))
'''
compile(PROBE, 'installed-runtime-fact-queries', 'exec')


def exercise_runtime_fact_queries(consumer, python):
    result = subprocess.run(
        [str(python), '-I', '-c', PROBE], cwd=consumer, env=_environment(),
        capture_output=True, text=True,
    )
    assert result.returncode == 0, _record(result)
    observation = json.loads(result.stdout)
    assert observation['sdk_absent'] and observation['runtime_owned_helpers']
    assert observation['physical_deadline_context_qualified']
    assert observation['forged_mapping_or_evidence_rejected'] == 11
    assert observation['reference_model_bound_budget_minutes'] == 80
    assert observation['reference_projection_invalid_facts_rejected'] == 6
    assert observation['reference_projection_cap_atomic'] is True
    assert observation['modern_periodic_planned_workflows'] == 2
    assert observation['periodic_literal_gates'] == 20 and observation['periodic_parts_across_two_schedules'] == 4
    assert observation['periodic_ordered_coverage_and_custody_preserved']
    assert observation['identical_requirement_predicates_collapsed'] == 2
    assert observation['differing_requirement_strings_blocked'] and observation['interpreter_projection_unallocated']
    assert observation['busy_cases'] == 3 and observation['candidate_or_subprocess_not_executed']
    return _record(result)


def test_installed_private_runtime_recomputes_facts_and_reports_only_known_ownership(
    installed_consumer, isolated_python,
):
    exercise_runtime_fact_queries(installed_consumer, isolated_python)

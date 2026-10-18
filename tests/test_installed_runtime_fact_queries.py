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
for owner in (runtime, admission):
    assert Path(owner.__file__).resolve().is_relative_to(root / 'scripts/_bcf_runtime')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def forbidden(*args, **kwargs):
    raise AssertionError('fact recomputation executed a subprocess')

with tempfile.TemporaryDirectory(prefix='bcf-private-fact-query-') as temporary:
    fixture = Path(temporary)
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
                  'sdk_absent': True, 'runtime_owned_helpers': True,
                  'valid_mapping_returned_unchanged': True, 'forged_mapping_or_evidence_rejected': 11,
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
    assert observation['forged_mapping_or_evidence_rejected'] == 11
    assert observation['busy_cases'] == 3 and observation['candidate_or_subprocess_not_executed']
    return _record(result)


def test_installed_private_runtime_recomputes_facts_and_reports_only_known_ownership(
    installed_consumer, isolated_python,
):
    exercise_runtime_fact_queries(installed_consumer, isolated_python)

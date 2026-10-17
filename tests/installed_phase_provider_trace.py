"""Test-only exact provider-port transcript; verifier outcomes are never replayed."""

import base64
from dataclasses import asdict

from bcf_governance.tooling.ci_github_api import GitHubContent


def encode(value):
    if isinstance(value, bytes):
        return {'$bytes': base64.b64encode(value).decode('ascii')}
    if isinstance(value, GitHubContent):
        return {'$content': encode(asdict(value))}
    if isinstance(value, tuple):
        return {'$tuple': [encode(item) for item in value]}
    if isinstance(value, list):
        return [encode(item) for item in value]
    if isinstance(value, dict):
        assert all(isinstance(key, str) for key in value)
        return {key: encode(item) for key, item in value.items()}
    assert value is None or isinstance(value, (str, bool, int, float)), type(value)
    return value


class RecordingProvider:
    def __init__(self, provider):
        self.provider = provider
        self.rows = []

    def __getattr__(self, name):
        port = getattr(self.provider, name)
        assert callable(port), name
        def query(*args, **kwargs):
            value = port(*args, **kwargs)
            self.rows.append({'port': name, 'args': encode(args),
                              'kwargs': encode(kwargs), 'value': encode(value)})
            return value
        return query


PARENT_PROBE = r'''
import ast, base64, hashlib, importlib.util, io, json, sys, zipfile
from pathlib import Path
assert importlib.util.find_spec('bcf_governance') is None
root = Path.cwd()
sys.path.insert(0, str(root / 'scripts'))
from _bcf_runtime.ci_github_api import GitHubContent
from _bcf_runtime.ci_github_identity import GitHubControllerError
from _bcf_runtime.trusted_inputs import verify_phase_closure_input
def encode(value):
    if isinstance(value, tuple):
        return {'$tuple': [encode(item) for item in value]}
    if isinstance(value, list):
        return [encode(item) for item in value]
    if isinstance(value, dict):
        return {key: encode(item) for key, item in value.items()}
    return value
def decode(value):
    if isinstance(value, dict):
        if set(value) == {'$bytes'}:
            return base64.b64decode(value['$bytes'], validate=True)
        if set(value) == {'$content'}:
            return GitHubContent(**decode(value['$content']))
        if set(value) == {'$tuple'}:
            return tuple(decode(item) for item in value['$tuple'])
        return {key: decode(item) for key, item in value.items()}
    if isinstance(value, list):
        return [decode(item) for item in value]
    return value
transcript = json.loads(Path(sys.argv[1]).read_text())
mode = sys.argv[2]
if mode == 'substituted_without_guard':
    from _bcf_runtime import trusted_inputs as owner
    tree = ast.parse(Path(owner.__file__).read_text())
    count = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and any(
            isinstance(value, ast.Constant)
            and value.value == 'phase prerequisite artifact provider digest mismatch'
            for statement in node.body for value in ast.walk(statement)
        ):
            node.test = ast.Constant(False)
            count += 1
    assert count == 1
    exec(compile(ast.fix_missing_locations(tree), owner.__file__, 'exec'), owner.__dict__)
    verify_phase_closure_input = owner.verify_phase_closure_input
    mode = 'substituted'
class Replay:
    index = 0
    downloads = 0
    def __getattr__(self, name):
        def query(*args, **kwargs):
            assert self.index < len(transcript['rows']), 'unexpected provider query'
            row = transcript['rows'][self.index]
            assert row['port'] == name, (row['port'], name)
            assert row['args'] == encode(args) and row['kwargs'] == encode(kwargs)
            self.index += 1
            result = decode(row['value'])
            if name == 'artifact_bytes':
                self.downloads += 1
                if mode == 'substituted':
                    stream = io.BytesIO(result)
                    with zipfile.ZipFile(stream, 'a') as archive:
                        archive.comment = b'substituted provider archive envelope'
                    return stream.getvalue()
            return result
        return query
api = Replay()
try:
    artifact, verification, raw = verify_phase_closure_input(api, **transcript['coordinates'])
except GitHubControllerError as error:
    assert mode == 'substituted' and 'provider digest mismatch' in str(error), str(error)
    assert api.downloads == 1 and api.index < len(transcript['rows'])
    print(json.dumps({'outcome': 'rejected', 'reason': 'provider_digest_mismatch'}))
else:
    assert mode == 'valid', 'substituted archive was accepted'
    assert verification.status == 'pass' and verification.computed_state == 'certified'
    proposition = verification.certified_proposition
    assert proposition['target'] == {'kind': 'phase', 'id': 'P01'}
    assert proposition['predicate'] == 'phase_closed'
    assert hashlib.sha256(raw).hexdigest() == transcript['archive_sha256']
    assert artifact.artifact_id == '800' and api.downloads == 1
    assert api.index == len(transcript['rows'])
    assert 'bcf_governance' not in sys.modules
    print(json.dumps({'outcome': 'certified', 'provider_calls': api.index,
                      'source_sdk_absent': True, 'complete_trace_consumed': True}))
'''
compile(PARENT_PROBE, 'installed-parent-provider-trace', 'exec')

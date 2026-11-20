"""Controlled source/cache counterfactual; no native package or release approval."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import py_compile
import struct
import subprocess
import sys


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def observe(probe):
    result = subprocess.run([sys.executable, '-I', '-B', '-c', probe],
        capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout)
    assert observed['security_qualified'] is observed['runtime_context_qualified'] is False
    assert all(observed['positive_controls'].values())
    assert all(row['protected_cookie_retained'] for row in observed['cookiejar'])
    return observed


def main():
    payload = json.loads(sys.argv[1])
    artifact = Path(payload['result_path'])
    assert artifact.parent == Path('/tmp') and not artifact.exists()
    print('native-counterfactual:started', file=sys.stderr, flush=True)
    source = Path('/usr/lib/python3.14/http/cookies.py')
    cache = Path(importlib.util.cache_from_source(str(source)))
    original = source.read_bytes()
    bytecode = cache.read_bytes()
    assert sha(original) == payload['base_sha256']
    assert sha(bytecode) == payload['old_bytecode_sha256']
    assert bytecode[:4] == importlib.util.MAGIC_NUMBER
    before_flags = struct.unpack('<I', bytecode[4:8])[0]
    assert before_flags == 1, 'baseline is not unchecked-hash bytecode'
    patched = base64.b64decode(payload['patched_source_base64'], validate=True)
    assert sha(patched) == payload['patched_sha256']
    source.write_bytes(patched)
    print('native-counterfactual:source-only', file=sys.stderr, flush=True)
    source_only = observe(payload['probe_source'])
    assert source_only['modules']['http.cookies']['source_sha256'] == sha(patched)
    assert source_only['modules']['http.cookies']['cached_bytecode_sha256'] == sha(bytecode)
    assert not any(row['rejected'] for row in source_only['morsel']), 'source-only counterfactual differed'
    assert cache.read_bytes() == bytecode
    py_compile.compile(str(source), cfile=str(cache), dfile=str(source), doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)
    rebuilt = cache.read_bytes()
    assert rebuilt[:4] == importlib.util.MAGIC_NUMBER
    after_flags = struct.unpack('<I', rebuilt[4:8])[0]
    assert after_flags == 3 and sha(rebuilt) != sha(bytecode)
    print('native-counterfactual:recompiled', file=sys.stderr, flush=True)
    recompiled = observe(payload['probe_source'])
    assert recompiled['modules']['http.cookies']['source_sha256'] == sha(patched)
    assert recompiled['modules']['http.cookies']['cached_bytecode_sha256'] == sha(rebuilt)
    assert all(row['rejected'] for row in recompiled['morsel']), 'remediation did not reject injection'
    serialized = json.dumps(dict(authority=False,security_qualified=False,runtime_context_qualified=False,
        source_only=source_only,recompiled=recompiled,
        before_source_sha256=sha(original),after_source_sha256=sha(patched),
        before_cache_sha256=sha(bytecode),after_cache_sha256=sha(rebuilt),
        before_cache_flags=before_flags,after_cache_flags=after_flags,
        package_build_qualified=False,release_runtime_selected=None),sort_keys=True)
    pending = artifact.with_suffix('.pending')
    pending.write_text(serialized + '\n', encoding='utf-8')
    pending.replace(artifact)
    print(serialized, flush=True)


if __name__ != '__main__':
    raise RuntimeError('native counterfactual requires its declared main invocation')
main()

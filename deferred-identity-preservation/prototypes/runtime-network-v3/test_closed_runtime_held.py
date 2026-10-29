"""Real closed-runtime smoke; fresh no-network fixture, not owner admission."""
import importlib
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import pytest

from test_owner_registration import registration as _registration

views = importlib.import_module('_bcf_owner_runtime.evidence_execution_view')
images = importlib.import_module('_bcf_owner_runtime.evidence_closed_runtime_image')
immutable = importlib.import_module('_bcf_owner_runtime.evidence_immutable_source')
held = importlib.import_module('_bcf_owner_runtime.evidence_closed_held')
owner = importlib.import_module('_bcf_owner_runtime.evidence_execution_owner')

# Only nominate the fixed interpreter's actual file origins. This observation
# is not admission; the real held process must start from the resulting bytes.
_ORIGINS = '''import json,runpy,socket,sys,os,pathlib,hashlib
runpy.run_path('/dev/null',run_name='__main__')
files={str(pathlib.Path(m.__file__).resolve()) for m in list(sys.modules.values())
       if isinstance(getattr(m,'__file__',None),str) and m.__file__.startswith('/')}
for row in pathlib.Path('/proc/self/maps').read_text().splitlines():
 columns=row.split(maxsplit=5)
 if len(columns)==6 and columns[5].startswith('/'):
  assert not columns[5].endswith(' (deleted)')
  files.add(str(pathlib.Path(columns[5]).resolve()))
binary=str(pathlib.Path(sys.executable).resolve());files.add(binary)
print(json.dumps({'files':sorted(files),'executable':binary,'prefix':sys.base_prefix}))
'''


def runtime_fixture(tmp_path):
    observed = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', _ORIGINS],
        capture_output=True, timeout=10, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
    assert observed.returncode == 0, observed.stderr
    assert len(observed.stdout) <= 65536
    record = json.loads(observed.stdout)
    assert 1 <= len(record['files']) <= 512
    root = tmp_path/'runtime'; root.mkdir()
    pins = {}
    origins = {path: path for path in record['files']}
    binary = Path(record['executable'])
    interpreter = images._elf_interpreter(binary.read_bytes())
    if interpreter is not None:
        origins[interpreter] = str(Path(interpreter).resolve())
    for destination, origin in origins.items():
        raw, mode = views._read_regular(Path(origin))
        pins[origin] = (raw, mode)
        target = root/destination.removeprefix('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw); target.chmod(mode)
    runtime = views.inspect_view(root, tuple(path.removeprefix('/') for path in origins))
    (tmp_path/'runtime-origins.json').write_text(json.dumps({path: {
        'sha256': hashlib.sha256(raw).hexdigest(), 'mode': mode, 'bytes': len(raw)}
        for path, (raw, mode) in pins.items()}, sort_keys=True))
    return runtime, record['executable'], record['prefix']+'/lib', pins


def test_real_interpreter_and_libraries_run_without_host_runtime_mounts(tmp_path, socket_root):
    runtime, binary, library_path, pins = runtime_fixture(tmp_path)
    application = '''import errno,os,sys,socket
assert not os.path.exists('/docker') and not os.path.exists('/home') and not os.path.exists('/proc')
for descriptor in range(3,64):
 try:os.fstat(descriptor)
 except OSError as error:assert error.errno==errno.EBADF
 else:raise AssertionError('unexpected inherited capability')
for path in ('/work/application.py',sys.executable):
 try:open(path,'wb')
 except OSError as error:assert error.errno==errno.EROFS
 else:raise AssertionError('frozen input is writable')
with socket.socket(socket.AF_INET) as connection:
 connection.settimeout(.2)
 try:connection.connect(('1.1.1.1',443))
 except OSError:pass
 else:raise AssertionError('no-network profile reached an external address')
print('closed-runtime-running',flush=True)
assert sys.stdin.buffer.read(1)==b'Q'
'''
    source_root = tmp_path/'source'; source_root.mkdir()
    (source_root/'application.py').write_text(application)
    source = views.inspect_view(source_root, ('application.py',))
    image = images.compose_execution_image(source, runtime, destination=tmp_path/'image', executable=binary)
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(socket_root/'ready.sock')); os.chmod(socket_root/'ready.sock', 0o600)
    listener.listen(1)
    frozen = None; plan = None; process = None
    try:
        frozen = immutable.freeze_execution_image(image.image, deadline=time.monotonic()+30,
                                                   ready_listener=listener)
        plan = held.prepare_closed_held_python(frozen, image, ready_listener=listener,
            script='application.py', library_path=library_path)
        process = subprocess.Popen(plan.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, pass_fds=plan.bootstrap_descriptors)
        try:
            observation = plan.observe(supervisor=owner.ProcessIdentity.observe(os.getpid()),
                                       deadline=time.monotonic()+20)
        except BaseException:
            if process.poll() is not None:
                _stdout, stderr = process.communicate(timeout=5)
                raise AssertionError(stderr) from None
            raise
        # These are only private composition copies, never the shared interpreter.
        (image.image.root/binary.removeprefix('/')).write_bytes(b'host alias changed')
        (source_root/'application.py').write_text("raise AssertionError('source alias leaked')")
        assert owner.ProcessIdentity.observe(observation.identity.pid) == observation.identity
        plan.release()
        assert process.stdout.readline() == 'closed-runtime-running\n'
        peer_module=importlib.import_module('_bcf_owner_runtime.evidence_held_peer')
        expected=views.WorkingView(frozen.view.root/'work',source.manifest,source.digest)
        # Independent query after release inspects the same real kernel view.
        again=peer_module.inspect_held_process(observation.identity,expected_view=expected,
            supervisor=owner.ProcessIdentity.observe(os.getpid()),deadline=time.monotonic()+15)
        assert again==observation
        # Equal digests never substitute for the actual retained source inode.
        with pytest.raises(owner.OwnerAdmissionError):
            peer_module.inspect_held_process(observation.identity,expected_view=source,
                supervisor=owner.ProcessIdentity.observe(os.getpid()),deadline=time.monotonic()+15)
        with pytest.raises(owner.OwnerAdmissionError):
            peer_module.inspect_held_process(owner.ProcessIdentity.observe(os.getpid()),expected_view=expected,
                supervisor=owner.ProcessIdentity.observe(os.getpid()),deadline=time.monotonic()+15)

        assert owner.ProcessIdentity.observe(observation.identity.pid) == observation.identity
        stdout, stderr = process.communicate('Q', timeout=10)
        assert process.returncode == 0, stderr
        assert stdout == '' and not Path('/proc', str(observation.identity.pid)).exists()
    finally:
        if process is not None and process.poll() is None:
            process.kill(); process.communicate(timeout=5)
        if plan is not None:
            plan.close()
        listener.close()
        if frozen is not None:
            frozen.close()
        assert all(views._read_regular(Path(path)) == pin for path, pin in pins.items())

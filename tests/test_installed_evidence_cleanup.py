"""Exercise real child custody with the source package absent, fresh and upgraded."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess

from test_installed_evidence_storage import (
    _environment, _record, installed_consumer, isolated_python,
)


PROBE = r'''import importlib.util,json,os,signal,subprocess,sys,time
from pathlib import Path
assert importlib.util.find_spec('bcf_governance') is None
sys.path.insert(0,str(Path('scripts').resolve()))
from _bcf_runtime.evidence_execution import _run,EvidenceError
import _bcf_runtime.evidence_process_supervisor as owner
assert Path(owner.__file__).resolve().is_relative_to(Path.cwd())

def live(pid):
    for stat in Path('/proc/'+str(pid)+'/task').glob('*/stat'):
        try:raw=stat.read_text()
        except FileNotFoundError:continue
        if raw[raw.rfind(')')+2:].split()[0] not in {'Z','X'}:return True
    return False

result=_run([sys.executable,'-c',"import sys;print('é');sys.stderr.write('failure\\r\\n');sys.exit(7)"],
            cwd=Path.cwd(),timeout_seconds=2,cleanup_timeout_seconds=1)
assert (result.returncode,result.stdout,result.stderr)==(7,'é\n','failure\n')
try:
    _run([sys.executable,'-c','import sys;sys.stdout.buffer.write(bytes([255]))'],
         cwd=Path.cwd(),timeout_seconds=2,cleanup_timeout_seconds=1)
except UnicodeDecodeError:pass
else:raise AssertionError('verified cleanup changed ordinary text decoding failure')

child_code="""import json,os,sys,time
from pathlib import Path
mode=sys.argv[2]
if mode=='doublefork':
    if os.fork():os._exit(0)
    os.setsid()
    if os.fork():os._exit(0)
metadata={'pid':os.getpid(),'group':os.getpgrp(),'worker_group':int(sys.argv[3]),
          'supervisor_group':int(sys.argv[4])}
Path(sys.argv[1]).write_text(json.dumps(metadata))
if mode=='threaded':
    import threading,ctypes
    threading.Thread(target=lambda:time.sleep(20)).start()
    ctypes.CDLL(None).pthread_exit(None)
time.sleep(20)
"""
worker_code="""import os,subprocess,sys,time
from pathlib import Path
marker=Path(sys.argv[1]);mode=sys.argv[2]
subprocess.Popen([sys.executable,'-c',sys.argv[3],str(marker),mode,
                  str(os.getpgrp()),str(os.getppid())],
                 start_new_session=mode in {'setsid','doublefork'},
                 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
end=time.monotonic()+1
while not marker.exists():
    assert time.monotonic()<end,'fixture child not ready'
    time.sleep(0.005)
if mode=='threaded':
    import json
    pid=json.loads(marker.read_text())['pid']
    while True:
        path=Path('/proc/'+str(pid));raw=(path/'stat').read_text()
        if raw[raw.rfind(')')+2:].split()[0]=='Z' and len(list((path/'task').iterdir()))>1:break
        assert time.monotonic()<end,'fixture did not establish zombie thread leader'
        time.sleep(0.005)
if mode=='timeout':time.sleep(20)
"""
for mode in ('timeout','background','threaded','setsid','doublefork'):
    marker=Path('probe-owned-'+mode+'.json')
    result=_run([sys.executable,'-c',worker_code,str(marker),mode,child_code],
                cwd=Path.cwd(),timeout_seconds=2,cleanup_timeout_seconds=1)
    assert result.returncode==126,(mode,result)
    assert 'execution infrastructure failure' in result.stderr
    assert marker.exists(),'fixture never established child'
    metadata=json.loads(marker.read_text())
    assert not live(metadata['pid']),'installed command abandoned '+mode

effect=Path('unexpected-command-effect')
effect_code="from pathlib import Path;Path('unexpected-command-effect').write_text('effect')"
rejected=0
for budget in (None,0,-1,False,1.5,'1',21601):
    try:_run([sys.executable,'-c',effect_code],cwd=Path.cwd(),timeout_seconds=1,
             cleanup_timeout_seconds=budget)
    except EvidenceError:rejected+=1
    else:raise AssertionError('invalid cleanup executed '+repr(budget))
assert not effect.exists()
original=signal.getsignal(signal.SIGCHLD)
try:
    signal.signal(signal.SIGCHLD,signal.SIG_IGN)
    try:_run([sys.executable,'-c',effect_code],cwd=Path.cwd(),timeout_seconds=1)
    except EvidenceError as exc:assert 'SIGCHLD' in str(exc)
    else:raise AssertionError('nonexclusive wait owner executed effect')
finally:signal.signal(signal.SIGCHLD,original)
assert not effect.exists() and rejected==7
print(json.dumps({'authority':False,'source_package_absent':True,'child_modes':5,
                  'invalid_budgets':rejected,'normal_nonzero':True,'sigchld_guard':True,
                  'decode_failure_preserved':True}))
'''


def test_installed_evidence_commands_retain_kernel_child_custody(installed_consumer, isolated_python):
    process = subprocess.Popen(
        [str(isolated_python), '-I', '-c', PROBE], cwd=installed_consumer,
        env=_environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True,
    )
    try:
        output, error = process.communicate(timeout=20)
        assert process.returncode == 0, _record(subprocess.CompletedProcess(
            process.args, process.returncode, output, error,
        ))
        assert json.loads(output) == {
            'authority': False, 'source_package_absent': True, 'child_modes': 5,
            'invalid_budgets': 7, 'normal_nonzero': True, 'sigchld_guard': True,
            'decode_failure_preserved': True,
        }
    finally:
        # Retire only processes created and recorded by this fixture, on failure too.
        for marker in installed_consumer.glob('probe-owned-*.json'):
            metadata = json.loads(marker.read_text())
            for group in {metadata['group'], metadata['worker_group'], metadata['supervisor_group']}:
                assert group != os.getpgrp()
                try:
                    os.killpg(group, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=2)

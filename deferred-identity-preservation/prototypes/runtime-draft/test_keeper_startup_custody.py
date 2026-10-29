"""Real inherited OFD tests with synthetic leases; no actual execution/backend."""
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import pytest
from test_owner_registration import registration as _registration
keeper=importlib.import_module('_bcf_owner_runtime.evidence_lease_keeper')

@pytest.mark.parametrize('failure',['core_digest','start_shape','prestart_eof'])
def test_bootstrap_failure_keeps_original_synthetic_ofd(tmp_path,failure):
    path=tmp_path/'synthetic.lock';lease=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
    fcntl.flock(lease,fcntl.LOCK_EX)
    info=os.fstat(lease)
    root=tmp_path/'custody';root.mkdir(mode=0o700)
    parent,child=socket.socketpair();process=None
    core=Path(keeper.__file__).with_name('evidence_process_supervisor.py')
    digest='0'*64 if failure=='core_digest' else hashlib.sha256(core.read_bytes()).hexdigest()
    try:
        process=subprocess.Popen([sys.executable,'-I','-B',keeper.__file__,str(child.fileno()),str(root),'a'*64,'2','1',digest,json.dumps([[lease,info.st_dev,info.st_ino]])],pass_fds=(child.fileno(),lease),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        child.close();parent.settimeout(2)
        if failure!='core_digest':
            assert keeper._receive(parent)['state']=='ready'
            if failure=='start_shape':keeper._send(parent,{'operation':'start','unexpected':True})
            else:parent.close()
        os.close(lease);lease=-1
        time.sleep(.3)
        assert process.poll() is None,'bootstrap error released inherited lease'
        probe=os.open(path,os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
            held=Path('/proc',str(process.pid),'fd')
            assert any((entry.stat().st_dev,entry.stat().st_ino)==(info.st_dev,info.st_ino) for entry in held.iterdir())
        finally:os.close(probe)
    finally:
        parent.close();child.close()
        if lease>=0:os.close(lease)
        if process is not None:
            if process.poll() is None:process.terminate()
            process.communicate(timeout=5)
    # Only the synthetic fixture lock is retired, after test child exit/reap.
    probe=os.open(path,os.O_RDWR)
    try:fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
    finally:os.close(probe)

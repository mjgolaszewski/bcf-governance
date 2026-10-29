"""Real guarded held-source lifecycle using a synthetic outer budget and lease."""
from dataclasses import asdict
import fcntl
import hashlib
import importlib
import multiprocessing
import os
from pathlib import Path
import sys
import time

import pytest
from test_owner_registration import registration as _registration
from test_keeper_owner_composition import idle_budget

owner = importlib.import_module('_bcf_owner_runtime.evidence_execution_owner')
views = importlib.import_module('_bcf_owner_runtime.evidence_execution_view')
immutable = importlib.import_module('_bcf_owner_runtime.evidence_immutable_source')
launcher = importlib.import_module('_bcf_owner_runtime.evidence_held_invocation')
keepers = importlib.import_module('_bcf_owner_runtime.evidence_lease_keeper')
core = importlib.import_module('_bcf_owner_runtime.evidence_process_supervisor')


def test_native_guardian_starts_held_process_before_actual_context_is_bound(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'application.py').write_text('''import errno,os
from pathlib import Path
assert not Path('/proc').exists() and not Path('/docker').exists()
for fd in range(3,128):
 try:os.fstat(fd)
 except OSError as error:assert error.errno==errno.EBADF
 else:raise AssertionError('bootstrap or original lease leaked')
try:Path('/work/application.py').write_text('changed')
except OSError as error:assert error.errno==errno.EROFS
else:raise AssertionError('source was mutable')
print('actual-frozen-script')
''')
    view = views.inspect_view(source, ('application.py',))
    frozen = immutable.freeze_source(view, deadline=time.monotonic()+10)
    plan = launcher.prepare_held_python(frozen, script='application.py')
    ready_parent, ready_child = multiprocessing.Pipe(False)
    stop_parent, stop_child = multiprocessing.Pipe()
    budget = multiprocessing.Process(target=idle_budget, args=(ready_child, stop_child))
    budget.start()
    lease = -1
    keeper = None
    try:
        assert ready_parent.poll(5)
        budget_pid = ready_parent.recv()
        ready_parent.close();ready_child.close();stop_child.close()
        lock = tmp_path / 'synthetic.lock'
        lease = os.open(lock, os.O_CREAT|os.O_EXCL|os.O_RDWR, 0o600)
        fcntl.flock(lease, fcntl.LOCK_EX)
        evidence = tmp_path / 'keeper'
        evidence.mkdir(mode=0o700)
        keeper = keepers.ExecutionLeaseKeeper(lease_descriptors=(lease,), evidence_root=evidence,
            timeout_seconds=8, cleanup_seconds=1,
            protected_budget_owner=owner.ProcessIdentity.observe(budget_pid),
            bootstrap_descriptors=plan.bootstrap_descriptors)
        os.close(lease);lease=-1
        keeper.start(plan.command, cwd=tmp_path, environment={
            'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'})
        deadline = time.monotonic()+5
        while True:
            status = keeper.status()
            if 'native_supervisor_pid' in status:
                break
            assert status['state']=='pending' and time.monotonic()<deadline
        assert keeper.context_digest is None
        observed = plan.observe(supervisor=owner.ProcessIdentity.observe(status['native_supervisor_pid']),
                                deadline=deadline)
        assert observed.source_digest==view.digest
        raw = views.context_manifest(frozen.view, runtime={'qualification':'mechanical-only'},
            producer='synthetic',profile='held-plan',control='baseline',
            deadline_ns=int(deadline*1e9),invocation_nonce=os.urandom(16).hex(),
            controller=asdict(owner.ProcessIdentity.observe(budget_pid)),
            held_peer=asdict(observed.identity))
        actual_context = hashlib.sha256(raw).hexdigest()
        keeper.bind_actual_context(actual_context)
        (source/'application.py').write_text("raise AssertionError('host bytes leaked')")
        plan.release()
        with pytest.raises(owner.OwnerAdmissionError):
            plan.release()
        while True:
            terminal = keeper.status()
            if terminal['state']!='pending':
                break
            assert time.monotonic()<deadline
        assert terminal['state']=='native_closed' and terminal['returncode']==0, terminal
        assert terminal['stdout']=='actual-frozen-script\n' and terminal['stderr']==''
        assert not Path('/proc',str(observed.identity.pid)).exists()
        probe = os.open(lock,os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally:os.close(probe)
        # No issuer was ever staged. Still, native closure alone cannot release
        # this synthetic fixture lease; cleanup below kills only this test keeper.
    finally:
        if lease>=0:os.close(lease)
        if keeper is not None:
            keeper.disconnect()
            if keeper.process.poll() is None:keeper.process.terminate()
            keeper.process.communicate(timeout=5)
        plan.close();frozen.close()
        try:stop_parent.send('done')
        except (BrokenPipeError,EOFError):pass
        stop_parent.close()
        budget.join(2)
        if budget.is_alive():budget.terminate();budget.join(2)
        assert not budget.is_alive()


def test_original_regular_lease_cannot_become_a_bootstrap_capability(tmp_path):
    descriptor = os.open(tmp_path/'synthetic.lock',os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
    fcntl.flock(descriptor,fcntl.LOCK_EX)
    mount = os.open('/proc/self/ns/mnt',os.O_RDONLY)
    user = os.open('/proc/self/ns/user',os.O_RDONLY)
    try:
        with pytest.raises(core.OwnedProcessError,match='directory'):
            core.run_owned_command([sys.executable,'-c','raise AssertionError("must not execute")'],
                cwd=tmp_path,env={},timeout_seconds=1,cleanup_seconds=1,
                bootstrap_descriptors=(descriptor,mount,user))
    finally:
        for value in (descriptor,mount,user):os.close(value)

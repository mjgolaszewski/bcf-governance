"""Actual frozen-view/held-peer composition; no credentials or runtime admission."""
import importlib
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from test_owner_registration import registration as _registration
views=importlib.import_module('_bcf_owner_runtime.evidence_execution_view')
immutable=importlib.import_module('_bcf_owner_runtime.evidence_immutable_source')
peers=importlib.import_module('_bcf_owner_runtime.evidence_held_peer')
owner=importlib.import_module('_bcf_owner_runtime.evidence_execution_owner')


def test_frozen_view_executes_without_changing_admitted_kernel_lifetime(tmp_path):
    candidate="""import errno,os,sys
from pathlib import Path
assert not Path('/docker').exists() and not Path('/home').exists() and not Path('/proc').exists()
for fd in range(3,64):
 try:os.fstat(fd)
 except OSError as error:assert error.errno==errno.EBADF
 else:raise AssertionError('unexpected inherited capability')
try:Path('/work/application.py').write_text('changed')
except OSError as error:assert error.errno==errno.EROFS
else:raise AssertionError('source is writable')
print('candidate-running',flush=True)
assert sys.stdin.buffer.read(1)==b'Q'
"""
    (tmp_path/'application.py').write_text(candidate)
    view=views.inspect_view(tmp_path,('application.py',))
    frozen=immutable.freeze_source(view,deadline=time.monotonic()+10)
    capabilities=frozen.duplicate_execution_capabilities()
    assert all(not os.get_inheritable(fd) for fd in capabilities)
    address='bcf-immutable-held-'+os.urandom(16).hex()
    stub="""import runpy,socket,sys
with socket.socket(socket.AF_UNIX) as connection:
 connection.connect('\\0'+sys.argv[1]);connection.sendall(b'held')
 assert connection.recv(1)==b'R'
runpy.run_path('/work/application.py',run_name='__main__')
"""
    prefix=Path(sys.base_prefix).resolve()
    command=['/usr/bin/bwrap','--unshare-user','--unshare-pid','--unshare-ipc',
        '--unshare-uts','--new-session','--die-with-parent','--cap-drop','ALL',
        '--ro-bind','/usr','/usr','--ro-bind','/lib','/lib','--ro-bind','/lib64','/lib64',
        '--ro-bind','/view','/work','--dev','/dev','--tmpfs','/tmp',
        '--clearenv','--setenv','LD_LIBRARY_PATH',str(prefix/'lib')]
    if not prefix.is_relative_to('/usr'):
        command.extend(['--ro-bind',str(prefix),str(prefix)])
    command.extend([str(Path(sys.executable).resolve()),'-I','-S','-B','-c',stub,address])
    bootstrap="""import os,sys
view,mount,user=map(int,sys.argv[1:4])
os.setns(user,0)
os.setns(mount,0)
root=os.open('..',os.O_RDONLY|os.O_DIRECTORY,dir_fd=view)
expected=os.fstat(view);actual=os.stat('view',dir_fd=root)
assert (expected.st_dev,expected.st_ino)==(actual.st_dev,actual.st_ino)
os.fchdir(root);os.chroot('.');os.chdir('/')
for descriptor in (view,mount,user,root):os.close(descriptor)
os.execv(sys.argv[4],sys.argv[4:])
"""
    launch=[str(Path(sys.executable).resolve()),'-I','-S','-B','-c',bootstrap,
            *(str(fd) for fd in capabilities),*command]
    process=None
    try:
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind('\0'+address);listener.listen(1)
            process=subprocess.Popen(launch,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=capabilities,text=True)
            supervisor=owner.ProcessIdentity.observe(os.getpid())
            try:
                connection,observation=peers.observe_held_namespace(listener,expected_view=frozen.view,
                    supervisor=supervisor,deadline=time.monotonic()+5)
            except BaseException:
                if process.poll() is not None:
                    _output,error=process.communicate(timeout=5)
                    raise AssertionError(error) from None
                raise
            listener.close()  # Candidate cannot reconnect to the admission listener.
            with connection:
                assert connection.recv(4)==b'held'
                (tmp_path/'application.py').write_text("raise AssertionError('host write leaked')")
                assert owner.ProcessIdentity.observe(observation.identity.pid)==observation.identity
                connection.sendall(b'R')
            assert process.stdout.readline()=='candidate-running\n'
            assert owner.ProcessIdentity.observe(observation.identity.pid)==observation.identity
            assert (frozen.view.root/'application.py').read_text()==candidate
            stdout,stderr=process.communicate('Q',timeout=5)
            assert process.returncode==0,stderr
            assert stdout=='' and not Path('/proc',str(observation.identity.pid)).exists()
    finally:
        if process is not None and process.poll() is None:
            process.kill();process.communicate(timeout=5)
        for descriptor in capabilities:os.close(descriptor)
        frozen.close()

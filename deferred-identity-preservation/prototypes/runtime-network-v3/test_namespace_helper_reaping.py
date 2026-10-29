"""Trusted bootstrap waits for real helpers; raw commands still reject orphans."""
import importlib
import os
from pathlib import Path
import signal
import sys
import time

import pytest

from test_closed_runtime_held import views, immutable

core=importlib.import_module('_bcf_owner_runtime.evidence_process_supervisor')
bootstrap=importlib.import_module('_bcf_owner_runtime.evidence_namespace_bootstrap')


def wrapped(tmp_path, program):
    source=tmp_path/'source';source.mkdir()
    (source/'scope.py').write_text('pass\n')
    frozen=immutable.freeze_source(views.inspect_view(source,('scope.py',)),deadline=time.monotonic()+10)
    descriptors=()
    try:
        descriptors=frozen.duplicate_execution_capabilities()
        binary=str(Path(sys.executable).resolve())
        command=[binary,'-I','-S','-B','-c',bootstrap.ENTER_VIEW,
            *(str(fd) for fd in descriptors),binary,'-I','-S','-B','-c',program]
        return core.run_owned_command(command,cwd=tmp_path,
            env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},timeout_seconds=5,cleanup_seconds=1,
            bootstrap_descriptors=descriptors)
    finally:
        for descriptor in descriptors:os.close(descriptor)
        frozen.close()


def test_bootstrap_waits_for_real_double_forked_helper_before_returning(tmp_path):
    result=wrapped(tmp_path,"import os,time\nif os.fork():os._exit(0)\nos.setsid()\nif os.fork():os._exit(0)\ntime.sleep(.1)\nprint('helper-finished',flush=True)\n")
    assert result.returncode==0,result
    assert result.stdout=='helper-finished\n' and result.stderr==''


@pytest.mark.parametrize('program,code',[("raise SystemExit(7)",7),
    ("import os,signal;os.kill(os.getpid(),signal.SIGTERM)",-signal.SIGTERM)])
def test_bootstrap_preserves_original_program_terminal_status(tmp_path,program,code):
    result=wrapped(tmp_path,program)
    assert result.returncode==code,result
    assert result.stdout=='' and result.stderr==''


def test_native_guardian_still_rejects_unwrapped_live_orphan(tmp_path):
    result=core.run_owned_command([sys.executable,'-I','-B','-c',
        "import os,time\nif os.fork():os._exit(0)\nos.setsid()\ntime.sleep(1)\n"],
        cwd=tmp_path,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},timeout_seconds=3,cleanup_seconds=1)
    assert result.returncode==126
    assert 'command left live descendants' in result.stderr

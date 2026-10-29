"""Real read-only namespace bytes and descriptor retention, not JIT custody."""
import errno
import importlib
import os
from pathlib import Path
import time

import pytest

from test_owner_registration import registration as _registration

module=importlib.import_module('_bcf_owner_runtime.evidence_immutable_source')
view_module=importlib.import_module('_bcf_owner_runtime.evidence_execution_view')


def test_host_writes_cannot_change_the_frozen_namespace(tmp_path):
    original=tmp_path/'source';original.mkdir();(original/'application.py').write_text('original')
    (original/'nested').mkdir();(original/'nested/data.json').write_text('{}')
    view=view_module.inspect_view(original,('application.py','nested/data.json'))
    frozen=module.freeze_source(view,deadline=time.monotonic()+10)
    try:
        (original/'application.py').write_text('host changed')
        assert (frozen.view.root/'application.py').read_text()=='original'
        with pytest.raises(OSError) as error:
            (frozen.view.root/'application.py').write_text('namespace changed')
        assert error.value.errno==errno.EROFS
        with pytest.raises(OSError) as error:
            (frozen.view.root/'new.py').write_text('added')
        assert error.value.errno==errno.EROFS
        assert os.readlink(Path('/proc/self/fd',str(frozen.namespace_fd)))==frozen.namespace
    finally:frozen.close()


def test_both_namespace_capabilities_can_be_retained_by_an_outside_owner(tmp_path):
    (tmp_path/'application.py').write_text('pinned')
    view=view_module.inspect_view(tmp_path,('application.py',))
    frozen=module.freeze_source(view,deadline=time.monotonic()+10)
    directory,namespace=frozen.duplicate_capabilities()
    try:
        frozen.close()
        assert Path('/proc/self/fd',str(directory),'application.py').read_text()=='pinned'
        assert os.readlink(Path('/proc/self/fd',str(namespace))).startswith('mnt:[')
        assert not os.get_inheritable(directory) and not os.get_inheritable(namespace)
    finally:os.close(directory);os.close(namespace)


def test_changed_input_refuses_before_a_view_is_returned(tmp_path):
    path=tmp_path/'application.py';path.write_text('original')
    view=view_module.inspect_view(tmp_path,('application.py',));path.write_text('changed')
    with pytest.raises(module.OwnerAdmissionError,match='source changed'):
        module.freeze_source(view,deadline=time.monotonic()+10)


def test_large_source_population_uses_one_readonly_filesystem(tmp_path):
    names=tuple('source/module_'+str(index)+'.py' for index in range(256))
    (tmp_path/'source').mkdir()
    for index,name in enumerate(names):
        path=tmp_path/name;path.write_text('value = '+str(index)+'\n');path.chmod(0o644 if index%2 else 0o600)
    view=view_module.inspect_view(tmp_path,names)
    frozen=module.freeze_source(view,deadline=time.monotonic()+20)
    descriptors=[]
    try:
        descriptors.append(os.open(frozen.view.root,os.O_RDONLY|os.O_DIRECTORY))
        for index,name in enumerate(names):
            path=frozen.view.root/name
            assert path.read_text()=='value = '+str(index)+'\n'
            assert path.stat().st_mode&0o777==(0o644 if index%2 else 0o600)
            assert os.statvfs(path).f_flag&os.ST_RDONLY
        for name in (names[0],names[-1]):descriptors.append(os.open(frozen.view.root/name,os.O_RDONLY))
        mount_ids={next(line for line in Path('/proc/self/fdinfo',str(fd)).read_text().splitlines() if line.startswith('mnt_id:')) for fd in descriptors}
        assert len(mount_ids)==1
        (tmp_path/names[0]).write_text('changed host input')
        assert (frozen.view.root/names[0]).read_text()=='value = 0\n'
        with pytest.raises(OSError) as error:(frozen.view.root/names[-1]).write_text('changed snapshot')
        assert error.value.errno==errno.EROFS
    finally:
        for descriptor in descriptors:os.close(descriptor)
        frozen.close()


def test_actual_seals_hold_when_python_omits_symbolic_exports(monkeypatch):
    for name in ('F_SEAL_WRITE','F_SEAL_GROW','F_SEAL_SHRINK','F_SEAL_SEAL','F_ADD_SEALS','F_GET_SEALS'):
        monkeypatch.delattr(module.fcntl,name,raising=False)
    descriptor=module._sealed(b'fixed')
    try:
        assert module.fcntl.fcntl(descriptor,1034)==0x000f
        for operation in (lambda:os.write(descriptor,b'x'),lambda:os.ftruncate(descriptor,1),lambda:os.ftruncate(descriptor,99)):
            with pytest.raises(OSError) as failure:operation()
            assert failure.value.errno==errno.EPERM
    finally:os.close(descriptor)

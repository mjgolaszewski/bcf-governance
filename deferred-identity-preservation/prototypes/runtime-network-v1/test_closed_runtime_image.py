"""Closed image byte/layout controls; no provider or release acceptance."""
import importlib
import os
from pathlib import Path
import struct
import time

import pytest

from test_owner_registration import registration as _registration

image = importlib.import_module('_bcf_owner_runtime.evidence_closed_runtime_image')
views = importlib.import_module('_bcf_owner_runtime.evidence_execution_view')
immutable = importlib.import_module('_bcf_owner_runtime.evidence_immutable_source')


def executable(loader=None):
    raw = bytearray(120)
    raw[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<H', raw, 18, 62)
    struct.pack_into('<Q', raw, 32, 64)
    struct.pack_into('<HH', raw, 54, 56, 1)
    if loader is not None:
        value = loader.encode() + b'\0'
        struct.pack_into('<I', raw, 64, 3)
        struct.pack_into('<Q', raw, 72, 120)
        struct.pack_into('<Q', raw, 96, len(value))
        raw.extend(value)
    return bytes(raw)


def inputs(tmp_path, *, runtime_name='usr/bin/python', loader=None):
    source = tmp_path / 'source'; source.mkdir()
    (source / 'application.py').write_text('answer = 42\n')
    runtime = tmp_path / 'runtime'; runtime.mkdir()
    target = runtime / runtime_name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(executable(loader)); target.chmod(0o755)
    return (views.inspect_view(source, ('application.py',)),
            views.inspect_view(runtime, (runtime_name,)))


def test_exact_source_runtime_bytes_remain_separate(tmp_path):
    source, runtime = inputs(tmp_path)
    result = image.compose_execution_image(source, runtime, destination=tmp_path/'image',
                                           executable='/usr/bin/python')
    assert result.source_digest == source.digest and result.runtime_digest == runtime.digest
    assert [row[0] for row in result.image.manifest] == ['usr/bin/python', 'work/application.py']
    assert (result.image.root/'usr/bin/python').read_bytes() == executable()
    assert (result.image.root/'work/application.py').read_text() == 'answer = 42\n'
    result.recheck()
    (result.image.root/'usr/bin/python').write_bytes(b'changed')
    with pytest.raises(views.ExecutionViewError, match='changed'):
        result.recheck()


@pytest.mark.parametrize('name', ['work/bin/python', 'proc/python', 'sys/python',
                                 'dev/python', 'tmp/python', 'run/python', 'usr/unsafe.pth'])
def test_reserved_runtime_paths_refuse_before_destination(tmp_path, name):
    source, runtime = inputs(tmp_path, runtime_name=name)
    with pytest.raises(views.ExecutionViewError):
        image.compose_execution_image(source, runtime, destination=tmp_path/'image', executable='/'+name)
    assert not (tmp_path/'image').exists()


@pytest.mark.parametrize('which', ['source', 'runtime'])
def test_changed_input_refuses_before_destination(tmp_path, which):
    source, runtime = inputs(tmp_path)
    target = source.root/'application.py' if which == 'source' else runtime.root/'usr/bin/python'
    target.write_bytes(b'changed')
    with pytest.raises(views.ExecutionViewError):
        image.compose_execution_image(source, runtime, destination=tmp_path/'image', executable='/usr/bin/python')
    assert not (tmp_path/'image').exists()


def test_missing_kernel_elf_interpreter_refuses(tmp_path):
    source, runtime = inputs(tmp_path, loader='/lib64/ld-linux-x86-64.so.2')
    with pytest.raises(views.ExecutionViewError, match='interpreter is not frozen'):
        image.compose_execution_image(source, runtime, destination=tmp_path/'image', executable='/usr/bin/python')
    assert not (tmp_path/'image').exists()


def test_nominated_elf_interpreter_is_in_exact_frozen_population(tmp_path):
    source, runtime = inputs(tmp_path, loader='/lib64/ld-linux-x86-64.so.2')
    target = runtime.root/'lib64/ld-linux-x86-64.so.2'
    target.parent.mkdir(); target.write_bytes(b'loader fixture'); target.chmod(0o755)
    runtime = views.inspect_view(runtime.root, ('usr/bin/python', 'lib64/ld-linux-x86-64.so.2'))
    result = image.compose_execution_image(source, runtime, destination=tmp_path/'image', executable='/usr/bin/python')
    assert result.interpreter == '/lib64/ld-linux-x86-64.so.2'


def test_symlink_parent_destination_cannot_escape_owned_root(tmp_path):
    source, runtime = inputs(tmp_path)
    outside = tmp_path/'outside'; outside.mkdir()
    alias = tmp_path/'alias'; alias.symlink_to(outside, target_is_directory=True)
    with pytest.raises(views.ExecutionViewError):
        image.compose_execution_image(source, runtime, destination=alias/'image', executable='/usr/bin/python')
    assert not (outside/'image').exists()


def test_runtime_snapshot_exceeds_old_source_file_budget_and_rejects_host_writes(tmp_path):
    source, runtime = inputs(tmp_path)
    for number in range(4096):
        (runtime.root/f'file-{number}').write_bytes(b'x')
    runtime = views.inspect_view(runtime.root, ('usr/bin/python', *(f'file-{n}' for n in range(4096))))
    result = image.compose_execution_image(source, runtime, destination=tmp_path/'image', executable='/usr/bin/python')
    with pytest.raises(immutable.OwnerAdmissionError, match='cohort or deadline'):
        immutable.freeze_source(result.image, deadline=time.monotonic()+20)
    frozen = immutable.freeze_execution_image(result.image, deadline=time.monotonic()+30)
    try:
        (result.image.root/'usr/bin/python').write_bytes(b'host alias changed')
        assert (frozen.view.root/'usr/bin/python').read_bytes() == executable()
        assert len(frozen.view.manifest) == 4098
        assert os.statvfs(frozen.view.root).f_flag & os.ST_RDONLY
        with pytest.raises(OSError):
            (frozen.view.root/'usr/bin/python').write_bytes(b'namespace changed')
    finally:
        frozen.close()

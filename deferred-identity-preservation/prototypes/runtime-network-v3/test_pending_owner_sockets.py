"""Pending socket selection refuses role and readiness substitution before birth."""
import os
import socket
import time

import pytest

from test_closed_runtime_held import views, immutable, owner


@pytest.mark.parametrize('case',['unknown_role','duplicate_role','same_inode','readiness_alias','public_socket'])
def test_pending_socket_substitution_refuses_before_materialization(tmp_path,socket_root,case):
    root=tmp_path/'source';root.mkdir();(root/'program.py').write_text('pass\n')
    view=views.inspect_view(root,('program.py',))
    channels=[]
    for name in ('ready','issuer','custody'):
        channel=socket.socket(socket.AF_UNIX);path=socket_root/(name+'.sock')
        channel.bind(str(path));os.chmod(path,0o600);channel.listen(1);channels.append(channel)
    ready,issuer,custody=channels
    inputs={
        'unknown_role':(('foreign',issuer),),
        'duplicate_role':(('issuer',issuer),('issuer',custody)),
        'same_inode':(('issuer',issuer),('custody',issuer)),
        'readiness_alias':(('issuer',ready),),
        'public_socket':(('issuer',issuer),),
    }
    if case=='public_socket':os.chmod(socket_root/'issuer.sock',0o666)
    try:
        with pytest.raises(owner.OwnerAdmissionError):
            immutable.freeze_execution_image(view,deadline=time.monotonic()+10,
                ready_listener=ready,workload_listeners=inputs[case])
    finally:
        for channel in channels:channel.close()

"""Real framed adverse controls sharing one held image; no provider operations."""
import importlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

import pytest

bridge=importlib.import_module('_bcf_owner_runtime.evidence_owner_peer_bridge')
owner=importlib.import_module('_bcf_owner_runtime.evidence_execution_owner')

_ACTOR='''import importlib,json,os,socket,sys,types
package=types.ModuleType('_peer_adverse');package.__path__=[sys.argv[1]];sys.modules[package.__name__]=package
native=importlib.import_module(package.__name__+'.evidence_owner_peer_bridge')
channel=socket.socket(fileno=int(sys.argv[2]));case=sys.argv[3]
channel.send(b'ready')
if channel.recv(1)==b'G':
 if case=='wrong_listener':left=socket.socket(fileno=int(sys.argv[5]));right=socket.socket()
 else:left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
 request={'schema':native.SCHEMA,'op':'authenticate_workload','context':sys.argv[4],'sequence':1,'nonce':os.urandom(16).hex()}
 if case=='wrong_context':request['context']='f'*64
 if case=='wrong_sequence':request['sequence']=2
 if case=='unknown_field':request['pid']=os.getpid()
 raw=json.dumps(request).encode()
 if case=='duplicate_field':raw=b'{"sequence":1,'+raw[1:]
 if case=='nonfinite':raw=raw.replace(b'"sequence": 1',b'"sequence": NaN')
 if case=='malformed_json':raw=b'{'
 if case=='oversize':raw=b'x'*1025
 ancillary=[] if case=='missing_fd' else [(socket.SOL_SOCKET,socket.SCM_RIGHTS,__import__('array').array('i',[left.fileno(),right.fileno()]if case=='extra_fd'else[left.fileno()]))]
 channel.sendmsg([raw],ancillary)
 assert channel.recv(1)==b'Q'
 left.close();right.close()
channel.close();print('adverse-closed',flush=True)
'''


def exercise_rejected_frames(plan,context,deadline,tmp_path):
    """Run before release, so no adversarial frame can cause workload effects."""
    assert not plan.release_attempted
    results=[]
    idle_parent,idle_child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    idle=subprocess.Popen([sys.executable,'-I','-B','-c',
        'import socket,sys;c=socket.socket(fileno=int(sys.argv[1]));c.send(b"ready");assert c.recv(1)==b"Q"',
        str(idle_child.fileno())],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        pass_fds=(idle_child.fileno(),))
    idle_child.close();idle_parent.settimeout(5)
    try:
        assert idle_parent.recv(64)==b'ready'
        custody=owner.ProcessIdentity.observe(idle.pid)
        cases={
            'wrong_sender':(owner.OwnerAdmissionError,'sender'),
            'wrong_context':(owner.OwnerAdmissionError,'context'),
            'wrong_sequence':(owner.OwnerAdmissionError,'sequence'),
            'unknown_field':(owner.OwnerAdmissionError,'sender'),
            'missing_fd':(owner.OwnerAdmissionError,'FD'),
            'extra_fd':(owner.OwnerAdmissionError,'FD'),
            'wrong_workload':(owner.OwnerAdmissionError,'another peer'),
            'wrong_listener':(owner.OwnerAdmissionError,'pending listener'),
            'duplicate_field':(owner.OwnerAdmissionError,'duplicate'),
            'nonfinite':(owner.OwnerAdmissionError,'non-finite'),
            'malformed_json':(json.JSONDecodeError,'Expecting'),
            'oversize':(owner.OwnerAdmissionError,'frame'),
        }
        for case,(error_type,reason) in cases.items():
            parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            spare=child.dup() if case=='wrong_sender' else None
            extra=(plan._connection.fileno(),) if case=='wrong_listener' else ()
            actor=subprocess.Popen([sys.executable,'-I','-B','-c',_ACTOR,
                str(Path(bridge.__file__).parent),str(child.fileno()),case,context,
                str(extra[0])if extra else '-1'],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                pass_fds=(child.fileno(),*extra))
            child.close();parent.settimeout(5)
            try:
                assert parent.recv(64)==b'ready'
                verifier=bridge.OwnerPeerBridge(plan,context_digest=context,
                    owners={'issuer':owner.ProcessIdentity.observe(actor.pid),'custody':custody},
                    channels={'issuer':parent,'custody':idle_parent},access_deadline=deadline)
                before=len(os.listdir('/proc/self/fd'))
                if case=='wrong_sender':
                    left,right=socket.socketpair()
                    try:
                        bridge._send(spare,{'schema':bridge.SCHEMA,'op':'authenticate_workload',
                            'context':context,'sequence':1,'nonce':os.urandom(16).hex()},left.fileno())
                    finally:left.close();right.close()
                else:parent.send(b'G')
                with pytest.raises(error_type,match=reason):verifier.handle_once('issuer')
                assert len(os.listdir('/proc/self/fd'))==before
                with pytest.raises(owner.OwnerAdmissionError,match='uncertain'):
                    verifier.handle_once('issuer')
                assert not plan.release_attempted
                parent.send(b'Q')
                output,error=actor.communicate(timeout=5)
                assert actor.returncode==0,error
                assert output==b'adverse-closed\n'
                results.append({'case':case,'expected_cause':reason,'received_FDs_closed':True,
                    'no_retry':True,'workload_still_held':True,'owner_reaped':True})
            finally:
                if actor.poll() is None:actor.kill()
                actor.communicate(timeout=5);parent.close()
                if spare is not None:spare.close()
        (tmp_path/'owner-peer-adverse-results.json').write_text(json.dumps(results,indent=2)+'\n')
    finally:
        try:idle_parent.send(b'Q')
        except OSError:pass
        if idle.poll() is None:
            try:idle.communicate(timeout=5)
            except subprocess.TimeoutExpired:idle.kill();idle.communicate(timeout=5)
        idle_parent.close()

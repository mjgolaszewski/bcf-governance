"""Bounded native Docker exec completion; caller retains actual container custody.

CLI exit and attach EOF never establish daemon exec termination. This adapter
creates exactly one ExecID, records it before start, and inspects its terminal
state. A timeout/transport failure grants no replay or cleanup/lease release.
"""
from __future__ import annotations
from dataclasses import dataclass
import http.client
import json
import math
import os
import re
import socket
import stat
import struct
import time
from collections.abc import Callable

API='/v1.45'
class ExecUncertain(RuntimeError):
    pass

@dataclass(frozen=True)
class ExecResult:
    exec_id: str
    returncode: int
    stdout: bytes
    stderr: bytes

class NativeExec:
    def __init__(self, *, socket_path: str, daemon_id: str, deadline: float):
        if (socket_path!='/var/run/docker.sock' or type(daemon_id)is not str or not daemon_id
                or type(deadline)not in(int,float) or not math.isfinite(deadline)
                or not 0<deadline-time.monotonic()<=900):
            raise ExecUncertain('fixed finite operator daemon scope required')
        self.path=socket_path;self.daemon=daemon_id;self.deadline=deadline
        s=os.stat(self.path,follow_symlinks=False)
        if not stat.S_ISSOCK(s.st_mode):raise ExecUncertain('native daemon socket required')
        self.identity=(s.st_dev,s.st_ino,s.st_uid)
        if self.request('GET','/info').get('ID')!=daemon_id:
            raise ExecUncertain('native daemon identity differs')

    def remaining(self) -> float:
        value=self.deadline-time.monotonic()
        if value<=0:raise ExecUncertain('original native exec budget expired; retain container custody')
        return value

    def connect(self) -> socket.socket:
        s=os.stat(self.path,follow_symlinks=False)
        if (s.st_dev,s.st_ino,s.st_uid)!=self.identity or not stat.S_ISSOCK(s.st_mode):
            raise ExecUncertain('native daemon socket lifetime changed')
        connection=socket.socket(socket.AF_UNIX)
        try:
            connection.settimeout(min(10.,self.remaining()));connection.connect(self.path)
            return connection
        except BaseException:
            connection.close();raise

    def request(self, method: str, path: str, body: dict | None=None) -> dict:
        connection=http.client.HTTPConnection('localhost',timeout=min(10.,self.remaining()))
        connection.sock=self.connect()
        try:
            raw=None if body is None else json.dumps(body,allow_nan=False).encode()
            connection.request(method,API+path,body=raw,headers={'Content-Type':'application/json'})
            response=connection.getresponse();raw=response.read(65537)
            if response.status not in(200,201) or len(raw)>65536:
                raise ExecUncertain('native daemon response refused')
            result=json.loads(raw)
            if type(result)is not dict:raise ExecUncertain('native daemon object required')
            self.remaining();return result
        finally:connection.close()

    def exact(self, connection: socket.socket, count: int, *, eof: bool=False) -> bytes:
        result=bytearray()
        while len(result)<count:
            connection.settimeout(min(10.,self.remaining()))
            part=connection.recv(count-len(result))
            if not part:
                if eof and not result:return b''
                raise ExecUncertain('native exec framing ended early')
            result.extend(part)
        return bytes(result)

    def run(self, container_id: str, command: tuple[str,...], *, data: bytes | None=None,
            observe: Callable[[dict],None]) -> ExecResult:
        if (type(container_id)is not str or re.fullmatch('[0-9a-f]{64}',container_id)is None
                or type(command)is not tuple or not 1<=len(command)<=64
                or any(type(x)is not str or chr(0)in x for x in command)
                or sum(map(len,command))>32768
                or data is not None and(type(data)is not bytes or len(data)>16384)):
            raise ExecUncertain('native exec command/input scope refused')
        created=self.request('POST','/containers/'+container_id+'/exec',{
            'AttachStdin':data is not None,'AttachStdout':True,'AttachStderr':True,
            'Tty':False,'Cmd':list(command)})
        identifier=created.get('Id')
        if type(identifier)is not str or re.fullmatch('[0-9a-f]{64}',identifier)is None:
            raise ExecUncertain('native daemon ExecID missing')
        observe({'stage':'native-exec-created','container_id':container_id,'exec_id':identifier})
        connection=self.connect();outputs={1:bytearray(),2:bytearray()}
        try:
            raw=b'{"Detach":false,"Tty":false}'
            headers=('POST '+API+'/exec/'+identifier+'/start HTTP/1.1\r\nHost: localhost\r\n'
                'Content-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n'
                'Content-Length: '+str(len(raw))+'\r\n\r\n').encode()
            connection.sendall(headers+raw)
            response=bytearray()
            while not response.endswith(b'\r\n\r\n'):
                if len(response)>=16384:raise ExecUncertain('native exec HTTP header exceeds bound')
                response.extend(self.exact(connection,1))
            if response.split(b'\r\n',1)[0].split()[1]!=b'101':
                raise ExecUncertain('native exec upgrade refused; never restart')
            if data:connection.sendall(data)
            connection.shutdown(socket.SHUT_WR)
            while header:=self.exact(connection,8,eof=True):
                stream=header[0];length=struct.unpack('!I',header[4:])[0]
                if stream not in outputs or header[1:4]!=b'\0\0\0' or length>65536-sum(map(len,outputs.values())):
                    raise ExecUncertain('native exec output framing/budget refused')
                outputs[stream].extend(self.exact(connection,length))
        finally:connection.close()
        # Even an authenticated hijack EOF can precede actual daemon closure.
        while True:
            state=self.request('GET','/exec/'+identifier+'/json')
            if state.get('ID')!=identifier or state.get('ContainerID')!=container_id or type(state.get('Running'))is not bool:
                raise ExecUncertain('native exec lifetime/scope differs')
            if not state['Running']:
                code=state.get('ExitCode')
                if type(code)is not int or not -255<=code<=255:
                    raise ExecUncertain('native exec terminal status invalid')
                observe({'stage':'native-exec-terminal','container_id':container_id,'exec_id':identifier,'returncode':code})
                return ExecResult(identifier,code,bytes(outputs[1]),bytes(outputs[2]))
            time.sleep(min(.05,self.remaining()))

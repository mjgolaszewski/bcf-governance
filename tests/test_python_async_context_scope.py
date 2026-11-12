"""Ordinary async receiver contexts differ without changing service source."""
import hashlib,os,subprocess,sys
import pytest
SOURCE="class Service:\n    async def query(self):\n        return await self._read()\n    async def _read(self):\n        return 1\n"
@pytest.mark.parametrize("rebound",(False,True))
def test_fresh_native_async_receiver_context_requires_binding(tmp_path,rebound):
 suffix="service=Service()\n"
 if rebound:
  suffix+="class Awaitable:\n    def __await__(self):\n        STATE.append(1)\n        if False:\n            yield\n        return 1\nservice._read=lambda: Awaitable()\n"
 expected=[1] if rebound else []
 path=tmp_path/"consumer.py"
 path.write_text("import asyncio\nSTATE=[]\n"+SOURCE+suffix+"assert asyncio.run(service.query()) == 1\nassert STATE == "+repr(expected)+"\nprint('async-context-witnessed')\n")
 env={k:v for k,v in os.environ.items() if not k.startswith(("PYTHON","BCF_","GIT_","GITHUB_","AGENTBUS_")) and k not in {"GH_TOKEN","VIRTUAL_ENV"}}
 result=subprocess.run([sys.executable,"-I","-B",str(path)],cwd=tmp_path,env=env,capture_output=True,text=True,timeout=10)
 assert result.returncode==0,result.stderr
 assert result.stdout=="async-context-witnessed\n" and not result.stderr

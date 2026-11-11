"""Qualify sibling response retirement in isolated fresh and upgraded consumers."""
import json
import subprocess
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment, _record
installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = r'''import importlib.util,json,sys,tempfile
from pathlib import Path
from io import BytesIO
from email.message import Message
from urllib.error import HTTPError
assert importlib.util.find_spec('bcf_governance') is None
root=Path('scripts').resolve()
sys.path.insert(0,str(root))
from _bcf_runtime import ci_github_api,evidence_storage_github_api,protection_inspection_client
from _bcf_runtime.ci_github_api import GitHubAPI,GitHubAPIError
from _bcf_runtime.ci_github_errors import GitHubAPIConflictError
from _bcf_runtime.evidence_storage_github_api import GitHubEvidenceAPI
from _bcf_runtime.protection_inspection_client import ProtectionInspectionClient
completed=[]
url='https://uploads.github.com/repos/acme/project/releases/1/assets'
class CleanupInterrupt(BaseException):pass
def population(error):
    pending=[error];found=[]
    while pending:
        current=pending.pop()
        if current is None or any(current is seen for seen in found):continue
        found.append(current);pending.extend([current.__cause__,current.__context__])
    return found
def exercise(kind,method,code,cleanup_kind=None):
    closes=[];calls=[]
    signal=CleanupInterrupt('installed cleanup interruption') if cleanup_kind=='interrupt' else OSError('installed cleanup failure')
    class Body(BytesIO):
        def close(self):
            closes.append('close')
            if cleanup_kind:raise signal
            super().close()
    body=Body(b'{"message":"controlled provider failure"}')
    error=HTTPError('https://api.github.com/repos/acme/project',code,'controlled',Message(),body)
    def opener(request,**kwargs):
        calls.append(request)
        raise error
    owner=protection_inspection_client if kind=='protection' else evidence_storage_github_api if kind=='evidence' else ci_github_api
    attribute='_open_inspection' if kind=='protection' else 'open_download'
    original=getattr(owner,attribute)
    setattr(owner,attribute,opener)
    caught=None
    try:
        try:
            if kind=='json':
                GitHubAPI(token='fixture-token')._request(method,'/repos/acme/project/value',payload={'value':'exact'} if method!='GET' else None)
            elif kind=='release':
                GitHubAPI(token='fixture-token')._upload_bytes(url,payload=b'exact',media_type='application/octet-stream')
            elif kind=='evidence':
                with tempfile.TemporaryDirectory() as directory:
                    source=Path(directory)/'evidence.bin';source.write_bytes(b'exact')
                    GitHubEvidenceAPI(token='fixture-token').upload_evidence_asset(upload_url=url,repository='acme/project',release_id=1,name=source.name,path=source,maximum_bytes=5)
            else:
                ProtectionInspectionClient(token='fixture-token',repository='acme/project',repository_id=1,installation_id=2,observed_installation_id=2)._request('GET','/repos/acme/project')
        except BaseException as failure:caught=failure
        assert len(calls)==1 and calls[0].get_method()==method
        assert closes==['close'],'one retirement owner and no request retry'
        if cleanup_kind=='interrupt':
            assert caught is signal
        elif cleanup_kind:
            assert isinstance(caught,GitHubAPIError) and not isinstance(caught,GitHubAPIConflictError)
            assert error in population(caught) and signal in population(caught)
        else:
            assert body.closed
            assert isinstance(caught,GitHubAPIError) and error in population(caught)
            if kind=='json' and method!='GET' and code in (409,422):
                assert isinstance(caught,GitHubAPIConflictError)
        completed.append([kind,method,code,cleanup_kind])
    finally:
        setattr(owner,attribute,original)
        try:
            error.close()
        except BaseException as final_cleanup:
            assert cleanup_kind and final_cleanup is signal
        finally:
            BytesIO.close(body)
for method in ('POST','PUT','PATCH','DELETE'):
    for code in (409,422,503):exercise('json',method,code)
for code in (403,409,422):exercise('json','GET',code)
for code in (403,404,503):exercise('protection','GET',code)
for kind in ('release','evidence'):
    for code in (409,422,503):exercise(kind,'POST',code)
for kind in ('json','release','evidence','protection'):
    for cleanup in ('failure','interrupt'):
        exercise(kind,'GET' if kind=='protection' else 'POST',409,cleanup)
origins={name:str(Path(module.__file__).resolve()) for name,module in list(sys.modules.items()) if name.startswith('_bcf_runtime.') and getattr(module,'__file__',None)}
assert origins and all(Path(value).is_relative_to(root) for value in origins.values())
assert len(completed)==32
print(json.dumps({'source_package_absent':True,'cases':completed,'private_origins':origins},sort_keys=True))
'''

compile(PROBE, 'installed-sibling-response-retirement', 'exec')

def exercise_installed_sibling_retirement(installed_consumer, isolated_python):
    result = subprocess.run(
        [str(isolated_python), '-I', '-B', '-c', PROBE], cwd=installed_consumer,
        env=_environment(), capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, _record(result)
    actual = json.loads(result.stdout)
    assert actual['source_package_absent'] is True and actual['private_origins']
    assert len(actual['cases']) == 32
    assert len({tuple(case) for case in actual['cases']}) == 32

    return actual


def test_installed_sibling_response_retirement(installed_consumer, isolated_python):
    exercise_installed_sibling_retirement(installed_consumer, isolated_python)


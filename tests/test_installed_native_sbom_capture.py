"""SDK-absent sealed cataloger capture and source-binding detector parity."""
import inspect
import subprocess

import test_installed_evidence_storage as fixtures
import test_native_archive_subject as archives
import test_native_sbom_capture as captures

installed_consumer = fixtures.installed_consumer
isolated_python = fixtures.isolated_python
PROBE = '''import fcntl,gzip,hashlib,io,json,sys,tarfile,tempfile
from pathlib import Path
assert __import__("importlib.util").util.find_spec("bcf_governance") is None
ROOT=Path.cwd()
sys.path.insert(0,str(ROOT/"scripts"))
from _bcf_runtime import dependency_assurance as owner
from _bcf_runtime import evidence_process_supervisor as commands
''' + inspect.getsource(archives.Case) + '\nArchiveCase=Case\n' + inspect.getsource(captures.Case) + '''
with tempfile.TemporaryDirectory() as directory:
 case=Case(Path(directory))
 raw=case.invoke()
 assert raw==case.reply.read_bytes()
 assert (case.arguments["output_dir"]/"seen-input").read_bytes()==case.arguments["archive_bytes"]
with tempfile.TemporaryDirectory() as directory:
 case=Case(Path(directory))
 reply=json.loads(case.reply.read_text())
 reply["source"]["metadata"]["imageID"]="sha256:"+"0"*64
 case.reply.write_text(json.dumps(reply))
 try:case.invoke()
 except owner.DependencyAssuranceError:pass
 else:raise AssertionError("installed cataloger source substitution was accepted")
print("installed-native-sbom-qualified")
'''


def invoke(installed_consumer, isolated_python):
    return subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
        cwd=installed_consumer, env=fixtures._environment(), capture_output=True, text=True)


def test_installed_sealed_cataloger_and_substitution(installed_consumer, isolated_python):
    result = invoke(installed_consumer, isolated_python)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-native-sbom-qualified"


def test_installed_binding_control_detects_omission(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/dependency_assurance.py"
    source = path.read_text()
    guard = "binding = native_archive_subject(archive_bytes, **inputs, sbom_bytes=result.stdout)"
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, "binding = native_archive_subject(archive_bytes, **inputs)"))
    result = invoke(installed_consumer, isolated_python)
    assert result.returncode == 1
    assert "installed cataloger source substitution was accepted" in result.stderr

"""Fresh/repaired SDK-absent consumers retain installed metadata refusal."""
import subprocess
import test_installed_evidence_storage as _fixture_owner
from test_installed_evidence_storage import _environment

installed_consumer = _fixture_owner.installed_consumer
isolated_python = _fixture_owner.isolated_python
PROBE = 'import importlib.util,sys\nfrom pathlib import Path\nfrom types import SimpleNamespace\nassert importlib.util.find_spec("bcf_governance") is None\nsys.path.insert(0,str(Path("scripts").resolve()))\nfrom _bcf_runtime import dependency_assurance as owner\ndef distribution(name):\n return SimpleNamespace(metadata={"Name":name},version="1.0",requires=[])\nowner.metadata.distributions=lambda:iter([distribution("example"),distribution("EXAMPLE")])\ntry:\n owner._installed()\nexcept owner.DependencyAssuranceError as error:\n assert "ambiguous installed dependency" in str(error)\nelse:\n raise AssertionError("installed duplicate metadata falsely admitted")\nowner.metadata.distributions=lambda:iter([distribution("Example_Package")])\nassert set(owner._installed())=={"example-package"}\nowner.metadata.distributions=lambda:iter([distribution(None)])\ntry:\n owner._installed()\nexcept owner.DependencyAssuranceError as error:\n assert "installed dependency name" in str(error)\nelse:\n raise AssertionError("installed malformed metadata falsely omitted")\nprint("installed-metadata-admission-qualified")\n'

def test_installed_metadata_admission(installed_consumer, isolated_python):
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
                            cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "installed-metadata-admission-qualified"


def test_installed_duplicate_guard_removal_fails_named_control(installed_consumer, isolated_python):
    path = installed_consumer / "scripts/_bcf_runtime/dependency_assurance.py"
    source = path.read_text()
    guard = "if identity in result:"
    assert source.count(guard) == 1
    path.write_text(source.replace(guard, "if False and identity in result:"))
    result = subprocess.run([str(isolated_python), "-I", "-B", "-c", PROBE],
                            cwd=installed_consumer, env=_environment(), capture_output=True, text=True)
    assert result.returncode == 1
    assert "installed duplicate metadata falsely admitted" in result.stderr

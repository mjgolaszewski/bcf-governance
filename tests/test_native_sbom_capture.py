"""Pinned cataloger captures exact sealed input under existing native custody."""
import fcntl
import hashlib
import json
import sys

import pytest
from bcf_governance.tooling import dependency_assurance as owner
from bcf_governance.tooling import evidence_process_supervisor as commands
from test_native_archive_subject import Case as ArchiveCase


class Case:
    def __init__(self, root):
        self.root = root
        archive = ArchiveCase().arguments()
        sbom = json.loads(archive.pop("sbom_bytes"))
        sbom["descriptor"] = {"name": "syft", "version": "1.57.2"}
        sbom["artifacts"] = [{"id": "one", "purl": "pkg:apk/wolfi/example@1-r0", "name": "example", "version": "1-r0"}]
        self.reply = root / "reply.json"
        self.reply.write_text(json.dumps(sbom))
        self.mode = root / "mode"
        self.mode.write_text("normal")
        self.tool = root / "cataloger"
        self.tool.write_text("#!" + sys.executable + "\n" + '''import json,os,sys
from pathlib import Path
raw=sys.stdin.buffer.read()
Path("seen-input").write_bytes(raw)
assert sys.argv[3:] == ["scan","docker-archive:/proc/self/fd/0","--output","syft-json"]
config=Path(sys.argv[2])
assert json.loads(config.read_text()) == {"check-for-app-update":False}
assert not any(k.startswith(("GITHUB_","AWS_","SYFT_EXCLUDE")) for k in os.environ)
root=Path(__file__).parent
mode=(root/"mode").read_text()
if mode=="mutate-tool":Path(__file__).write_text(Path(__file__).read_text()+"\\n")
if mode=="mutate-config":config.write_text("{}")
sys.stdout.buffer.write((root/"reply.json").read_bytes())
sys.stderr.write("retained diagnostic")
raise SystemExit(1 if mode=="nonzero" else 0)
''')
        self.tool.chmod(0o700)
        self.arguments = {**archive, "cataloger": self.tool, "expected_cataloger_sha256": hashlib.sha256(self.tool.read_bytes()).hexdigest(),
                          "command_seconds": 10, "output_dir": root / "output"}

    def invoke(self):
        with (self.root / "native-lease").open("w+b") as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with commands.native_lease_custody(lease.fileno(), timeout_seconds=30, cleanup_seconds=5):
                return owner.capture_native_sbom(**self.arguments)


def test_pinned_capture_preserves_exact_input_raw_output_and_closed_environment(tmp_path, monkeypatch):
    case = Case(tmp_path)
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-enter-child")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-enter-child")
    monkeypatch.setenv("SYFT_EXCLUDE", "must-not-select-packages")
    raw = case.invoke()
    assert raw == case.reply.read_bytes()
    assert (case.arguments["output_dir"] / "seen-input").read_bytes() == case.arguments["archive_bytes"]
    assert (case.arguments["output_dir"] / "cataloger.stdout").read_bytes() == raw
    assert (case.arguments["output_dir"] / "cataloger.stderr").read_bytes() == b"retained diagnostic"
    binding = json.loads((case.arguments["output_dir"] / "archive-binding.json").read_text())
    assert binding["authority"] is binding["security_qualified"] is False
    assert binding["sbom_binding"]["normalized_manifest_independently_verified"] is False


@pytest.mark.parametrize("cause", ["archive-pin", "manifest-pin", "tool-pin", "malformed-tool-pin", "archive-bytes",
    "zero-budget", "bool-budget", "unbounded-budget", "expanded-bound", "existing-output", "tool-symlink"])
def test_bad_inputs_refuse_without_allocating_output(tmp_path, cause):
    case = Case(tmp_path)
    if cause == "archive-pin":
        case.arguments["expected_archive_sha256"] = "0" * 64
    elif cause == "manifest-pin":
        case.arguments["expected_manifest_digest"] = "sha256:" + "0" * 64
    elif cause == "tool-pin":
        case.arguments["expected_cataloger_sha256"] = "0" * 64
    elif cause == "malformed-tool-pin":
        case.arguments["expected_cataloger_sha256"] = True
    elif cause == "archive-bytes":
        case.arguments["archive_bytes"] = bytearray(case.arguments["archive_bytes"])
    elif cause in {"zero-budget", "bool-budget", "unbounded-budget"}:
        case.arguments["command_seconds"] = {"zero-budget": 0, "bool-budget": True, "unbounded-budget": 2**10000}[cause]
    elif cause == "expanded-bound":
        case.arguments["max_expanded_bytes"] = 1
    elif cause == "existing-output":
        case.arguments["output_dir"].mkdir()
        (case.arguments["output_dir"] / "preserve").write_bytes(b"owned")
    else:
        link = tmp_path / "tool-link"
        link.symlink_to(case.tool)
        case.arguments["cataloger"] = link
    with pytest.raises(owner.DependencyAssuranceError):
        case.invoke()
    if cause == "existing-output":
        assert (case.arguments["output_dir"] / "preserve").read_bytes() == b"owned"
    else:
        assert not case.arguments["output_dir"].exists()


@pytest.mark.parametrize("cause", ["nonzero", "malformed", "name", "version", "config", "layer", "empty-packages", "bad-package", "mutate-tool", "mutate-config"])
def test_execution_or_output_failure_preserves_raw_evidence_without_binding(tmp_path, cause):
    case = Case(tmp_path)
    reply = json.loads(case.reply.read_text())
    if cause in {"nonzero", "mutate-tool", "mutate-config"}:
        case.mode.write_text(cause)
    elif cause == "malformed":
        case.reply.write_bytes(b"not JSON")
    elif cause in {"name", "version"}:
        reply["descriptor"][cause] = "wrong"
    elif cause == "config":
        reply["source"]["metadata"]["imageID"] = "sha256:" + "0" * 64
    elif cause == "layer":
        reply["source"]["metadata"]["layers"].reverse()
    elif cause == "empty-packages":
        reply["artifacts"] = []
    else:
        reply["artifacts"][0]["purl"] = "wrong"
    if cause not in {"nonzero", "malformed", "mutate-tool", "mutate-config"}:
        case.reply.write_text(json.dumps(reply))
    with pytest.raises(owner.DependencyAssuranceError):
        case.invoke()
    assert (case.arguments["output_dir"] / "cataloger.stdout").read_bytes() == case.reply.read_bytes()
    assert not (case.arguments["output_dir"] / "archive-binding.json").exists()


def test_existing_owner_required_before_any_work(tmp_path):
    case = Case(tmp_path)
    with pytest.raises(owner.DependencyAssuranceError, match="execution owner"):
        owner.capture_native_sbom(**case.arguments)
    assert not case.arguments["output_dir"].exists()


def test_unknown_process_custody_propagates_and_preserves_namespace(tmp_path, monkeypatch):
    case = Case(tmp_path)
    def unknown(*args, **kwargs):
        raise commands.OwnedProcessError("unknown custody")
    monkeypatch.setattr(commands, "run_admitted_command", unknown)
    with pytest.raises(commands.OwnedProcessError, match="unknown custody"):
        case.invoke()
    assert case.arguments["output_dir"].is_dir()

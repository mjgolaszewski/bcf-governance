"""Independent function population and real pinned-Radon score witnesses."""
import hashlib
import subprocess
import zipfile
import sys
from pathlib import Path

import pytest

from bcf_governance.tooling import operational_observations as owner

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def radon_tool(tmp_path_factory):
    archive = ROOT / "tests/fixtures/radon-toolchain/radon-6.0.1-py2.py3-none-any.whl"
    raw = archive.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == "632cc032364a6f8bb1010a2f6a12d0f14bc7e5ede76585ef29dc0cecf4cd8859"
    target = tmp_path_factory.mktemp("radon-toolchain")
    with zipfile.ZipFile(archive) as wheel:
        for name in wheel.namelist():
            path = Path(name)
            assert not path.is_absolute() and ".." not in path.parts and "\\" not in name
        wheel.extractall(target)
    return target


@pytest.fixture(autouse=True)
def use_pinned_calculator(radon_tool, monkeypatch):
    monkeypatch.syspath_prepend(str(radon_tool))


def repository(tmp_path, source, extras=None):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "source.py").write_text(source)
    for name, value in (extras or {}).items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
    def git(*args):
        return subprocess.check_output(["git", "-c", "core.hooksPath=/dev/null", *args], cwd=root, text=True).strip()
    git("init", "-q")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "add", ".")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "source")
    return root, {"commit_sha": git("rev-parse", "HEAD"), "tree_sha": git("rev-parse", "HEAD^{tree}")}


def observe(root, subject):
    return owner.python_complexity_observation(root, subject=subject)


@pytest.mark.parametrize("source,expected", [
    ("def f():\n return 1\n", 1),
    ("def f(x):\n if x: return 1\n return 0\n", 2),
    ("def f(x,y,z):\n return x and y and z\n", 3),
    ("def f(xs):\n for x in xs: pass\n", 2),
    ("async def f(x):\n if x: return x\n", 2),
])
def test_pinned_radon_scores_known_real_branches(tmp_path, source, expected):
    root, subject = repository(tmp_path, source)
    result = observe(root, subject)
    assert result["status"] == "complete", result
    assert [row["complexity"] for row in result["functions"]] == [expected]
    assert result["authority"] is result["execution_qualified"] is False
    owner.validate_operational_observation(ROOT, result)


def test_independent_population_keeps_nested_async_methods_and_repeated_names(tmp_path):
    source = "def outer():\n def same(): return 1\n class C:\n  async def same(self): return 2\n return same\nclass C:\n def same(self): return 3\nlambda_only=lambda x:x\n"
    root, subject = repository(tmp_path, source, {"empty.py": "x=1\n"})
    result = observe(root, subject)
    assert result["status"] == "complete", result
    assert [row["qualified_name"] for row in result["functions"]] == ["outer", "outer.same", "outer.C.same", "C.same"]
    assert sum(row["named_functions"] for row in result["files"]) == 4
    assert sum(row["lambdas"] for row in result["files"]) == 1
    assert len(result["files"]) == 2


def test_worktree_edits_cannot_replace_exact_committed_source(tmp_path):
    root, subject = repository(tmp_path, "def f(): return 1\n")
    before = observe(root, subject)
    (root / "source.py").write_text("def forged(x):\n if x: return 1\n")
    (root / "untracked.py").write_text("def hidden(): pass\n")
    after = observe(root, subject)
    for key in ("files", "functions", "subject", "tool", "status"):
        assert before[key] == after[key]
    assert [row["qualified_name"] for row in after["functions"]] == ["f"]


@pytest.mark.parametrize("source,reason", [
    ("def invalid(: pass\n", "invalid_python"),
    ("def f():\n try: pass\n except* ValueError: pass\n", "unsupported_syntax"),
    ("type Alias = int\n", "unsupported_syntax" if sys.version_info >= (3, 12) else "invalid_python"),
])
def test_invalid_or_unqualified_syntax_is_not_clean(tmp_path, source, reason):
    root, subject = repository(tmp_path, source)
    result = observe(root, subject)
    assert result["status"] == "incomplete"
    assert result["failures"] == [{"path": "source.py", "reason": reason}]
    owner.validate_operational_observation(ROOT, result)


@pytest.mark.parametrize("version", [None, "0.0.0"])
def test_missing_or_wrong_calculator_is_typed_incomplete(tmp_path, monkeypatch, version):
    import importlib.metadata
    root, subject = repository(tmp_path, "def f(): return 1\n")
    def metadata(name):
        assert name == "radon"
        if version is None:
            raise importlib.metadata.PackageNotFoundError(name)
        return version
    monkeypatch.setattr(importlib.metadata, "version", metadata)
    result = observe(root, subject)
    assert result["status"] == "incomplete"
    assert result["functions"] == []
    assert result["failures"] == [{"path": "", "reason": "calculator_unavailable_or_wrong_version"}]


def test_wrong_subject_rejects_before_calculator_import(tmp_path):
    root, subject = repository(tmp_path, "def f(): return 1\n")
    subject["tree_sha"] = "a" * 40
    with pytest.raises(owner.OperationalObservationError, match="source subject"):
        observe(root, subject)


def test_omitted_calculator_row_cannot_hide_real_function(tmp_path, monkeypatch):
    import radon.complexity
    root, subject = repository(tmp_path, "def f(): return 1\n")
    monkeypatch.setattr(radon.complexity, "cc_visit_ast", lambda *args, **kwargs: [])
    result = observe(root, subject)
    assert result["status"] == "incomplete"
    assert result["failures"] == [{"path": "source.py", "reason": "calculator_population_mismatch"}]


def test_observation_repeats_without_clock_claim(tmp_path):
    root, subject = repository(tmp_path, "def f(x):\n if x: return 1\n return 0\n")
    a, b = observe(root, subject), observe(root, subject)
    a.pop("elapsed_ms")
    b.pop("elapsed_ms")
    assert a == b
    assert a["python"]["version"] == ".".join(str(v) for v in sys.version_info[:3])


def test_calculator_failure_is_typed_incomplete(tmp_path, monkeypatch):
    import radon.complexity
    root, subject = repository(tmp_path, "def f(): return 1\n")
    def crashed(*args, **kwargs):
        raise RuntimeError("calculator failed")
    monkeypatch.setattr(radon.complexity, "cc_visit_ast", crashed)
    result = observe(root, subject)
    assert result["status"] == "incomplete"
    assert result["failures"] == [{"path": "source.py", "reason": "calculator_failed"}]
    owner.validate_operational_observation(ROOT, result)

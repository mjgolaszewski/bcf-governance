"""An independent source pass prevents omitted call rows from hiding effects."""
import copy
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from bcf_governance.tooling import semantic_authority_operations as owner
from bcf_governance.tooling.semantic_authority_contracts import SemanticAuthorityError
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source

SOURCE = "def helper():\n    return 1\ndef work():\n    return helper()\nCOMMANDS = {'work': work}\n"


def payload():
    return dict(schema_version="1.0", document=dict(kind="application_operation_registry",
        id="coverage-operations", version="1.0.0", status="active",
        path="governance/application-operations.yml"),
        populations=[dict(id="cli", adapter="python_mapping", source="runtime.py",
            symbol="COMMANDS", public_only=True)],
        operations=[dict(id="coverage.work.v1", population="cli", population_key="work",
            family="coverage", bounded_context="coverage", entrypoints=["runtime.py::work"],
            semantic_kind="query", authoritative_read=True, authoritative_mutation=False,
            authority_conferral=False, produces_projection=False, model_callable=False,
            allowed_mutation_ports=[], allowed_authority_ports=[], non_authoritative_output_effects=[])],
        migrations=[])


def capture(root, source=SOURCE, version=None):
    (root / "runtime.py").write_bytes(source.encode())
    (root / "schemas").mkdir(exist_ok=True)
    shutil.copy2(Path(__file__).parents[1] / "schemas/application-operations.schema.json",
                 root / "schemas/application-operations.schema.json")
    return discover_python_source(root, files=[root / "runtime.py"], call_contracts_version=version)


def consume(root, facts):
    return owner._validate_operations(root, payload(), facts)


def work(facts):
    return next(row for row in facts["functions"] if row["symbol"] == "runtime.py::work")


@pytest.mark.parametrize("version", [None, "1.0"])
@pytest.mark.parametrize("defect", ["erase", "duplicate", "line", "end_column", "caller", "function", "file", "duplicate_file", "member_sha", "changed_bytes", "unsafe_path"])
def test_actual_consumer_rejects_independent_source_coverage_defects(tmp_path, version, defect):
    facts = capture(tmp_path, version=version)
    assert consume(tmp_path, facts)
    if defect == "erase":
        work(facts)["calls"] = []
    elif defect == "duplicate":
        work(facts)["calls"].append(copy.deepcopy(work(facts)["calls"][0]))
    elif defect in {"line", "end_column"}:
        work(facts)["calls"][0][defect] += 1
    elif defect == "caller":
        work(facts)["calls"][0]["caller"] = "runtime.py::helper"
    elif defect == "function":
        work(facts)["calls"] = []
        facts["functions"] = [row for row in facts["functions"] if row["symbol"] != "runtime.py::helper"]
    elif defect == "file":
        facts["files"] = []
    elif defect == "duplicate_file":
        facts["files"].append(copy.deepcopy(facts["files"][0]))
    elif defect == "member_sha":
        facts["files"][0]["sha256"] = "0" * 64
    elif defect == "changed_bytes":
        with (tmp_path / "runtime.py").open("a") as stream:
            stream.write("# moving source\n")
    else:
        facts["files"].append(dict(path="../outside.py", sha256="0" * 64))
    with pytest.raises(SemanticAuthorityError, match="Python source call coverage"):
        consume(tmp_path, facts)


@pytest.mark.parametrize("version", [None, "1.0"])
def test_removed_edge_cannot_hide_independently_witnessed_write(tmp_path, version):
    source = "STATE=0\ndef helper():\n    global STATE\n    STATE=1\ndef work():\n    helper()\n    return 1\nCOMMANDS={'work':work}\n"
    namespace = {}
    exec(compile(source, "runtime.py", "exec"), namespace)
    assert namespace["STATE"] == 0
    namespace["work"]()
    assert namespace["STATE"] == 1
    facts = capture(tmp_path, source, version)
    with pytest.raises(SemanticAuthorityError, match="undeclared write"):
        consume(tmp_path, facts)
    work(facts)["calls"] = []
    with pytest.raises(SemanticAuthorityError, match="Python source call coverage"):
        consume(tmp_path, facts)


@pytest.mark.parametrize("version", [None, "1.0"])
def test_inner_call_cannot_be_omitted_while_outer_call_remains(tmp_path, version):
    source = "def helper():\n    return 1\ndef wrap(value):\n    return 1\ndef work():\n    return wrap(helper())\nCOMMANDS={'work':work}\n"
    facts = capture(tmp_path, source, version)
    work(facts)["calls"] = [row for row in work(facts)["calls"] if row["call_name"] != "helper"]
    with pytest.raises(SemanticAuthorityError, match="Python source call coverage"):
        consume(tmp_path, facts)


@pytest.mark.parametrize("field", ["expression", "arguments", "missing"])
def test_explicit_call_contract_is_bound_to_its_actual_expression(tmp_path, field):
    source = "def helper(value):\n    return 1\ndef work():\n    return helper(3)\nCOMMANDS={'work':work}\n"
    facts = capture(tmp_path, source, "1.0")
    contract = work(facts)["calls"][0]["call_contract"]
    if field == "expression":
        contract["expression_sha256"] = "0" * 64
    elif field == "arguments":
        contract["arguments"][0]["expression_sha256"] = "0" * 64
    else:
        del work(facts)["calls"][0]["call_contract"]
    with pytest.raises(SemanticAuthorityError, match="Python source call coverage"):
        consume(tmp_path, facts)


@pytest.mark.parametrize("source", [
    SOURCE,
    SOURCE.replace("return helper()", "helper()\n    return helper()"),
    SOURCE.replace("helper", "hélper"),
    SOURCE.replace("\n", "\r\n"),
    "def work():\n    def child():\n        return 1\n    return child()\nCOMMANDS={'work':work}\n",
    "from __future__ import annotations\ndef other(value: annotation() = default()) -> result():\n    local: annotation() = 1\n    return (lambda x=default(): deferred())\ndef work():\n    return 1\nCOMMANDS={'work':work}\n",
    "@decorate(factory())\ndef other(value=default()):\n    class Local:\n        @decorate(factory())\n        def method(self, arg=default()):\n            return invoked()\n    return (lambda value=default(): deferred())\ndef work():\n    return 1\nCOMMANDS={'work':work}\n",
    "def other(values, item, kwargs):\n    return helper(*values, named=item, **kwargs)\ndef work():\n    return 1\nCOMMANDS={'work':work}\n",
])
@pytest.mark.parametrize("version", [None, "1.0"])
def test_ordinary_source_scope_and_call_shapes_remain_compatible(tmp_path, source, version):
    facts = capture(tmp_path, source, version)
    assert consume(tmp_path, facts)
    assert facts["files"][0]["sha256"] == hashlib.sha256(source.encode()).hexdigest()


def test_erased_edge_and_paired_test_inventory_still_fail_committed_membership(tmp_path):
    facts = capture(tmp_path)
    (tmp_path / "paired_test.py").write_text("def test_helper():\n    return True\n")
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    def git(*args):
        return subprocess.check_output(["git", "-c", "core.hooksPath=/dev/null", "-c", "gc.auto=0", *args], cwd=tmp_path, env=env, text=True).strip()
    git("init", "-b", "main")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "add", ".")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "source and paired test")
    subject = dict(commit_sha=git("rev-parse", "HEAD"), tree_sha=git("rev-parse", "HEAD^{tree}"))
    facts = discover_python_source(tmp_path, source_subject=subject, call_contracts_version="1.0")
    assert consume(tmp_path, facts)
    work(facts)["calls"] = []
    facts["functions"] = [row for row in facts["functions"] if not row["symbol"].startswith("paired_test.py::")]
    facts["files"] = [row for row in facts["files"] if row["path"] != "paired_test.py"]
    (tmp_path / "paired_test.py").unlink()
    with pytest.raises(SemanticAuthorityError, match="Python source call coverage"):
        consume(tmp_path, facts)

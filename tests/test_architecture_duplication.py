from pathlib import Path

import pytest

from bcf_governance.tooling.architecture_source_observation import duplication_blocks
from bcf_governance.tooling.ci_github_bundle import canonical_json, provider_snapshot
from bcf_governance.tooling.ci_github_identity import MainIdentity
from test_template_architecture_gate import _instantiate_template_repo, _load_module, _write_python


def _body(offset=0):
    return "\n".join(f"    value_{index} = {index + (offset if index == 6 else 0)}" for index in range(14))


def test_repeated_interface_signatures_are_not_duplicated_implementation():
    signature = "\n".join(f"    value_{index}: str," for index in range(15))
    first = f"def first(\n{signature}\n):\n    return 'first'\n"
    second = f"def second(\n{signature}\n):\n    return 'second'\n"
    assert duplication_blocks(first, 12) == duplication_blocks(second, 12) == []


def test_real_body_windows_remain_detectable_and_mutating_the_middle_breaks_them():
    first = "def first():\n" + _body() + "\n"
    second = "def second():\n" + _body() + "\n"
    windows = {block for _, block in duplication_blocks(first, 12)}
    assert windows & {block for _, block in duplication_blocks(second, 12)}
    assert not windows & {block for _, block in duplication_blocks("def second():\n" + _body(1), 12)}


def test_separate_short_methods_are_not_concatenated_into_a_fake_body():
    source = "\n\n".join(f"def method_{index}(value):\n    return value" for index in range(15))
    assert duplication_blocks(source, 12) == []


def test_installed_gate_retains_causal_body_rejection(tmp_path: Path):
    root = _instantiate_template_repo(tmp_path)
    first = root / "backend/src/app/features/orders/commands/first.py"
    second = first.with_name("second.py")
    _write_python(first, "def first():\n" + _body() + "\n")
    _write_python(second, "def second():\n" + _body() + "\n")
    gate = _load_module(root / "backend/tests/architecture/test_boundaries_ast.py")
    with pytest.raises(AssertionError, match="bounded-context duplication"):
        gate.test_bounded_context_duplication_is_explicit()
    _write_python(second, "def second():\n" + _body(1) + "\n")
    gate.test_bounded_context_duplication_is_explicit()


@pytest.mark.parametrize("version", [None, "1.1"])
def test_shared_snapshot_encoder_preserves_existing_authority_domains(version):
    main = MainIdentity("123", "main", "a" * 40, "b" * 40)
    admission = {"admission_ordinal": "7", "collection_complete": True}
    run = {"producer_id": "tests", "run_id": "21"}
    expected = {
        "schema_version": "1.0", "producer_id": "tests",
        "repository": {"provider": "github", "repository_id": "123"},
        "authentication": {"collector_id": "bcf-trusted-finalizer", "provider_api_verified": True,
                           "captured_at": "2026-11-08T00:00:00Z"},
        "current_default_main": {"checkout_sha": "a" * 40, "tree_sha": "b" * 40},
        "admissions": [{**admission, "producer_run": run}],
    }
    if version is not None:
        expected["authority_contract_version"] = version
    actual = provider_snapshot(main=main, admission=admission, producer_run=run,
                               captured_at="2026-11-08T00:00:00Z", authority_contract_version=version)
    assert canonical_json(actual) == canonical_json(expected)
    assert admission == {"admission_ordinal": "7", "collection_complete": True}
    assert run == {"producer_id": "tests", "run_id": "21"}

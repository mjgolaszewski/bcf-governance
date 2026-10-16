from __future__ import annotations

from pathlib import Path
import subprocess
import copy
import yaml

import pytest

from bcf_governance.tooling.governance_validation.ci_state_matrix import (
    CIStateMatrixError,
    validate_ci_state_matrix,
)


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def isolated_comparison_environment(monkeypatch):
    # Disposable Git fixtures are independent of the invoking provider's subject.
    for name in (
        'BCF_PROVIDER_EVENT', 'GITHUB_EVENT_NAME', 'BCF_INVOCATION_KIND',
        'BCF_COMPARISON_BASE_SHA', 'BCF_ORIGIN_COMPARISON_BASE_SHA',
        'BCF_CALLER_COMPARISON_BASE_SHA', 'BCF_PR_BASE_SHA',
    ):
        monkeypatch.delenv(name, raising=False)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "spec/phase0").mkdir(parents=True)
    (repo / "bcf_governance/tooling").mkdir(parents=True)
    (repo / "spec/RELEASE_TRAIN_STATE_DAG.md").write_bytes(
        (ROOT / "spec/RELEASE_TRAIN_STATE_DAG.md").read_bytes()
    )
    (repo / "spec/phase0/release-train-backtrace.yml").write_bytes(
        (ROOT / "spec/phase0/release-train-backtrace.yml").read_bytes()
    )
    (repo / "schemas").mkdir()
    (repo / "schemas/release-train-backtrace.schema.json").write_bytes(
        (ROOT / "schemas/release-train-backtrace.schema.json").read_bytes()
    )
    (repo / "bcf_governance/tooling/preflight.py").write_text("VALUE = 1\n")
    _git(repo, "init", "--initial-branch=main")
    _git(repo, "config", "user.name", "BCF Test")
    _git(repo, "config", "user.email", "bcf@example.invalid")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "base")
    _git(repo, "remote", "add", "origin", str(repo))
    _git(repo, "fetch", "origin", "main")
    return repo


def test_changed_ci_contract_requires_same_candidate_matrix_update(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "bcf_governance/tooling/preflight.py").write_text("VALUE = 2\n")
    with pytest.raises(CIStateMatrixError, match="same-candidate state matrix"):
        validate_ci_state_matrix(repo)
    with (repo / "spec/RELEASE_TRAIN_STATE_DAG.md").open("a", encoding="utf-8") as stream:
        stream.write("\nCandidate-specific transition coverage.\n")
    report = validate_ci_state_matrix(repo)
    assert report["changed_contracts"] == ["bcf_governance/tooling/preflight.py", "spec/RELEASE_TRAIN_STATE_DAG.md"]
    assert report["machine_backtrace"] == {"edges": 7, "transitions": 15}


def test_machine_backtrace_rejects_an_incomplete_edge_before_ci_allocation(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    path = repo / "spec/phase0/release-train-backtrace.yml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "authority_effect: exact_release_byte_verification, ", "", 1
        ),
        encoding="utf-8",
    )
    with pytest.raises(CIStateMatrixError, match="AC-001 lacks: authority_effect"):
        validate_ci_state_matrix(repo)


def test_matrix_guard_is_self_required_and_adopter_inapplicable(tmp_path: Path) -> None:
    adopter = tmp_path / "adopter"
    adopter.mkdir()
    assert validate_ci_state_matrix(adopter)["status"] == "not_applicable_to_adopter"
    (adopter / "governance").mkdir()
    (adopter / "governance/self-governance-policy.yml").write_text("document: {}\n")
    with pytest.raises(CIStateMatrixError, match="unavailable"):
        validate_ci_state_matrix(adopter)


@pytest.mark.parametrize("defect", ["duplicate_invariant", "duplicate_primitive", "duplicate_state", "duplicate_transition", "state_reference", "invariant_reference", "active_primitive_reference", "schema_version", "declared_field_bypass", "field_list_omission", "source_identity"])
def test_machine_backtrace_rejects_typed_identity_and_shape_defects(tmp_path: Path, defect: str) -> None:
    repo = _repo(tmp_path)
    path = repo / "spec/phase0/release-train-backtrace.yml"
    model = yaml.safe_load(path.read_text())
    if defect.startswith("duplicate_"):
        section = {"invariant": "invariants", "primitive": "primitives", "state": "states", "transition": "transitions"}[defect.removeprefix("duplicate_")]
        duplicate = copy.deepcopy(model[section][0])
        field = {"invariants": "statement", "primitives": "owner", "states": "owner", "transitions": "cost"}[section]
        duplicate[field] += "-different"
        model[section].append(duplicate)
    elif defect == "state_reference":
        model["transitions"][0]["to"] = "ST-UNKNOWN"
    elif defect == "invariant_reference":
        model["primitives"][0]["invariants"] = ["INV-RT-999"]
    elif defect == "active_primitive_reference":
        model["adopter_compatibility_observation"]["primitives"].append("PRIM-UNKNOWN")
    elif defect == "schema_version":
        model["document"]["schema_version"] = 99
    elif defect == "source_identity":
        model["document"]["source"]["commit_sha"] = "not-a-commit"
    else:
        observation = model["adopter_compatibility_observation"]
        observation["edge_contract_fields"].remove("authority_effect")
        if defect == "declared_field_bypass":
            del observation["edges"][0]["authority_effect"]
    path.write_text(yaml.safe_dump(model, sort_keys=False))
    with pytest.raises(CIStateMatrixError, match="machine-readable"):
        validate_ci_state_matrix(repo)


def test_machine_backtrace_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    path = repo / "spec/phase0/release-train-backtrace.yml"
    path.write_text(path.read_text() + "\nvalidation_status: {}\n")
    with pytest.raises(CIStateMatrixError, match="duplicate YAML key"):
        validate_ci_state_matrix(repo)


def test_machine_backtrace_rejects_symlinked_input(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    path = repo / "spec/phase0/release-train-backtrace.yml"
    retained = path.with_suffix(".retained.yml")
    path.rename(retained)
    path.symlink_to(retained.name)
    with pytest.raises(CIStateMatrixError, match="nonsymlink"):
        validate_ci_state_matrix(repo)


def test_authored_machine_mode_defers_prose_projection_checks(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "spec/RELEASE_TRAIN_STATE_DAG.md").write_text("Pending canonical projection.\n")
    result = validate_ci_state_matrix(repo, authored_only=True)
    assert result["authority"] is False
    assert result["execution_qualified"] is False
    assert result["machine_backtrace"]["transitions"] > 0
    with pytest.raises(CIStateMatrixError, match="required coverage"):
        validate_ci_state_matrix(repo)


@pytest.mark.parametrize("field", ["rejection_transition", "retry_of"])
@pytest.mark.parametrize("defect", ["missing", "self", "wrong-kind", "wrong-source", "lost-invariant"])
def test_authored_backtrace_rejects_unbound_typed_transition_reference(tmp_path, field, defect):
    repo = _repo(tmp_path)
    path = repo / "spec/phase0/release-train-backtrace.yml"
    model = yaml.safe_load(path.read_text())
    source, target = model["transitions"][:2]
    source["kind"] = "success" if field == "rejection_transition" else "recovery"
    if field == "retry_of": source["max_attempts"] = 2
    if defect == "missing": source[field] = "TR-999"
    elif defect == "self": source[field] = source["id"]
    elif defect == "wrong-kind":
        source[field] = target["id"]
        target["kind"] = "recovery" if field == "rejection_transition" else "rejection"
        if target["kind"] == "recovery":
            target.update(retry_of=model["transitions"][2]["id"], max_attempts=2)
    else:
        source[field] = target["id"]
        target["kind"] = "rejection" if field == "rejection_transition" else "success"
        if field == "rejection_transition":
            target["from"] = source["from"]
            target["invariants"] = list(source["invariants"])
            if defect == "wrong-source": target["from"] = source["to"]
            else: target["invariants"] = ["INV-RT-018"]
        else:
            rejected = model["transitions"][2]
            target["rejection_transition"] = rejected["id"]
            rejected.update(kind="rejection", invariants=list(target["invariants"]))
            rejected["from"] = target["from"]
            source.update(invariants=list(target["invariants"]))
            source["from"], source["to"] = rejected["to"], target["from"]
            if defect == "wrong-source": source["from"] = target["from"]
            else: source["invariants"] = ["INV-RT-018"]
    path.write_text(yaml.safe_dump(model, sort_keys=False))
    with pytest.raises(CIStateMatrixError, match="typed transition reference"):
        validate_ci_state_matrix(repo, authored_only=True)


@pytest.mark.parametrize("recovery", [False, True])
def test_authored_backtrace_accepts_declared_typed_transition_references(tmp_path, recovery):
    repo = _repo(tmp_path)
    path = repo / "spec/phase0/release-train-backtrace.yml"
    model = yaml.safe_load(path.read_text())
    success, rejection, retry = model["transitions"][:3]
    success.update(kind="success", rejection_transition=rejection["id"])
    rejection.update(kind="rejection", invariants=list(success["invariants"]))
    rejection["from"] = success["from"]
    if recovery:
        retry.update(kind="recovery", retry_of=success["id"], max_attempts=2, invariants=list(success["invariants"]))
        retry["from"], retry["to"] = rejection["to"], success["from"]
    path.write_text(yaml.safe_dump(model, sort_keys=False))
    result = validate_ci_state_matrix(repo, authored_only=True)
    assert result["authority"] is False
    assert result["execution_qualified"] is False


@pytest.mark.parametrize("field", ["rejection_transition", "retry_of"])
@pytest.mark.parametrize("defect", ["missing", "changed", "duplicate"])
def test_authored_reference_guard_rejects_lost_guard_obligation(field, defect):
    from bcf_governance.tooling.governance_validation.ci_state_matrix import _validate_backtrace_references

    model = yaml.safe_load((ROOT / "spec/phase0/release-train-backtrace.yml").read_text())
    success, rejected, recovery = model["transitions"][:3]
    success.update(kind="success", rejection_transition=rejected["id"], guard_refs=["sha256:" + "a" * 64])
    rejected.update(kind="rejection", guard_refs=list(success["guard_refs"]), invariants=list(success["invariants"]))
    rejected["from"] = success["from"]
    recovery.update(kind="recovery", retry_of=success["id"], max_attempts=2,
                    guard_refs=list(success["guard_refs"]), invariants=list(success["invariants"]))
    recovery["from"], recovery["to"] = rejected["to"], success["from"]
    changed = rejected if field == "rejection_transition" else recovery
    if defect == "missing": changed.pop("guard_refs")
    elif defect == "changed": changed["guard_refs"] = ["sha256:" + "b" * 64]
    else: changed["guard_refs"] *= 2
    with pytest.raises(CIStateMatrixError, match="guard"):
        _validate_backtrace_references(model)


@pytest.mark.parametrize("changed", [False, True])
def test_authored_only_recovery_preserves_declared_guard_before_allocation(tmp_path, changed):
    repo = _repo(tmp_path)
    path = repo / "spec/phase0/release-train-backtrace.yml"
    model = yaml.safe_load(path.read_text())
    success, rejected, recovery = model["transitions"][:3]
    refs = ["sha256:" + "a" * 64]
    success.update(kind="success", rejection_transition=rejected["id"], guard_refs=list(refs))
    rejected.update(kind="rejection", guard_refs=list(refs), invariants=list(success["invariants"]))
    rejected["from"] = success["from"]
    recovery.update(kind="recovery", retry_of=success["id"], max_attempts=2,
                    guard_refs=list(refs), invariants=list(success["invariants"]))
    recovery["from"], recovery["to"] = rejected["to"], success["from"]
    path.write_text(yaml.safe_dump(model, sort_keys=False))
    assert validate_ci_state_matrix(repo, authored_only=True)["authority"] is False
    if changed: recovery["guard_refs"] = ["sha256:" + "b" * 64]
    else: recovery.pop("guard_refs")
    path.write_text(yaml.safe_dump(model, sort_keys=False))
    with pytest.raises(CIStateMatrixError, match="guard"):
        validate_ci_state_matrix(repo, authored_only=True)


def test_substituted_comparison_head_cannot_hide_changed_contract(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    base = _git(repo, 'rev-parse', 'HEAD')
    (repo / 'bcf_governance/tooling/preflight.py').write_text('VALUE = 2\n')
    _git(repo, 'add', '.')
    _git(repo, 'commit', '-m', 'contract change without matrix')
    head = _git(repo, 'rev-parse', 'HEAD')
    for name, value in {
        'BCF_PROVIDER_EVENT': 'pull_request', 'GITHUB_EVENT_NAME': 'pull_request',
        'BCF_INVOCATION_KIND': 'direct_event', 'BCF_COMPARISON_BASE_SHA': head,
        'BCF_ORIGIN_COMPARISON_BASE_SHA': base, 'BCF_PR_BASE_SHA': base,
        'BCF_CALLER_COMPARISON_BASE_SHA': '',
    }.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(CIStateMatrixError, match='comparison'):
        validate_ci_state_matrix(repo)


def test_bare_local_comparison_assertion_cannot_choose_a_new_base(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    (repo / 'bcf_governance/tooling/preflight.py').write_text('VALUE = 2\n')
    _git(repo, 'add', '.')
    _git(repo, 'commit', '-m', 'contract change without matrix')
    monkeypatch.setenv('BCF_COMPARISON_BASE_SHA', _git(repo, 'rev-parse', 'HEAD'))
    with pytest.raises(CIStateMatrixError, match='comparison'):
        validate_ci_state_matrix(repo)


def _comparison_environment(monkeypatch, base, *, event='pull_request', invocation='direct_event'):
    values = {
        'BCF_PROVIDER_EVENT': event, 'GITHUB_EVENT_NAME': event,
        'BCF_INVOCATION_KIND': invocation, 'BCF_COMPARISON_BASE_SHA': base,
        'BCF_ORIGIN_COMPARISON_BASE_SHA': base,
        'BCF_PR_BASE_SHA': base if event == 'pull_request' else '',
        'BCF_CALLER_COMPARISON_BASE_SHA': base if invocation == 'reusable_call' else '',
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)


@pytest.mark.parametrize('event,invocation', [('pull_request', 'direct_event'), ('push', 'direct_event'), ('pull_request', 'reusable_call'), ('push', 'reusable_call')])
def test_valid_comparison_context_preserves_changed_contract_requirement(tmp_path, monkeypatch, event, invocation):
    repo = _repo(tmp_path)
    base = _git(repo, 'rev-parse', 'HEAD')
    _comparison_environment(monkeypatch, base, event=event, invocation=invocation)
    (repo / 'bcf_governance/tooling/preflight.py').write_text('VALUE = 2\n')
    with pytest.raises(CIStateMatrixError, match='same-candidate state matrix'):
        validate_ci_state_matrix(repo)
    with (repo / 'spec/RELEASE_TRAIN_STATE_DAG.md').open('a') as stream:
        stream.write('\nContext-specific coverage.\n')
    assert validate_ci_state_matrix(repo)['comparison_base'] == base


@pytest.mark.parametrize('event', ['schedule', 'workflow_dispatch'])
def test_noncomparison_context_does_not_invent_a_local_merge_base(tmp_path, monkeypatch, event):
    repo = _repo(tmp_path)
    _comparison_environment(monkeypatch, '', event=event)
    assert validate_ci_state_matrix(repo)['comparison_base'] is None
    monkeypatch.setenv('BCF_COMPARISON_BASE_SHA', _git(repo, 'rev-parse', 'HEAD'))
    with pytest.raises(CIStateMatrixError, match='comparison'):
        validate_ci_state_matrix(repo)


@pytest.mark.parametrize('defect', ['origin', 'pr', 'direct_caller', 'missing_caller', 'wrong_caller', 'event', 'invocation', 'symbolic', 'zero', 'unavailable', 'nonancestor'])
def test_invalid_comparison_context_rejects_before_diff(tmp_path, monkeypatch, defect):
    from bcf_governance.tooling.governance_validation import ci_state_matrix as matrix

    repo = _repo(tmp_path)
    base = _git(repo, 'rev-parse', 'HEAD')
    _comparison_environment(monkeypatch, base)
    if defect == 'origin':
        monkeypatch.setenv('BCF_ORIGIN_COMPARISON_BASE_SHA', 'a' * 40)
    elif defect == 'pr':
        monkeypatch.setenv('BCF_PR_BASE_SHA', 'a' * 40)
    elif defect == 'direct_caller':
        monkeypatch.setenv('BCF_CALLER_COMPARISON_BASE_SHA', base)
    elif defect == 'missing_caller':
        monkeypatch.setenv('BCF_INVOCATION_KIND', 'reusable_call')
    elif defect == 'wrong_caller':
        _comparison_environment(monkeypatch, base, invocation='reusable_call')
        monkeypatch.setenv('BCF_CALLER_COMPARISON_BASE_SHA', 'a' * 40)
    elif defect == 'event':
        monkeypatch.setenv('GITHUB_EVENT_NAME', 'push')
    elif defect == 'invocation':
        monkeypatch.setenv('BCF_INVOCATION_KIND', '')
    elif defect == 'symbolic':
        _comparison_environment(monkeypatch, 'HEAD')
    elif defect == 'zero':
        _comparison_environment(monkeypatch, '0' * 40)
    elif defect == 'unavailable':
        _comparison_environment(monkeypatch, 'f' * 40)
    else:
        tree = _git(repo, 'rev-parse', 'HEAD^{tree}')
        unrelated = _git(repo, 'commit-tree', tree, '-m', 'unrelated')
        _comparison_environment(monkeypatch, unrelated)
    real = matrix._git
    def guarded(root, *args):
        if args and args[0] == 'diff':
            raise AssertionError('diff executed before context rejection')
        return real(root, *args)
    monkeypatch.setattr(matrix, '_git', guarded)
    with pytest.raises(CIStateMatrixError, match='comparison'):
        validate_ci_state_matrix(repo)


def test_invalid_comparison_rejects_before_matrix_decoding(tmp_path, monkeypatch):
    from bcf_governance.tooling.governance_validation import ci_state_matrix as matrix

    repo = _repo(tmp_path)
    base = _git(repo, 'rev-parse', 'HEAD')
    _comparison_environment(monkeypatch, base)
    monkeypatch.setenv('BCF_ORIGIN_COMPARISON_BASE_SHA', 'a' * 40)
    monkeypatch.setattr(matrix, '_validate_machine_backtrace', lambda *_: pytest.fail('matrix decoded before comparison rejection'))
    with pytest.raises(CIStateMatrixError, match='comparison'):
        validate_ci_state_matrix(repo)


def test_invalid_comparison_stops_real_preflight_before_session_allocation(tmp_path, monkeypatch):
    import sys
    from bcf_governance.tooling import preflight

    repo = _repo(tmp_path)
    base = _git(repo, 'rev-parse', 'HEAD')
    _comparison_environment(monkeypatch, base)
    monkeypatch.setenv('BCF_ORIGIN_COMPARISON_BASE_SHA', 'a' * 40)
    # The fixture has no phase ledger; keep the real Git and state-matrix checks.
    monkeypatch.setattr(preflight, 'validate_authored_phase_state', lambda _: {})
    monkeypatch.setattr(preflight, 'allocate_session', lambda *a, **kw: pytest.fail('session allocated after invalid comparison'))
    trace = []
    evidence = tmp_path / 'evidence'
    before = _git(repo, 'status', '--porcelain')
    with pytest.raises(ValueError, match='comparison'):
        preflight.run_preflight(repo, mode='pr', python_executable=Path(sys.executable), artifact_root=evidence, trace=trace.append)
    assert trace == ['git-state', 'pr-context']
    assert not evidence.exists()
    assert _git(repo, 'status', '--porcelain') == before


def test_authored_only_is_structural_without_comparison_authority(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    _comparison_environment(monkeypatch, 'HEAD')
    report = validate_ci_state_matrix(repo, authored_only=True)
    assert report['status'] == 'authored_structurally_valid'
    assert report['authority'] is False
    assert report['execution_qualified'] is False


def test_matching_bare_local_comparison_assertion_is_preserved(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    base = _git(repo, 'rev-parse', 'origin/main')
    monkeypatch.setenv('BCF_COMPARISON_BASE_SHA', base)
    assert validate_ci_state_matrix(repo)['comparison_base'] == base


@pytest.mark.parametrize('consumer', ['adopter_compatibility_observation', 'bounded_workitem_frontier_contract'])
def test_all_primitive_consumers_reject_undeclared_references(tmp_path, consumer):
    repo = _repo(tmp_path)
    path = repo / 'spec/phase0/release-train-backtrace.yml'
    model = yaml.safe_load(path.read_text())
    if consumer == 'bounded_workitem_frontier_contract':
        model[consumer]['primitive'] = 'PRIM-UNKNOWN'
    else:
        model[consumer]['primitives'].append('PRIM-UNKNOWN')
    path.write_text(yaml.safe_dump(model, sort_keys=False))
    with pytest.raises(CIStateMatrixError, match='primitive reference'):
        validate_ci_state_matrix(repo, authored_only=True)


def test_actual_backtrace_declares_every_active_primitive():
    model = yaml.safe_load((ROOT / 'spec/phase0/release-train-backtrace.yml').read_text())
    declared = {row['id'] for row in model['primitives']}
    consumed = set(model['adopter_compatibility_observation']['primitives']) | {model['bounded_workitem_frontier_contract']['primitive']}
    assert consumed <= declared


def test_actual_backtrace_binds_all_retained_p26_primitive_owners():
    retained = yaml.safe_load((ROOT / 'audits/bcf-2.1-p26-invariant-ownership.yml').read_text())
    model = yaml.safe_load((ROOT / 'spec/phase0/release-train-backtrace.yml').read_text())
    bindings = {row['canonical_name']: row for row in model['primitives']}
    assert {row['id'] for row in retained['primitives']} <= bindings.keys()
    for row in retained['primitives']:
        assert bindings[row['id']]['canonical_reference'] == row['canonical_owner']
        assert bindings[row['id']]['executable_owner'] == row['executable_owner']


def test_retained_primitive_references_resolve_current_schema_and_source():
    import json
    from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
    model = yaml.safe_load((ROOT / 'spec/phase0/release-train-backtrace.yml').read_text())
    retained = yaml.safe_load((ROOT / 'audits/bcf-2.1-p26-invariant-ownership.yml').read_text())['primitives']
    names = {row['id'] for row in retained}
    rows = [row for row in model['primitives'] if row['canonical_name'] in names]
    modules = sorted({ROOT / row['executable_owner'].partition('::')[0] for row in rows})
    functions = {row['symbol'] for row in discover_python_source(ROOT, files=modules)['functions']}
    for row in rows:
        path, _, fragment = row['canonical_reference'].partition('#')
        raw = (ROOT / path).read_text()
        value = json.loads(raw) if path.endswith('.json') else yaml.safe_load(raw)
        for key in filter(None, fragment.split('/')):
            value = value[key.replace('~1', '/').replace('~0', '~')]
        assert value is not None
        module, separator, function = row['executable_owner'].partition('::')
        assert (ROOT / module).is_file()
        if separator:
            assert row['executable_owner'] in functions


@pytest.mark.parametrize('normative', [False, True])
def test_rejected_provider_design_cannot_become_active_primitive_authority(tmp_path, normative):
    repo = _repo(tmp_path)
    path = repo / 'spec/phase0/release-train-backtrace.yml'
    model = yaml.safe_load(path.read_text())
    model['adopter_source_transaction']['normative'] = normative
    model['adopter_source_transaction']['primitives'].append('PRIM-HISTORICAL-UNIMPLEMENTED')
    path.write_text(yaml.safe_dump(model, sort_keys=False))
    if normative:
        with pytest.raises(CIStateMatrixError, match='schema violation'):
            validate_ci_state_matrix(repo, authored_only=True)
    else:
        result = validate_ci_state_matrix(repo, authored_only=True)
        assert result['authority'] is False
        assert result['execution_qualified'] is False

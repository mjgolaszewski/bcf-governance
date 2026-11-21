"""Controlled source/native selectors and canonical fixture model evidence.

These fixtures simulate an authenticated protected model producer. They do not
qualify an actual native implementation, namespace, provider role or release.
"""
import ast
import hashlib
import json
import shutil
from pathlib import Path
import pytest
import yaml
from bcf_governance.tooling import ci_graph_composition_operations as owner
from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
from tests.test_governance_truth import _make_repo, _enable_v3_grouped_session, _git
ROOT = Path(__file__).parents[1]
CALLER = 'bcf_governance/tooling/ci_commands.py::main'
CALLEE = 'bcf_governance/tooling/nested_cli_runtime.py::cli_arguments'
OPERATION = 'governance.cli.ci.v1'
PAIR = ('release', 'build', 'verify')
NATIVE = dict(implementation_sha256='a' * 64, namespace_sha256='b' * 64)

def subject(root):
    return dict(commit_sha=_git(root, 'rev-parse', 'HEAD'), tree_sha=_git(root, 'rev-parse', 'HEAD^{tree}'))

def operation_payload():
    return dict(schema_version='1.1', document=dict(kind='application_operation_registry', id='fixture-runtime-model', version='1.1.0', status='active', path='governance/application-operations.yml'), populations=[dict(id='cli', adapter='python_mapping', source='entry.py', symbol='COMMANDS', public_only=True)], operations=[dict(id=OPERATION, population='cli', population_key='ci', family='cli', bounded_context='ci_authority', entrypoints=[CALLER], semantic_kind='command', authoritative_read=True, authoritative_mutation=False, authority_conferral=False, produces_projection=False, model_callable=False, allowed_mutation_ports=[], allowed_authority_ports=[], non_authoritative_output_effects=[], runtime_qualifications=[dict(model='python.cli-string-snapshot', version='1.0', claims=['test-claim'], profiles=['normal'])])], migrations=[])

def statement_for(root, inventory):
    caller_raw = (root / CALLER.split('::')[0]).read_bytes()
    guard_raw = (root / CALLEE.split('::')[0]).read_bytes()
    main = next((node for node in ast.parse(caller_raw).body if isinstance(node, ast.FunctionDef) and node.name == 'main'))
    function = next((row for row in inventory['functions'] if row['symbol'] == CALLER))
    calls = {(row['line'], row['column']): row for row in function['calls'] if row.get('called_symbol') == CALLEE}
    sites = []
    for node in ast.walk(main):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != 'cli_arguments':
            continue
        call = calls[node.lineno, node.col_offset]
        value = node.args[0]
        sites.append(dict(caller=CALLER, callee=CALLEE, line=node.lineno, column=node.col_offset, expression_sha256=hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest(), occurrence=call['call_contract']['occurrence'], input_origin='cli_entry_vector' if isinstance(value, ast.Name) else 'parser_append_vector'))
    sites.sort(key=lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')))
    return dict(schema_version='1.0', model='python.cli-string-snapshot', model_version='1.0', target=dict(source_subject=subject(root), operation=OPERATION, entrypoint=CALLER, profile='normal', native_subject=dict(NATIVE)), caller_sha256=hashlib.sha256(caller_raw).hexdigest(), guard_sha256=hashlib.sha256(guard_raw).hexdigest(), call_sites=sites)

@pytest.fixture
def context_inputs(tmp_path):
    root = _make_repo(tmp_path)
    for relative in [CALLER.split('::')[0], CALLEE.split('::')[0]]:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, path)
    for relative in ['bcf_governance/__init__.py', 'bcf_governance/tooling/__init__.py']:
        (root / relative).write_text('')
    (root / 'entry.py').write_text('from bcf_governance.tooling.ci_commands import main\nCOMMANDS={"ci":main}\n')
    shutil.copyfile(ROOT / 'schemas/application-operations.schema.json', root / 'schemas/application-operations.schema.json')
    (root / 'governance/application-operations.yml').write_text(yaml.safe_dump(operation_payload()))
    gate_path = root / 'governance/gate-contracts.yml'
    gate = yaml.safe_load(gate_path.read_text())
    manifest = root / 'governance/test-manifests/qualifier.txt'
    manifest.parent.mkdir(parents=True)
    manifest.write_text('tests/test_security.py::test_auth\n')
    gate['gates']['test']['evidence'] = {'kind': 'test_suite', 'test_contract': {'expected_node_manifest': 'governance/test-manifests/qualifier.txt'}}
    for gate_id in ['test', 'security-review', 'reconcile']:
        gate['gates'][gate_id]['negative_controls'] = [dict(id='assertion-removed' if gate_id == 'test' else 'gate-broken', mutation=dict(path='plans/phase-01-workitems.yml', yaml_path='workitems[0].status', value='TODO'), oracle=dict(kind='test_node_failure', node_ids=['tests/test_security.py::test_auth']) if gate_id == 'test' else dict(kind='diagnostic', exit_codes=[1], stream='stdout', regex='expected mutation failure'))]
    gate_path.write_text(yaml.safe_dump(gate))
    evidence = _enable_v3_grouped_session(root, session_version='3.0')
    current = subject(root)
    facts = discover_python_source(root, source_subject=current, call_contracts_version='1.0')
    statement = statement_for(root, facts)
    for path in evidence.glob('*.evidence.json'):
        receipt = json.loads(path.read_bytes())
        receipt['qualification']['control_ids'] = [row['id'] for row in receipt['behavioral_probes']]
        if receipt['gate_id'] == 'test':
            receipt['observations']['runtime_context'] = statement
        path.write_text(json.dumps(receipt))
    public = owner.capture_public_operation_bindings(root, policy_subject=current, runtime_subject=current, required_relationships={OPERATION: frozenset({PAIR})}, relationship_roots={PAIR: frozenset({CALLER})})
    return dict(repo_root=root, inventory=facts, public_capture=public, operation_id=OPERATION, evidence_root=evidence, native_subject=dict(NATIVE))

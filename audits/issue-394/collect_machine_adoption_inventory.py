"""Read-only local adoption inventory; existing owners retain all semantics."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

from bcf_governance.tooling.ci_graph_contracts import validate_ci_graph
from bcf_governance.tooling.ci_graph_composition import edge_population_sha256
from bcf_governance.tooling.ci_graph_yaml import load_yaml_bytes
from bcf_governance.tooling.governance_validation.ci_state_matrix import (
    BACKTRACE_PATH, CIStateMatrixError, validate_ci_state_matrix,
)


def collect(repo_root: Path) -> dict:
    """Observe source shapes, never certify lifecycle adoption or execution."""
    paths = (BACKTRACE_PATH, 'schemas/release-train-backtrace.schema.json')
    captured = {path: (repo_root / path).read_bytes() for path in paths}
    native = validate_ci_state_matrix(repo_root, authored_only=True)
    if any((repo_root / path).read_bytes() != content for path, content in captured.items()):
        raise CIStateMatrixError('native backtrace inputs changed during inventory')
    model = load_yaml_bytes(captured[BACKTRACE_PATH], source=BACKTRACE_PATH)
    compiled = validate_ci_graph(repo_root)
    def git(*args: str) -> str:
        return subprocess.run(['git', *args], cwd=repo_root, check=True,
                              capture_output=True, text=True).stdout.strip()
    transitions = []
    for row in model['transitions']:
        required = {'kind', 'guard_refs'}
        if row.get('kind') == 'success':
            required.add('rejection_transition')
        elif row.get('kind') == 'recovery':
            required.update({'retry_of', 'max_attempts'})
        transitions.append(dict(id=row['id'], producer_state=row['from'], consumer_state=row['to'],
                                declared_kind=row.get('kind'), missing_typed_fields=sorted(required - row.keys())))
    states = [dict(id=row['id'], terminal_class_declared='terminal_class' in row,
                   declared_terminal_class=row.get('terminal_class')) for row in model['states']]
    edges = compiled.edge_contracts
    return dict(
        schema_version='1.0', kind='machine_lifecycle_adoption_inventory', authority=False,
        execution_qualified=False, normative_adoption_qualified=False,
        qualification='local_source_observation_only',
        producer=dict(recipe_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      graph_owner='bcf_governance/tooling/ci_graph_contracts.py::validate_ci_graph',
                      native_owner='bcf_governance/tooling/governance_validation/ci_state_matrix.py::validate_ci_state_matrix'),
        source=dict(base_commit_sha=git('rev-parse', 'HEAD'), base_tree_sha=git('rev-parse', 'HEAD^{tree}'),
                    native_input_sha256={path: hashlib.sha256(content).hexdigest() for path, content in captured.items()},
                    compiled_input_sha256=dict(compiled.input_sha256)),
        canonical_ci=dict(graph_sha256=compiled.graph_sha256, edge_population_sha256=edge_population_sha256(compiled),
                          edge_owner='bcf_governance/tooling/ci_graph_edges.py::compile_edge_contracts',
                          workflow_count=len(compiled.graph['workflows']),
                          job_count=sum(len(row['jobs']) for row in compiled.graph['workflows']),
                          ordered_pair_count=len(edges), reachable_count=sum(row.reachable for row in edges),
                          excluded_count=sum(not row.reachable for row in edges)),
        backtrace=dict(native_structural_observation=native, historical_source_declaration=model['document']['source'],
                       invariant_count=len(model['invariants']), primitive_count=len(model['primitives']),
                       active_compatibility_edge_ids=sorted(row['id'] for row in model['adopter_compatibility_observation']['edges']),
                       states=sorted(states, key=lambda row: row['id']),
                       transitions=sorted(transitions, key=lambda row: row['id'])),
        independently_unevaluated=[
            'authenticated successor baseline and installed consumer custody',
            'complete context-qualified lifecycle contracts and independently grounded exclusions',
            'independent runtime authority-effect and producer-consumer populations',
            'exact source/call/fact/test/control and typed recovery bindings',
            'positive and cause-specific negative execution qualification',
            'approved measurements, installed profiles and immutable terminal custody',
        ],
        interpretation='CI pair closure and native field presence do not prove full lifecycle conformance. '
                       'Historical source labels are retained, not authenticated as current admission. '
                       'No prose retirement or normative activation is claimed.',
    )


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=Path.cwd())
    print(json.dumps(collect(parser.parse_args().repo_root), indent=2, sort_keys=True))

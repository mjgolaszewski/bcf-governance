"""Read-only inventory of existing compiled job deadlines, never sufficiency proof."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import subprocess

from bcf_governance.tooling.ci_graph_contracts import validate_ci_graph
from bcf_governance.tooling.semantic_source_paths import committed_regular_blob_capture


def _subject(root: Path) -> dict[str, str]:
    def git(expression: str) -> str:
        return subprocess.check_output(['git', 'rev-parse', expression], cwd=root, text=True).strip()
    return {'commit_sha': git('HEAD'), 'tree_sha': git('HEAD^{tree}')}


def collect(repo_root: Path) -> dict:
    """Project all compiled jobs; caller authenticates source and compiler owner."""
    subject = _subject(repo_root)
    compiled = validate_ci_graph(repo_root)
    declared = dict(compiled.input_sha256 + compiled.extension_sha256)
    paths = {'governance/ci-graph.yml', 'schemas/ci-graph.schema.json'} | declared.keys()
    captures = {}
    for path in sorted(paths):
        identity, raw = committed_regular_blob_capture(repo_root, path=path, **subject)
        if (repo_root / path).read_bytes() != raw or (
            path in declared and declared[path] != identity['sha256']
        ):
            raise ValueError('deadline inventory compiled input differs from committed subject')
        captures[path] = identity['sha256']
    jobs = []
    for workflow in compiled.graph['workflows']:
        for job in workflow['jobs']:
            executor = job['executor']
            floors = []
            for component_id in executor.get('components', []):
                component = compiled.graph['step_components'][component_id]
                if 'minimum_job_timeout_minutes' in component:
                    floors.append({'component': component_id, 'minimum_job_timeout_minutes': component['minimum_job_timeout_minutes']})
            jobs.append({'workflow': workflow['id'], 'job': job['id'],
                         'timeout_minutes': job['timeout_minutes'],
                         'executor': copy.deepcopy(executor), 'component_floors': floors})
    if _subject(repo_root) != subject or any(
        hashlib.sha256((repo_root / path).read_bytes()).hexdigest() != digest
        for path, digest in captures.items()
    ):
        raise ValueError('deadline inventory source changed during capture')
    return {'schema_version': '1.0', 'kind': 'compiled_job_deadline_inventory',
            'authority': False, 'execution_qualified': False,
            'scope': 'compiled_job_deadlines_and_declared_component_floors_only',
            'producer': {'recipe_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                         'compiler_owner': 'bcf_governance/tooling/ci_graph_contracts.py::validate_ci_graph'},
            'subject': subject, 'compiled_graph_sha256': compiled.graph_sha256,
            'committed_inputs_sha256': captures,
            'jobs': sorted(jobs, key=lambda row: (row['workflow'], row['job'])),
            'unqualified': ['independent complete runtime provider consumer population',
                            'bounded retry setup cleanup measurement headroom composition',
                            'deadline sufficiency activation and terminal custody']}

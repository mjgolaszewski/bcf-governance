"""Project scheduled modern proof through the existing planned-session protocol."""
from __future__ import annotations

import copy
from typing import Any

from .ci_graph_builders import component
from .evidence_shards import workflow_shard_matrix


def _scope(value: Any, names: dict[str, str], workflow: str) -> Any:
    if isinstance(value, dict):
        return {key: item if key == 'action' else _scope(item, names, workflow)
                for key, item in value.items()}
    if isinstance(value, list):
        return [_scope(item, names, workflow) for item in value]
    if isinstance(value, str):
        return names.get(value, value.replace('bcf-session-', f'bcf-{workflow}-session-')
                         .replace('bcf-evidence-', f'bcf-{workflow}-evidence-')
                         .replace('bcf-governance-truth', f'bcf-{workflow}-truth'))
    return value


def project_scheduled_proof(graph: dict[str, Any], gates: list[str]) -> None:
    """Use session-selected producers; literal aliases never select runtime work."""
    components = ('checkout-candidate', 'setup-python', 'install-governance', 'upload-session',
                  'download-session', 'restore-session-modes', 'capture-shard', 'upload-receipts',
                  'download-receipts', 'restore-receipt-modes', 'truth', 'upload-truth')
    for workflow in graph['workflows']:
        if workflow['role'] != 'scheduled':
            continue
        wid = workflow['id']
        preflight_id, controls_id, truth_id = (wid + suffix for suffix in ('-preflight', '-controls', '-truth'))
        names = {name: wid + '-' + name for name in components}
        names.update({'evidence-session': wid + '-session', 'governance-receipts': wid + '-receipts',
                      'truth-report': truth_id, 'evidence-prerequisites-green': wid + '-proof-green',
                      'evidence-prerequisites-without-prior': wid + '-proof-green'})
        for command in ('restore-session-modes', 'capture-shard', 'restore-receipt-modes', 'truth'):
            names['v3-' + command] = wid + '-' + command
        for name in components:
            graph['step_components'][names[name]] = _scope(graph['step_components'][name], names, wid)
        for command in ('restore-session-modes', 'capture-shard', 'restore-receipt-modes', 'truth'):
            graph['commands'][wid + '-' + command] = _scope(graph['commands']['v3-' + command], names, wid)
        graph['commands'][truth_id]['environment'] = {
            'BCF_EVALUATION_MODE': 'closure', 'BCF_EVALUATION_TARGET': '',
        }
        graph['conditions'][wid + '-proof-green'] = (
            f"needs.{preflight_id}.result == 'success' && needs.{controls_id}.result == 'success'"
        )
        argv = graph['commands'][preflight_id]['argv']
        graph['commands'][preflight_id]['argv'] = [value for index, value in enumerate(argv)
            if value != '--expected-producer' and (index == 0 or argv[index-1] != '--expected-producer')]
        graph['commands'][preflight_id]['argv'].extend(['--expected-producer', controls_id])
        graph['step_components'][wid + '-preflight-stage'] = component(
            kind='command', name='Run fresh full-profile periodic preflight', command=preflight_id,
        )
        preflight, evidence, truth = (copy.deepcopy(workflow['jobs'][index]) for index in (0, 1, -1))
        for job in (preflight, evidence, truth):
            job.update(checkout=False, components=[])
        preflight.update(executor={'kind': 'component_sequence', 'components': [names[name] for name in
            ('checkout-candidate', 'setup-python', 'install-governance')] + [wid + '-preflight-stage', names['upload-session']]})
        evidence.update(id=controls_id, needs=[preflight_id], consumes=[wid + '-session'],
            produces=[wid + '-receipts'], permissions={'actions': 'read', 'contents': 'read'},
            executor={'kind': 'gate_shard', 'shard_key': 'shard', 'shard_count': 4, 'gates': list(gates),
                'components': [names[name] for name in ('checkout-candidate', 'setup-python', 'install-governance',
                    'download-session', 'restore-session-modes', 'capture-shard', 'upload-receipts')]},
            strategy={'fail_fast': False, 'max_parallel': 4, 'matrix': workflow_shard_matrix()})
        truth.update(needs=[preflight_id, controls_id], consumes=[wid + '-receipts'], executor={
            'kind': 'terminal_truth', 'command': truth_id, 'components': [names[name] for name in
                ('checkout-candidate', 'setup-python', 'install-governance', 'download-receipts',
                 'restore-receipt-modes', 'truth', 'upload-truth')]})
        workflow['jobs'] = [preflight, evidence, truth]

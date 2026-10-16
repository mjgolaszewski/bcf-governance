"""Protected deadline declarations over the existing compiled lifecycle owner."""
from __future__ import annotations

from collections.abc import Mapping
import re

from jsonschema import Draft202012Validator

from .ci_graph_errors import CIGraphError
from .ci_graph_timeouts import quantized_deadline_ms


def _measurement_floor(spec, measurements, expected_subjects, now_ms):
    reference = spec['measurement_ref']
    fallback = spec['measurement_policy'] == 'bounded_fallback'
    if reference is not None and reference not in expected_subjects:
        raise CIGraphError('deadline measurement protected subject is absent')
    if reference is None or reference not in measurements:
        if fallback:
            return 0, 'bounded_fallback_missing'
        raise CIGraphError('deadline required measurement is absent')
    value = measurements[reference]
    if (not isinstance(value, Mapping)
            or set(value) != {'subject', 'observed_at_ms', 'expires_at_ms', 'lower_bound_ms'}
            or value['subject'] != expected_subjects[reference]):
        raise CIGraphError('deadline measurement subject or metadata differs')
    subject = value['subject']
    if (not isinstance(subject, Mapping) or set(subject) != {'commit_sha', 'tree_sha'}
            or any(not isinstance(v, str) or re.fullmatch('[a-f0-9]{40}', v) is None for v in subject.values())):
        raise CIGraphError('deadline measurement subject is malformed')
    if any(type(value[key]) is not int or value[key] < 0
           for key in ('observed_at_ms', 'expires_at_ms', 'lower_bound_ms')):
        raise CIGraphError('deadline measurement clock or floor is malformed')
    if value['observed_at_ms'] > now_ms or value['expires_at_ms'] <= value['observed_at_ms']:
        raise CIGraphError('deadline measurement clock is invalid')
    if value['expires_at_ms'] <= now_ms:
        if fallback:
            return 0, 'bounded_fallback_stale'
        raise CIGraphError('deadline required measurement is stale')
    return value['lower_bound_ms'], 'fresh'


def validate_lifecycle_deadline_bindings(*, compiled, compiled_graph, schema, expected_source,
        required_deadlines, required_ci_consumers, measurements, expected_measurement_subjects, now_ms):
    """Observe declared arithmetic, never authenticate bounds or confer authority.

    Trusted consumers authenticate complete policy, source owners, duration bounds,
    original measurements and clock. This query checks their explicit bindings.
    """
    from .ci_graph_composition import _validate_compiled_identity, edge_population_sha256

    _validate_compiled_identity(compiled)
    if not isinstance(expected_source, Mapping) or compiled['source'] != dict(expected_source):
        raise CIGraphError('deadline source identity differs')
    if (compiled_graph.graph_sha256 != expected_source['graph_sha256']
            or edge_population_sha256(compiled_graph) != expected_source['ci_edges_sha256']):
        raise CIGraphError('deadline compiled CI graph identity differs')
    if (not isinstance(required_deadlines, Mapping) or not isinstance(required_ci_consumers, Mapping)
            or not isinstance(measurements, Mapping)
            or not isinstance(expected_measurement_subjects, Mapping)
            or type(now_ms) is not int or now_ms < 0):
        raise CIGraphError('deadline protected inputs are malformed')
    contracts = {(row['context'], row['producer'], row['consumer']): row['contract']
                 for row in compiled['relationships'] if row['contract'] is not None}
    if required_deadlines.keys() != contracts.keys() or required_ci_consumers.keys() != contracts.keys():
        raise CIGraphError('deadline protected relationship population differs')
    if any(row['contract'] is not None and row['exclusion'] is not None for row in compiled['relationships']):
        raise CIGraphError('deadline excluded relationship carries a contract')
    if any(not isinstance(key, str) or re.fullmatch('[a-f0-9]{64}', key) is None
           or key not in expected_measurement_subjects for key in measurements):
        raise CIGraphError('deadline measurement source reference is unbound')
    try:
        validator = Draft202012Validator({'$ref': '#/$defs/deadline', '$defs': schema['$defs']})
    except (KeyError, TypeError) as exc:
        raise CIGraphError('deadline schema is absent') from exc
    job_budgets = {workflow['id'] + ':' + job['id']: job['timeout_minutes'] * 60000
                   for workflow in compiled_graph.graph['workflows'] for job in workflow['jobs']}
    deadlines = []
    for pair, contract in sorted(contracts.items()):
        spec = required_deadlines[pair]
        if contract.get('deadline') != spec or not isinstance(spec, Mapping):
            raise CIGraphError('deadline declaration differs from protected specification')
        errors = sorted(validator.iter_errors(spec), key=lambda e: tuple(str(v) for v in e.absolute_path))
        if errors:
            raise CIGraphError(f'deadline schema violation: {errors[0].message}')
        operations = spec['operations']
        if len({row['id'] for row in operations}) != len(operations):
            raise CIGraphError('deadline operation identity is duplicated')
        if any(row['owner'] not in contract['implementation'] for row in operations):
            raise CIGraphError('deadline operation owner is not bound by implementation')
        work = sum(row['bounded_attempt_ms'] * row['max_attempts']
                   + row['max_retry_delay_ms'] * (row['max_attempts'] - 1) for row in operations)
        floor, status = _measurement_floor(spec, measurements, expected_measurement_subjects, now_ms)
        required = quantized_deadline_ms(bounded_work_ms=work, setup_ms=spec['setup_ms'],
            cleanup_ms=spec['cleanup_ms'], measured_lower_bound_ms=floor, headroom_ms=spec['headroom_ms'])
        consumers = required_ci_consumers[pair]
        if (not isinstance(consumers, (tuple, list))
                or any(not isinstance(value, str) or not value for value in consumers)
                or len(consumers) != len(set(consumers))
                or set(consumers) != {row['consumer'] for row in contract['ci_edges']}):
            raise CIGraphError('deadline CI consumer population differs from protected inventory')
        if not consumers or any(value not in job_budgets for value in consumers):
            raise CIGraphError('deadline actual outer execution budget is unbound')
        available = min(job_budgets[value] for value in consumers)
        if available < required:
            raise CIGraphError(f'deadline envelope {pair} {available}ms cannot contain required {required}ms')
        deadlines.append(dict(relationship=pair, required_ms=required, available_ms=available,
                              measurement=status, operations_checked=len(operations)))
    return dict(authority=False, execution_qualified=False,
        scope='declared_deadline_arithmetic_with_protected_bindings_only',
        schema_version='1.0', source=dict(expected_source), deadlines=tuple(deadlines))

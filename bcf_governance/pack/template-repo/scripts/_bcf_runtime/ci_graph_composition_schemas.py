"""Exact-source schema reference conformance for dormant lifecycle contracts."""
from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path, PurePosixPath
import re
from urllib.parse import quote, urljoin

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from referencing import Registry, Resource
from referencing.exceptions import CannotDetermineSpecification, NoSuchResource, Unresolvable
from referencing.jsonschema import DRAFT202012

from .ci_graph_errors import CIGraphError
from .semantic_source_paths import committed_regular_blob_capture


_BASE = 'https://bcf.invalid/'
_DRAFT = 'https://json-schema.org/draft/2020-12/schema'


def _schema_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f'duplicate schema JSON key {key!r}')
        value[key] = item
    return value


def _constant(value):
    raise ValueError(f'nonfinite schema JSON value {value}')


def capture_lifecycle_schema_bindings(
    repo_root: Path, *, compiled, expected_source, required_bindings, schema_catalog,
):
    """Caller authenticates complete policy/catalog and exact repository subject.

    This observes committed schema identities and offline reference closure only;
    it does not authenticate the caller, execute producer codecs or confer proof.
    """
    from .ci_graph_composition import _validate_compiled_identity

    _validate_compiled_identity(compiled)
    if not isinstance(expected_source, Mapping) or compiled['source'] != dict(expected_source):
        raise CIGraphError('lifecycle schema source identity differs')
    contracts = {(row['context'], row['producer'], row['consumer']): row['contract']
                 for row in compiled['relationships'] if row['contract'] is not None}
    if (not isinstance(required_bindings, Mapping) or required_bindings.keys() != contracts.keys()
            or not isinstance(schema_catalog, Mapping)):
        raise CIGraphError('lifecycle schema independent population is absent or differs')
    for pair, contract in contracts.items():
        fields = required_bindings[pair]
        if (not isinstance(fields, Mapping) or set(fields) != {'input_schema', 'output_schema'}
                or any(not isinstance(ref, str) or ref not in schema_catalog
                       or contract[field] != ref for field, ref in fields.items())):
            raise CIGraphError('lifecycle schema field reference differs from protected binding')
    paths = {}
    for reference, descriptor in schema_catalog.items():
        if (not isinstance(reference, str) or not reference or not isinstance(descriptor, Mapping)
                or set(descriptor) != {'path', 'sha256'}):
            raise CIGraphError('lifecycle schema catalog descriptor is malformed')
        path, digest = descriptor['path'], descriptor['sha256']
        if (not isinstance(path, str) or not path.startswith('schemas/') or not path.endswith('.json')
                or '\\' in path or '\0' in path or PurePosixPath(path).is_absolute()
                or any(part in {'', '.', '..'} for part in path.split('/'))
                or not isinstance(digest, str) or re.fullmatch('[a-f0-9]{64}', digest) is None
                or (path in paths and paths[path] != digest)):
            raise CIGraphError('lifecycle schema catalog path or digest is invalid or ambiguous')
        paths[path] = digest
    resources, captures = {}, {}
    try:
        for path, expected_digest in sorted(paths.items()):
            identity, raw = committed_regular_blob_capture(
                repo_root, commit_sha=expected_source['commit_sha'],
                tree_sha=expected_source['tree_sha'], path=path,
            )
            if identity['sha256'] != expected_digest:
                raise CIGraphError('lifecycle schema committed digest differs from protected catalog')
            payload = json.loads(raw.decode('utf-8'), object_pairs_hook=_schema_object, parse_constant=_constant)
            Draft202012Validator.check_schema(payload)
            resource = Resource.from_contents(payload, default_specification=DRAFT202012)
            resources[path] = resource
            captures[path] = (identity['blob_oid'], identity['sha256'])

        aliases = {(_BASE + quote(path, safe='/')): (path, id(root.contents), 'resource')
                   for path, root in resources.items()}
        for path, root in resources.items():
            uri = _BASE + quote(path, safe='/')
            pending = [(root, uri)]
            while pending:
                resource, base = pending.pop()
                content = resource.contents
                if isinstance(content, Mapping) and content.get('$schema', _DRAFT) != _DRAFT:
                    raise CIGraphError('lifecycle schema dialect is unsupported')
                uri = urljoin(base, resource.id()) if resource.id() is not None else base
                names = [(uri.rstrip('#'), 'resource')] if resource.id() is not None else []
                names.extend((uri.rstrip('#') + '#' + anchor.name, type(anchor).__name__)
                             for anchor in resource.anchors())
                for name, kind in names:
                    owner = (path, id(content), kind)
                    if name in aliases and aliases[name] != owner:
                        raise CIGraphError('lifecycle schema resource identifier is ambiguous')
                    aliases[name] = owner
                pending.extend((child, uri) for child in resource.subresources())

        def unavailable(uri):
            raise NoSuchResource(ref=uri)
        registry = Registry(retrieve=unavailable).with_resources(
            (_BASE + quote(path, safe='/'), resource) for path, resource in resources.items()
        ).crawl()
        references_checked = 0
        for path, root in resources.items():
            pending = [(root, registry.resolver(_BASE + quote(path, safe='/')).in_subresource(root))]
            while pending:
                resource, resolver = pending.pop()
                if isinstance(resource.contents, Mapping):
                    for key in ('$ref', '$dynamicRef'):
                        if key in resource.contents:
                            resolver.lookup(resource.contents[key])
                            references_checked += 1
                pending.extend((child, resolver.in_subresource(child)) for child in resource.subresources())
    except CIGraphError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, LookupError, RecursionError,
            SchemaError, CannotDetermineSpecification, Unresolvable) as exc:
        raise CIGraphError(f'lifecycle schema capture/reference conformance failed: {exc}') from exc
    return dict(
        authority=False, execution_qualified=False, scope='exact_committed_schema_references_only',
        subject={key: expected_source[key] for key in ('commit_sha', 'tree_sha')},
        schemas_checked=len(resources), references_checked=references_checked,
        schemas=tuple((path, *captures[path]) for path in sorted(captures)),
        bindings=tuple((pair, tuple(sorted(fields.items()))) for pair, fields in sorted(required_bindings.items())),
    )

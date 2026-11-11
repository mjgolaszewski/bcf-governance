"""Source-absent private consumers retain typed recovery and schema ownership."""
import copy
from dataclasses import asdict
import json
import subprocess

from test_ci_graph_composition import (
    composition, binding_inputs, operation_call_binding_inputs, reconstructed_binding_inputs,
)
from test_lifecycle_recovery_composition import typed
from test_installed_evidence_storage import (
    _environment, _record, installed_consumer, isolated_python,
)

PROBE = r'''import copy,hashlib,importlib.util,json,sys
from pathlib import Path
from types import SimpleNamespace
assert importlib.util.find_spec('bcf_governance') is None
private=Path('scripts').resolve();sys.path.insert(0,str(private))
from _bcf_runtime.ci_graph_composition import compile_lifecycle_composition,render_lifecycle_composition,validate_reconstructed_lifecycle_bindings,_bytes
from _bcf_runtime import semantic_ownership_inventory as source
from _bcf_runtime.ci_graph_edges import EdgeContract
from _bcf_runtime.ci_graph_errors import CIGraphError
from _bcf_runtime.ci_github_authority import packaged_repo_root
from _bcf_runtime import ci_recovery_frontier as owner
data=json.loads(sys.argv[1]);binding=data.pop('binding')
binding['repo_root']=Path(binding['repo_root'])
for field in ('required_negative_controls','required_call_edges','required_fact_bindings','required_operation_calls'):
 binding[field]={tuple(key):value for key,value in binding[field]}
binding['collected_selectors']=frozenset(binding['collected_selectors'])
data['expected_relationships']={tuple(k):v for k,v in data.pop('relationships')}
data['expected_effects']=frozenset(tuple(v) for v in data.pop('effects'))
data['expected_populations']={k:tuple(v) for k,v in data['expected_populations'].items()}
data['compiled_graph']=SimpleNamespace(graph_sha256=data.pop('graph_sha256'),edge_contracts=tuple(EdgeContract(**v) for v in data.pop('edges')))
owned=packaged_repo_root()/'schemas/ci-lifecycle-composition.schema.json'
assert owned.resolve().is_relative_to(private)
candidate=Path('schemas/ci-lifecycle-composition.schema.json');saved=candidate.read_bytes()
candidate.write_text('{}')
controls=[]
try:
 compiled=compile_lifecycle_composition(**data)
 assert compiled['recovery_frontier']['edges_checked']==len(owner._EDGES)
 assert compiled['recovery_frontier']['authority'] is False
 assert compiled['recovery_frontier']['context_authority_qualified'] is False
 controls.append('valid-loaded-owner')
 binding['compiled']=compiled
 observed=validate_reconstructed_lifecycle_bindings(**binding)
 assert observed['recovery_frontier']==compiled['recovery_frontier']
 assert observed['authority'] is False and observed['execution_qualified'] is False
 controls.append('reconstructed-source-consumer')
 altered=copy.deepcopy(data);altered['payload']['relationships'][0]['contract']['recovery_edges'].pop()
 try:compile_lifecycle_composition(**altered)
 except CIGraphError as error:assert 'recovery population' in str(error)
 else:raise AssertionError('private compiler accepted omitted recovery')
 controls.append('omitted-recovery-ref')
 altered=copy.deepcopy(data);altered['schema']={}
 try:compile_lifecycle_composition(**altered)
 except CIGraphError as error:assert 'owned schema' in str(error)
 else:raise AssertionError('candidate schema supplied authority')
 controls.append('candidate-schema')
 forged=copy.deepcopy(compiled);forged['recovery_frontier']['bindings'].pop()
 forged['composition_sha256']=hashlib.sha256(_bytes({k:v for k,v in forged.items() if k!='composition_sha256'})).hexdigest()
 try:render_lifecycle_composition(forged)
 except CIGraphError as error:assert 'recovery' in str(error) and 'differs' in str(error)
 else:raise AssertionError('rehashed recovery cache accepted')
 controls.append('forged-cache')
 downgraded=copy.deepcopy(compiled);downgraded['schema_version']='1.1'
 downgraded['composition_sha256']=hashlib.sha256(_bytes({k:v for k,v in downgraded.items() if k!='composition_sha256'})).hexdigest()
 try:render_lifecycle_composition(downgraded)
 except CIGraphError as error:assert 'recovery' in str(error) and 'version' in str(error)
 else:raise AssertionError('downgraded snapshot skipped recovery validation')
 controls.append('version-downgrade')
 unknown=copy.deepcopy(data);unknown['payload']['schema_version']=1.2;unknown['schema']={}
 try:compile_lifecycle_composition(**unknown)
 except CIGraphError as error:assert 'schema version' in str(error)
 else:raise AssertionError('unknown version borrowed candidate schema')
 controls.append('unknown-version')
 bad_binding=copy.deepcopy(binding);bad_binding['compiled']=forged
 real_discovery=source.discover_python_source
 def premature(*args,**kwargs):raise AssertionError('discovery before recovery rejection')
 source.discover_python_source=premature
 try:
  try:validate_reconstructed_lifecycle_bindings(**bad_binding)
  except CIGraphError as error:assert 'recovery' in str(error) and 'differs' in str(error)
  else:raise AssertionError('consumer accepted stale recovery snapshot')
 finally:source.discover_python_source=real_discovery
 controls.append('early-consumer-rejection')
 key=next(iter(owner._EDGES));previous=owner._EDGES[key]
 try:
  owner._EDGES[key]=('changed',previous[1])
  try:render_lifecycle_composition(compiled)
  except CIGraphError as error:assert 'recovery' in str(error) and 'differs' in str(error)
  else:raise AssertionError('stale loaded-owner state accepted')
 finally:owner._EDGES[key]=previous
 controls.append('owner-drift')
 parked=owned.with_name(owned.name+'.held');owned.rename(parked)
 try:
  try:compile_lifecycle_composition(**data)
  except CIGraphError as error:assert 'owned schema' in str(error)
  else:raise AssertionError('candidate schema replaced missing private resource')
  try:render_lifecycle_composition(compiled)
  except CIGraphError as error:assert 'owned schema' in str(error)
  else:raise AssertionError('cached consumer ignored missing owned schema')
 finally:parked.rename(owned)
 controls.append('missing-owned-schema')
finally:candidate.write_bytes(saved)
assert importlib.util.find_spec('bcf_governance') is None
origins={name:str(Path(module.__file__).resolve()) for name,module in list(sys.modules.items()) if name.startswith('_bcf_runtime.') and getattr(module,'__file__',None)}
assert origins and all(Path(value).is_relative_to(private) for value in origins.values())
print(json.dumps({'controls':controls,'source_sdk_absent':True,'private_origins':origins},sort_keys=True))
'''
compile(PROBE, 'private-typed-recovery', 'exec')


def test_installed_typed_recovery_uses_loaded_owner_and_schema(
    installed_consumer, isolated_python, composition, reconstructed_binding_inputs,
):
    data = typed(composition)
    graph = data.pop("compiled_graph")
    data["relationships"] = list(data.pop("expected_relationships").items())
    data["effects"] = sorted(data.pop("expected_effects"))
    data["graph_sha256"] = graph.graph_sha256
    data["edges"] = [asdict(edge) for edge in graph.edge_contracts]
    binding = copy.deepcopy(reconstructed_binding_inputs)
    binding.pop("compiled")
    binding["repo_root"] = str(binding["repo_root"])
    for name in ("required_negative_controls", "required_call_edges", "required_fact_bindings", "required_operation_calls"):
        binding[name] = list(binding[name].items())
    data["binding"] = binding
    result = subprocess.run(
        [str(isolated_python), "-I", "-B", "-c", PROBE, json.dumps(data, default=lambda value: sorted(value))],
        cwd=installed_consumer, env=_environment(), capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, _record(result)
    observed = json.loads(result.stdout)
    assert observed["source_sdk_absent"] and observed["private_origins"]
    assert observed["controls"] == ["valid-loaded-owner", "reconstructed-source-consumer", "omitted-recovery-ref", "candidate-schema",
                                    "forged-cache", "version-downgrade", "unknown-version", "early-consumer-rejection", "owner-drift", "missing-owned-schema"]

"""Causal native fixture controls; all generated copies are owned pytest temporary inputs."""
from pathlib import Path
import importlib.util
import json
import shutil
import tarfile
import io
import hashlib
import struct
import subprocess
import sys
import zlib
import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("historical_source_fixture_controls", ROOT/".github/scripts/historical_source_fixture.py")
fixture_owner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture_owner)
RELEASE_SPEC = importlib.util.spec_from_file_location("historical_release_owner_controls", ROOT/".github/scripts/test_release_artifacts.py")
release_owner = importlib.util.module_from_spec(RELEASE_SPEC)
# Maintained script establishes its own canonical Source/script import paths.
RELEASE_SPEC.loader.exec_module(release_owner)


@pytest.fixture(scope="module")
def inputs(tmp_path_factory):
    base = tmp_path_factory.mktemp("historical-native-fixture")
    scratch = base/"producer-scratch"; scratch.mkdir()
    generated = base/"generated"
    manifest = fixture_owner.produce(ROOT, generated)
    archive = fixture_owner.native_git(ROOT, scratch, ["archive", "--format=tar", "HEAD"], cap=fixture_owner.MAX_TOTAL)
    return base, generated, manifest, archive


def target(inputs, name, archive_fixture=None):
    base, generated, _manifest, archive = inputs
    source = base/name; source.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as payload:
        payload.extractall(source, filter="data")
    where = source/"tests/fixtures/historical-source-objects/v1"
    where.parent.mkdir(parents=True, exist_ok=True)
    if archive_fixture is False and where.exists():
        # Only this owned extracted testcopy; archived input remains unchanged.
        shutil.rmtree(where)
    if archive_fixture is True:
        where.mkdir(parents=True, exist_ok=True)
        for name in ["objects.pack", "manifest.json"]:
            shutil.copyfile(generated/name, where/name)
    shutil.copytree(generated, where, dirs_exist_ok=True)
    release_owner.initialize_source_custody(source)
    return source, where


@pytest.mark.parametrize("archive_fixture", [False, True])
def test_exact_partial_fixture_import_preserves_synthetic_source(inputs, archive_fixture):
    root, _where = target(inputs, "positive-"+str(archive_fixture), archive_fixture)
    result = fixture_owner.restore(root, inputs[0]/("positive-validation-"+str(archive_fixture)))
    assert result["complete_ancestor_history"] is False
    assert result["authority"] is False
    assert result["synthetic_head_refs_index_source_unchanged"] is True
    assert result["object_count"] == inputs[2]["object_count"]


@pytest.mark.parametrize("kind", ["missing", "corrupt", "subject", "extra-object", "object-hash", "ancestor-claim"])
def test_bad_fixture_refuses_before_target_object_import(inputs, kind):
    root, where = target(inputs, "negative-"+kind)
    manifest_path = where/"manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    if kind == "missing":
        (where/"objects.pack").unlink()
    elif kind == "corrupt":
        packed = bytearray((where/"objects.pack").read_bytes()); packed[len(packed)//2] ^= 1
        (where/"objects.pack").write_bytes(packed)
    elif kind == "subject":
        manifest["subjects"][0]["tree"] = "a"*40
    elif kind == "extra-object":
        row = dict(manifest["objects"][0]); row["id"] = "0"*40
        manifest["objects"].insert(0, row); manifest["object_count"] += 1
        manifest["total_object_bytes"] += row["bytes"]
    elif kind == "object-hash":
        manifest["objects"][0]["sha256"] = "0"*64
    elif kind == "ancestor-claim":
        manifest["complete_ancestor_history"] = True
    manifest_path.write_text(json.dumps(manifest)+"\n")
    scratch = inputs[0]/("negative-validation-"+kind)
    witness = inputs[0]/("negative-witness-"+kind); witness.mkdir()
    before = fixture_owner.native_git(root, witness, ["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"])
    with pytest.raises((RuntimeError, FileNotFoundError)):
        fixture_owner.restore(root, scratch)
    after = fixture_owner.native_git(root, witness, ["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"])
    assert before == after


@pytest.mark.parametrize('kind', ['magic', 'version', 'count', 'declared-object-bound'])
def test_pack_bounds_refuse_before_target_import(inputs, kind):
    root, where = target(inputs, 'bounded-'+kind)
    path = where/'objects.pack'
    packed = bytearray(path.read_bytes())
    manifest_path = where/'manifest.json'
    manifest = json.loads(manifest_path.read_bytes())
    if kind == 'magic':
        packed[:4] = b'FAIL'
    elif kind == 'version':
        packed[4:8] = struct.pack('>I', 4)
    elif kind == 'count':
        packed[8:12] = struct.pack('>I', fixture_owner.MAX_OBJECTS+1)
    else:
        manifest['objects'][0]['bytes'] = fixture_owner.MAX_OBJECT+1
    path.write_bytes(packed)
    manifest['pack']['sha256'] = hashlib.sha256(packed).hexdigest()
    manifest_path.write_text(json.dumps(manifest)+'\n')
    witness = inputs[0]/('bounded-witness-'+kind); witness.mkdir()
    before = fixture_owner.native_git(root, witness, ['cat-file', '--batch-all-objects', '--batch-check=%(objectname)'])
    with pytest.raises(RuntimeError):
        fixture_owner.restore(root, inputs[0]/('bounded-validation-'+kind))
    after = fixture_owner.native_git(root, witness, ['cat-file', '--batch-all-objects', '--batch-check=%(objectname)'])
    assert after == before


@pytest.mark.parametrize('inherited_mib', [128, 512])
def test_real_index_pack_decompression_respects_native_and_inherited_limits(inputs, tmp_path, inherited_mib):
    # A tiny compressed pack declares one 576 MiB blob. Construct it incrementally
    # so the test parent never allocates the expanded object. The production
    # native_git wrapper, rather than a mocked Git, must contain decompression.
    size = 576*1024**2
    remaining = size >> 4
    header = bytearray([(3 << 4) | (size & 15) | 128])
    while remaining:
        value = remaining & 127; remaining >>= 7
        header.append(value | (128 if remaining else 0))
    compressor = zlib.compressobj()
    chunks = [b'PACK'+struct.pack('>II', 2, 1), bytes(header)]
    block = b'x'*1024**2
    blob_id = hashlib.sha1(('blob '+str(size)+'\0').encode())
    blob_digest = hashlib.sha256()
    for _ in range(576):
        blob_id.update(block); blob_digest.update(block)
        chunks.append(compressor.compress(block))
    chunks.append(compressor.flush())
    packed = b''.join(chunks)
    packed += hashlib.sha1(packed).digest()
    assert len(packed) < 1024**2
    payload = tmp_path/'expanded-object.pack'; payload.write_bytes(packed)
    repo = tmp_path/'quarantine'
    subprocess.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', 'init', '--quiet', str(repo)], check=True, timeout=30)
    scratch = tmp_path/'scratch'; scratch.mkdir()
    program = '''
import importlib.util, json, pathlib, resource, sys
spec=importlib.util.spec_from_file_location('bounded_real_owner',sys.argv[1])
owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
packed=pathlib.Path(sys.argv[4]).read_bytes()
requested=int(sys.argv[5])*1024**2
soft,hard=resource.getrlimit(resource.RLIMIT_AS)
bound=min(requested,hard) if hard!=resource.RLIM_INFINITY else requested
resource.setrlimit(resource.RLIMIT_AS,(bound,bound))
try:
 owner.native_git(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]),['index-pack','--stdin'],packed,cap=128)
except RuntimeError as error:
 message=str(error).lower()
 assert message.startswith('native fixture git refused:'),message
 assert any(value in message for value in ['out of memory','cannot allocate','malloc','mmap']),message
 outcome='NATIVE_DECOMPRESSION_MEMORY_REFUSED'
else:
 outcome='BOUNDED_QUARANTINE_STREAMING_ACCEPTED'
proofs=list(pathlib.Path(sys.argv[3]).glob('native-index-pack-limits-*.json'))
assert len(proofs)==1
proof=json.loads(proofs[0].read_bytes())
assert proof['exec_target']=='/usr/bin/git' and proof['pid']>0
assert proof['limits'][str(resource.RLIMIT_AS)]==[bound,bound]
assert max(proof['limits'][str(resource.RLIMIT_FSIZE)])<=128*1024**2
assert max(proof['limits'][str(resource.RLIMIT_CPU)])<=90
print(outcome)
'''
    actual = subprocess.run([sys.executable, '-I', '-B', '-c', program,
                             str(ROOT/'.github/scripts/historical_source_fixture.py'),
                             str(repo), str(scratch), str(payload), str(inherited_mib)],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
    assert actual.returncode == 0, actual.stderr.decode(errors='replace')
    assert actual.stdout.strip() in {b'NATIVE_DECOMPRESSION_MEMORY_REFUSED', b'BOUNDED_QUARANTINE_STREAMING_ACCEPTED'}
    # Even if bounded Git streams successfully in quarantine, production restore
    # must reject a pack containing this undeclared oversized extra object before
    # importing anything into the synthetic TARGET repository.
    root, where = target(inputs, 'oversized-target-'+str(inherited_mib))
    original = (where/'objects.pack').read_bytes()
    count = struct.unpack('>I', original[8:12])[0]
    combined = b'PACK'+struct.pack('>II', 2, count+1)+original[12:-20]+packed[12:-20]
    combined += hashlib.sha1(combined).digest()
    (where/'objects.pack').write_bytes(combined)
    manifest_path = where/'manifest.json'
    manifest = json.loads(manifest_path.read_bytes())
    # Deliberately dishonest declared size exercises native validation, not a
    # producer assertion or reliance on the manifest's claimed expanded bound.
    manifest['objects'].append({'id':blob_id.hexdigest(),'type':'blob','bytes':1,'sha256':blob_digest.hexdigest()})
    manifest['objects'].sort(key=lambda row: row['id'])
    manifest['object_count'] += 1; manifest['total_object_bytes'] += 1
    manifest['pack']['bytes'] = len(combined)
    manifest['pack']['sha256'] = hashlib.sha256(combined).hexdigest()
    manifest_path.write_text(json.dumps(manifest)+'\n')
    before = fixture_owner.native_git(root, scratch, ['cat-file','--batch-all-objects','--batch-check=%(objectname)'])
    with pytest.raises(RuntimeError):
        fixture_owner.restore(root, tmp_path/'oversized-restore-validation')
    after = fixture_owner.native_git(root, scratch, ['cat-file','--batch-all-objects','--batch-check=%(objectname)'])
    assert after == before

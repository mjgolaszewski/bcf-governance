"""Native bounded producer for explicitly incomplete historical source TEST objects."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import struct
import tempfile
import time

SUBJECTS = {
    "5665e3f533028a12da7468ffe057fed0ff8c475f": "e814cc355c04df7fcf613490a62a13b0a403e7c4",
    "1bc71c747dda9e22c66ae2e878a3ed64b4189ab1": "4c01500a509c34e1651a363ffc8f440ab466ba98",
    "deedeced7a30858eba720eaaee0160a2383fc807": "ce0534fb7bf82a6bb249bc31cfde12bc889b0adf",
}
MAX_OBJECTS = 20000
MAX_PACK = 64 * 1024**2
MAX_TOTAL = 256 * 1024**2
MAX_OBJECT = 32 * 1024**2


def native_git(root: Path, scratch: Path, arguments: list[str], data: bytes = b"", cap: int = 8 * 1024**2) -> bytes:
    """Bound both native streams while reading, then reap every launched process."""
    with tempfile.TemporaryFile(dir=scratch) as source:
        source.write(data); source.seek(0)
        environment = dict(os.environ)
        for name in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"]:
            environment.pop(name, None)
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_SYSTEM="/dev/null", GIT_CONFIG_GLOBAL="/dev/null",
                           GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0")
        argv = ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "pack.threads=1",
                "-c", "index.threads=1", "-C", str(root), *arguments]
        if arguments[:1] == ["index-pack"]:
            proof_fd, proof_path = tempfile.mkstemp(prefix="native-index-pack-limits-", suffix=".json", dir=scratch)
            proof_stat = os.fstat(proof_fd)
            os.close(proof_fd)
            limiter = (
                "import json,os,resource,sys; "
                "limits=[(resource.RLIMIT_AS,512*1024**2),(resource.RLIMIT_FSIZE,128*1024**2),(resource.RLIMIT_CPU,90)]; "
                "[(resource.setrlimit(kind,(min(value,hard) if hard!=resource.RLIM_INFINITY else value,)*2)) "
                "for kind,value in limits for soft,hard in [resource.getrlimit(kind)]]; "
                "fd=os.open(sys.argv[1],os.O_WRONLY|os.O_NOFOLLOW); value=os.fstat(fd); "
                "assert (value.st_dev,value.st_ino)==(int(sys.argv[2]),int(sys.argv[3])) and value.st_nlink==1 and value.st_uid==os.getuid(); "
                "proof={'authority':False,'pid':os.getpid(),'exec_target':sys.argv[4],'limits':{str(kind):list(resource.getrlimit(kind)) for kind,_ in limits}}; "
                "os.write(fd,(json.dumps(proof,sort_keys=True)+'\\n').encode()); os.fsync(fd); os.close(fd); "
                "os.execv(sys.argv[4],sys.argv[4:])"
            )
            argv = [sys.executable, "-I", "-B", "-c", limiter, proof_path, str(proof_stat.st_dev), str(proof_stat.st_ino), *argv]
        process = subprocess.Popen(
            argv,
            stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
        )
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + 90
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        raise RuntimeError("bounded native fixture Git deadline exceeded")
                    for key, _ in selector.select(timeout=min(1.0, max(0.0, deadline-time.monotonic()))):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        maximum = cap if key.data == "stdout" else 4096
                        if len(buffers[key.data]) + len(chunk) > maximum:
                            raise RuntimeError("bounded native fixture Git stream exceeded")
                        buffers[key.data].extend(chunk)
            code = process.wait(timeout=max(0.1, deadline-time.monotonic()))
            if code:
                raise RuntimeError("native fixture Git refused: " + buffers["stderr"].decode(errors="replace")[:300])
            return bytes(buffers["stdout"])
        finally:
            if process.poll() is None:
                process.kill(); process.wait(timeout=10)
            process.stdout.close(); process.stderr.close()


def selected_objects(root: Path, scratch: Path) -> tuple[list[dict], list[dict]]:
    objects = set(SUBJECTS)
    subjects = []
    for commit, expected_tree in SUBJECTS.items():
        actual = native_git(root, scratch, ["rev-parse", commit+"^{tree}"], cap=64).decode().strip()
        if actual != expected_tree:
            raise RuntimeError("historical fixture exact subject tree differs")
        objects.add(expected_tree)
        listing = native_git(root, scratch, ["ls-tree", "-r", "-t", "-z", expected_tree])
        for entry in listing.split(b"\0"):
            if not entry:
                continue
            header, _path = entry.split(b"\t", 1)
            _mode, kind, identity = header.split()
            if kind not in {b"tree", b"blob"} or re.fullmatch(rb"[a-f0-9]{40}", identity) is None:
                raise RuntimeError("historical fixture has unsupported object entry")
            objects.add(identity.decode())
            if len(objects) > MAX_OBJECTS:
                raise RuntimeError("historical fixture object population exceeds bound")
        raw = native_git(root, scratch, ["cat-file", "commit", commit], cap=MAX_OBJECT)
        parents = [line[7:].decode() for line in raw.split(b"\n\n", 1)[0].splitlines() if line.startswith(b"parent ")]
        subjects.append({"commit": commit, "tree": expected_tree, "parents": parents})
    identities = sorted(objects)
    checked = native_git(root, scratch, ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
                         ("\n".join(identities)+"\n").encode(), cap=2*1024**2)
    metadata = []
    for expected, line in zip(identities, checked.decode().splitlines(), strict=True):
        identity, kind, size = line.split(); size = int(size)
        if identity != expected or kind not in {"tree", "blob", "commit"} or not 0 <= size <= MAX_OBJECT:
            raise RuntimeError("historical fixture object type/size mismatch")
        metadata.append((identity, kind, size))
    if sum(row[2] for row in metadata) > MAX_TOTAL:
        raise RuntimeError("historical fixture total object bytes exceed bound")
    raw_batch = native_git(root, scratch, ["cat-file", "--batch"],
                           ("\n".join(identities)+"\n").encode(), cap=MAX_TOTAL+MAX_OBJECTS*128)
    rows = []; cursor = 0
    for identity, kind, size in metadata:
        end = raw_batch.find(b"\n", cursor)
        if end < 0 or raw_batch[cursor:end].decode() != f"{identity} {kind} {size}":
            raise RuntimeError("historical fixture native batch header differs")
        cursor = end + 1
        raw = raw_batch[cursor:cursor+size]; cursor += size
        if len(raw) != size or raw_batch[cursor:cursor+1] != b"\n":
            raise RuntimeError("historical fixture native batch body differs")
        cursor += 1
        observed_identity = hashlib.sha1(f"{kind} {size}\0".encode()+raw).hexdigest()
        if observed_identity != identity:
            raise RuntimeError("historical fixture raw Git object digest differs")
        if kind == "commit":
            native_identity = native_git(root, scratch, ["hash-object", "-t", kind, "--stdin"], raw, cap=64).decode().strip()
            if native_identity != identity:
                raise RuntimeError("historical fixture native commit hash differs")
        rows.append({"id": identity, "type": kind, "bytes": size, "sha256": hashlib.sha256(raw).hexdigest()})
    if cursor != len(raw_batch):
        raise RuntimeError("historical fixture native batch contains extra data")
    for subject in subjects:
        subject["absent_parent_history"] = [parent for parent in subject["parents"] if parent not in objects]
    return subjects, rows


def produce(root: Path, output: Path) -> dict:
    output.mkdir(mode=0o700, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="historical-fixture-", dir=output) as temporary:
        scratch = Path(temporary)
        subjects, rows = selected_objects(root, scratch)
        exact_ids = ("\n".join(row["id"] for row in rows)+"\n").encode()
        packed = native_git(root, scratch, ["pack-objects", "--stdout", "--no-reuse-delta", "--no-reuse-object"], exact_ids, cap=MAX_PACK)
        (output/"objects.pack").write_bytes(packed)
        manifest = {
            "schema_version": "1.0", "purpose": "incomplete_historical_source_test_fixture",
            "complete_ancestor_history": False, "authority": False,
            "subjects": subjects, "objects": rows, "object_count": len(rows),
            "total_object_bytes": sum(row["bytes"] for row in rows),
            "pack": {"file": "objects.pack", "bytes": len(packed), "sha256": hashlib.sha256(packed).hexdigest()},
            "prohibitions": ["ancestry", "merge_base", "rev_list_history", "release_authority", "complete_history_fsck_claim"],
        }
        (output/"manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True)+"\n")
        return manifest


def fixture_bytes(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise RuntimeError("historical fixture leaf is unsafe or oversized")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(descriptor)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                    value.st_size, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
        if identity(opened) != identity(before):
            raise RuntimeError("historical fixture changed before admitted read")
        chunks = []; observed = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum+1-observed))
            if not chunk:
                break
            observed += len(chunk)
            if observed > maximum:
                raise RuntimeError("historical fixture grew beyond admitted bound")
            chunks.append(chunk)
        if identity(os.fstat(descriptor)) != identity(before) or identity(path.lstat()) != identity(before):
            raise RuntimeError("historical fixture changed during admitted read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def restore(root: Path, scratch: Path) -> dict:
    """Validate an archive-carried partial fixture in quarantine before native object import."""
    scratch.mkdir(mode=0o700, exist_ok=False)
    fixture = root / "tests/fixtures/historical-source-objects/v1"
    current = fixture
    while current != root:
        if current.is_symlink() or not current.is_dir():
            raise RuntimeError("historical fixture directory is unsafe")
        current = current.parent
    manifest = json.loads(fixture_bytes(fixture/"manifest.json", 8*1024**2))
    if (manifest.get("schema_version") != "1.0" or manifest.get("purpose") != "incomplete_historical_source_test_fixture"
            or manifest.get("complete_ancestor_history") is not False or manifest.get("authority") is not False):
        raise RuntimeError("historical fixture purpose or history scope differs")
    subjects = manifest.get("subjects")
    if not isinstance(subjects, list) or {r.get("commit"):r.get("tree") for r in subjects} != SUBJECTS or len(subjects) != 3:
        raise RuntimeError("historical fixture subject population differs")
    objects = manifest.get("objects")
    if not isinstance(objects, list) or not 3 <= len(objects) <= MAX_OBJECTS or manifest.get("object_count") != len(objects):
        raise RuntimeError("historical fixture object population differs")
    for row in objects:
        if (not isinstance(row, dict) or set(row) != {"id", "type", "bytes", "sha256"}
                or not isinstance(row["id"], str) or re.fullmatch(r"[a-f0-9]{40}", row["id"]) is None
                or row["type"] not in {"commit", "tree", "blob"} or type(row["bytes"]) is not int
                or not 0 <= row["bytes"] <= MAX_OBJECT or not isinstance(row["sha256"], str)
                or re.fullmatch(r"[a-f0-9]{64}", row["sha256"]) is None):
            raise RuntimeError("historical fixture object row is malformed")
    identities = [r["id"] for r in objects]
    if identities != sorted(set(identities)):
        raise RuntimeError("historical fixture object IDs are not exact sorted unique population")
    if manifest.get("total_object_bytes") != sum(r["bytes"] for r in objects) or not 0 <= manifest["total_object_bytes"] <= MAX_TOTAL:
        raise RuntimeError("historical fixture total object bytes differ")
    if manifest.get("pack", {}).get("file") != "objects.pack":
        raise RuntimeError("historical fixture pack path differs")
    packed = fixture_bytes(fixture/"objects.pack", MAX_PACK)
    if len(packed) != manifest["pack"].get("bytes") or hashlib.sha256(packed).hexdigest() != manifest["pack"].get("sha256"):
        raise RuntimeError("historical fixture pack bytes differ")
    if len(packed) < 12 or packed[:4] != b"PACK":
        raise RuntimeError("historical fixture pack header is invalid")
    version, count = struct.unpack(">II", packed[4:12])
    if version not in {2, 3} or count != len(objects) or count > MAX_OBJECTS:
        raise RuntimeError("historical fixture pack header population differs")
    gitdir = root/".git"
    for path in [root, gitdir, gitdir/"objects"]:
        if path.is_symlink() or not path.is_dir():
            raise RuntimeError("historical fixture target is not owned ordinary Git")
    prohibited = [gitdir/"objects/info/alternates", gitdir/"shallow", gitdir/"info/grafts", gitdir/"refs/replace"]
    if any(os.path.lexists(path) for path in prohibited):
        raise RuntimeError("historical fixture target has alternate or rewritten history metadata")
    witness_commands = [["rev-parse", "HEAD"], ["rev-parse", "HEAD^{tree}"], ["ls-files", "--stage", "-z"],
                        ["for-each-ref", "--format=%(refname) %(objectname)"], ["status", "--porcelain=v1", "-z", "--untracked-files=all"]]
    before = [native_git(root, scratch, args) for args in witness_commands]
    tracked = native_git(root, scratch, ["ls-files", "-z"]).split(b"\0")
    if len(tracked) > 10001:
        raise RuntimeError("historical fixture Source inventory exceeds bound")
    def source_inventory():
        rows = {}
        for encoded in tracked:
            if not encoded:
                continue
            relative = Path(os.fsdecode(encoded))
            if relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError("historical fixture Source path escapes owned root")
            path = root/relative
            if path.is_symlink():
                rows[str(relative)] = {"link":os.readlink(path)}
            else:
                rows[str(relative)] = {"sha256":hashlib.sha256(fixture_bytes(path, MAX_PACK)).hexdigest()}
        return rows
    source_before = source_inventory()
    index_before = fixture_bytes(gitdir/"index", 8*1024**2)
    quarantine = scratch/"quarantine.git"; quarantine.mkdir(mode=0o700)
    native_git(quarantine, scratch, ["init", "--bare", "--quiet"])
    native_git(quarantine, scratch, ["index-pack", "--stdin"], packed, cap=128)
    present = native_git(quarantine, scratch, ["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"], cap=MAX_OBJECTS*41)
    if sorted(present.decode().splitlines()) != [r["id"] for r in objects]:
        raise RuntimeError("historical fixture pack object membership differs")
    actual_subjects, actual_objects = selected_objects(quarantine, scratch)
    if actual_subjects != subjects or actual_objects != objects:
        raise RuntimeError("historical fixture native subject/object inventory differs")
    native_git(root, scratch, ["index-pack", "--stdin"], packed, cap=128)
    for commit, tree in SUBJECTS.items():
        if native_git(root, scratch, ["rev-parse", commit+"^{tree}"], cap=64).decode().strip() != tree:
            raise RuntimeError("historical fixture imported tree differs")
    after = [native_git(root, scratch, args) for args in witness_commands]
    if before != after or source_before != source_inventory() or index_before != fixture_bytes(gitdir/"index", 8*1024**2) or any(os.path.lexists(path) for path in prohibited):
        raise RuntimeError("historical fixture import changed synthetic Source or history authority")
    return {"authority":False, "status":"partial_historical_test_objects_imported", "object_count":len(objects),
            "pack_sha256":manifest["pack"]["sha256"], "synthetic_head_refs_index_source_unchanged":True,
            "complete_ancestor_history":False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    produce(options.source.resolve(), options.output.absolute())

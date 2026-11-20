"""OCI/config/rootfs populations stay distinct from normalized scanner labels."""
import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
from bcf_governance.tooling import dependency_assurance as owner

ROOT = Path(__file__).resolve().parents[1]


class Case:
    @staticmethod
    def raw(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    @staticmethod
    def sha(raw):
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def tar(files, extra=()):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, raw in files.items():
                item = tarfile.TarInfo(name)
                item.size = len(raw)
                archive.addfile(item, io.BytesIO(raw))
            for item, raw in extra:
                archive.addfile(item, io.BytesIO(raw) if raw is not None else None)
        return buffer.getvalue()

    def __init__(self, compressed=True):
        self.expanded = [self.tar({"etc/first": b"first"}), self.tar({"etc/second": b"second"})]
        self.layer_data = [gzip.compress(value, mtime=0) if compressed else value for value in self.expanded]
        self.media = "application/vnd.oci.image.layer.v1.tar" + ("+gzip" if compressed else "")
        self.config = {"os": "linux", "architecture": "amd64", "rootfs": {
            "type": "layers", "diff_ids": ["sha256:" + self.sha(raw) for raw in self.expanded]}}
        self.config_media = "application/vnd.oci.image.config.v1+json"
        self.manifest_media = "application/vnd.oci.image.manifest.v1+json"
        self.size_delta = 0
        self.change_files = None
        self.change_index = None
        self.change_compatibility = None
        self.change_sbom = None
        self.extra_members = []

    def arguments(self):
        files = {"oci-layout": self.raw({"imageLayoutVersion": "1.0.0"})}
        def blob(raw, media):
            value = {"mediaType": media, "digest": "sha256:" + self.sha(raw), "size": len(raw)}
            files["blobs/sha256/" + self.sha(raw)] = raw
            return value
        config = blob(self.raw(self.config), self.config_media)
        layers = [blob(raw, self.media) for raw in self.layer_data]
        layers[0]["size"] += self.size_delta
        manifest = blob(self.raw({"schemaVersion": 2, "mediaType": self.manifest_media,
                                 "config": config, "layers": layers}), self.manifest_media)
        index = {"schemaVersion": 2, "manifests": [manifest]}
        if self.change_index:
            self.change_index(index)
        files["index.json"] = self.raw(index)
        compatibility = [{"Config": "blobs/sha256/" + config["digest"][7:], "RepoTags": [],
                          "Layers": ["blobs/sha256/" + value["digest"][7:] for value in layers]}]
        if self.change_compatibility:
            self.change_compatibility(compatibility)
        files["manifest.json"] = self.raw(compatibility)
        if self.change_files:
            self.change_files(files)
        archive = self.tar(files, self.extra_members)
        sbom = {"schema": {"version": "16.1.13"}, "source": {"id": "f" * 64, "type": "image", "metadata": {
            "manifestDigest": "sha256:" + "f" * 64, "imageID": config["digest"],
            "os": "linux", "architecture": "amd64", "layers": [{"digest": value} for value in self.config["rootfs"]["diff_ids"]]}}}
        if self.change_sbom:
            self.change_sbom(sbom)
        return {"archive_bytes": archive, "expected_archive_sha256": self.sha(archive),
                "expected_manifest_digest": manifest["digest"], "max_archive_bytes": 1024 * 1024,
                "max_expanded_bytes": 1024 * 1024, "max_members": 100, "sbom_bytes": self.raw(sbom)}

    def invoke(self, arguments=None):
        return owner.native_archive_subject(**(self.arguments() if arguments is None else arguments))


@pytest.mark.parametrize("compressed", [False, True])
def test_distinct_manifest_config_and_normalized_ids_are_bound_without_authority(compressed):
    case = Case(compressed)
    args = case.arguments()
    report = case.invoke(args)
    assert report["authority"] is report["security_qualified"] is False
    assert report["archive_manifest_digest"] == args["expected_manifest_digest"]
    assert report["config_digest"] == json.loads(args["sbom_bytes"])["source"]["metadata"]["imageID"]
    assert report["config_digest"] != report["archive_manifest_digest"]
    assert report["sbom_binding"]["normalized_manifest_digest"] != report["archive_manifest_digest"]
    assert report["sbom_binding"]["normalized_manifest_independently_verified"] is False
    assert [row["diff_id"] for row in report["layers"]] == case.config["rootfs"]["diff_ids"]
    assert report == case.invoke(args)


def test_optional_sbom_does_not_invent_binding():
    case = Case()
    args = case.arguments()
    args["sbom_bytes"] = None
    assert case.invoke(args)["sbom_binding"] is None


@pytest.mark.parametrize("field", ["max_archive_bytes", "max_expanded_bytes", "max_members"])
@pytest.mark.parametrize("value", [0, -1, True, 1.0, 2**1000])
def test_invalid_bounds_refuse(field, value):
    case = Case()
    args = case.arguments()
    args[field] = value
    with pytest.raises(owner.DependencyAssuranceError):
        case.invoke(args)


@pytest.mark.parametrize("cause", ["archive-pin", "manifest-pin", "mutable-archive", "mutable-sbom",
    "member-bound", "archive-bound", "expanded-bound", "extra-file", "duplicate-member", "symlink", "escape",
    "noncanonical", "pax", "blob-substitution", "descriptor-size", "diff-id", "layer-order", "missing-layer",
    "config-media", "manifest-media", "multiple-images", "wrong-platform", "invalid-gzip", "trailing", "truncated",
    "compat-config", "compat-order", "compat-duplicate-key", "compat-nonfinite", "wrong-layout"])
def test_substituted_incomplete_or_ambiguous_archives_block(cause):
    case = Case()
    if cause == "extra-file":
        case.change_files = lambda files: files.update(unreferenced=b"unaccounted")
    elif cause == "duplicate-member":
        info = tarfile.TarInfo("index.json")
        info.size = 2
        case.extra_members = [(info, b"{}")]
    elif cause in {"symlink", "escape", "noncanonical", "pax"}:
        info = tarfile.TarInfo({"symlink": "link", "escape": "../outside", "noncanonical": "./extra", "pax": "extra"}[cause])
        if cause == "symlink":
            info.type = tarfile.SYMTYPE
            info.linkname = "../outside"
        if cause == "pax":
            info.pax_headers = {"comment": "ambiguous"}
        case.extra_members = [(info, None)]
    elif cause == "blob-substitution":
        def change(files):
            name = next(key for key in files if key.startswith("blobs/"))
            files[name] += b"wrong"
        case.change_files = change
    elif cause == "descriptor-size":
        case.size_delta = 1
    elif cause == "diff-id":
        case.config["rootfs"]["diff_ids"][0] = "sha256:" + "0" * 64
    elif cause == "layer-order":
        case.layer_data.reverse()
    elif cause == "missing-layer":
        case.layer_data.pop()
    elif cause == "config-media":
        case.config_media = "application/octet-stream"
    elif cause == "manifest-media":
        case.manifest_media = "application/octet-stream"
    elif cause == "multiple-images":
        case.change_index = lambda value: value["manifests"].append(value["manifests"][0])
    elif cause == "wrong-platform":
        case.config["os"] = "windows"
    elif cause == "invalid-gzip":
        case.layer_data[0] = b"invalid gzip"
    elif cause == "compat-config":
        case.change_compatibility = lambda value: value[0].update(Config="wrong")
    elif cause == "compat-order":
        case.change_compatibility = lambda value: value[0]["Layers"].reverse()
    elif cause == "compat-duplicate-key":
        case.change_files = lambda files: files.update({"manifest.json": b'[{"Config":"a","Config":"b"}]'})
    elif cause == "compat-nonfinite":
        case.change_compatibility = lambda value: value[0].update(unused=float("inf"))
    elif cause == "wrong-layout":
        case.change_files = lambda files: files.update({"oci-layout": b'{"imageLayoutVersion":"9"}'})
    args = case.arguments()
    if cause == "archive-pin":
        args["expected_archive_sha256"] = "0" * 64
    elif cause == "manifest-pin":
        args["expected_manifest_digest"] = "sha256:" + "0" * 64
    elif cause == "mutable-archive":
        args["archive_bytes"] = bytearray(args["archive_bytes"])
    elif cause == "mutable-sbom":
        args["sbom_bytes"] = bytearray(args["sbom_bytes"])
    elif cause in {"member-bound", "archive-bound", "expanded-bound"}:
        args[{"member-bound": "max_members", "archive-bound": "max_archive_bytes", "expanded-bound": "max_expanded_bytes"}[cause]] = 1
    elif cause in {"trailing", "truncated"}:
        args["archive_bytes"] = args["archive_bytes"] + b"hidden second archive" if cause == "trailing" else args["archive_bytes"][:1024]
        args["expected_archive_sha256"] = case.sha(args["archive_bytes"])
    with pytest.raises(owner.DependencyAssuranceError):
        case.invoke(args)


@pytest.mark.parametrize("cause", ["config", "os", "architecture", "layer-order", "missing-layer", "source-id", "manifest-label", "schema"])
def test_sbom_subject_substitution_or_projection_omission_blocks(cause):
    case = Case()
    def change(sbom):
        source = sbom["source"]
        metadata = source["metadata"]
        if cause == "config":
            metadata["imageID"] = "sha256:" + "0" * 64
        elif cause in {"os", "architecture"}:
            metadata[cause] = "wrong"
        elif cause == "layer-order":
            metadata["layers"].reverse()
        elif cause == "missing-layer":
            metadata["layers"].pop()
        elif cause == "source-id":
            source["id"] = "0" * 64
        elif cause == "manifest-label":
            metadata["manifestDigest"] = "sha1:wrong"
        else:
            sbom["schema"]["version"] = "0"
    case.change_sbom = change
    with pytest.raises(owner.DependencyAssuranceError):
        case.invoke()

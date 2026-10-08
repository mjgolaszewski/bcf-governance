"""One deterministic exact-release adopter qualification transaction."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from typing import Any, Mapping, Sequence

import yaml  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator

from .ci_github_values import GitHubValueError, remote_repository
from .ci_github_api import GitHubAPI


class ReleaseQualificationError(ValueError):
    """Exact release assets or an adopter qualification are incomplete."""


def dispatch_release_qualification(api: GitHubAPI, receipt: dict[str, Any]) -> None:
    """Continue the fixed publication train with no caller-selected routing."""

    subject = receipt.get("subject")
    if not isinstance(subject, dict) or not isinstance(subject.get("repository"), str):
        raise ReleaseQualificationError("release qualification subject is absent")
    api.dispatch(
        subject["repository"],
        event_type="bcf_release_qualified",
        client_payload={"qualification": receipt},
    )


def _run(argv: Sequence[str], *, cwd: Path, env: Mapping[str, str] | None = None) -> str:
    result = subprocess.run(
        list(argv), cwd=cwd, env=dict(env) if env is not None else None,
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ReleaseQualificationError(f"{' '.join(argv[:3])} failed: {detail}")
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _release_assets(root: Path) -> tuple[str, dict[str, str]]:
    checksums = root / "SHA256SUMS"
    if not checksums.is_file() or checksums.is_symlink():
        raise ReleaseQualificationError("release assets lack regular SHA256SUMS")
    declared: dict[str, str] = {}
    for line in checksums.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9_.+-]+)", line)
        if match is None or match.group(2) in declared:
            raise ReleaseQualificationError("release checksum inventory is malformed")
        declared[match.group(2)] = match.group(1)
    wheels = sorted(name for name in declared if name.endswith("-py3-none-any.whl"))
    sdists = sorted(name for name in declared if name.endswith(".tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1 or len(declared) != 2:
        raise ReleaseQualificationError("release checksum inventory must bind one wheel and sdist")
    for name, digest in declared.items():
        path = root / name
        if not path.is_file() or path.is_symlink() or _sha256(path) != digest:
            raise ReleaseQualificationError(f"release asset digest mismatch: {name}")
    version = re.fullmatch(r"bcf_governance-([0-9]+\.[0-9]+\.[0-9]+)-py3-none-any\.whl", wheels[0])
    if version is None:
        raise ReleaseQualificationError("release wheel name does not expose an exact version")
    return version.group(1), dict(sorted(declared.items()))


_EXACT_RELEASE_PROBE = r"""
import importlib.metadata as metadata
import json
from pathlib import Path
import sys

from packaging.requirements import Requirement

import bcf_governance

distribution = metadata.distribution("bcf-governance")
requirements = []
for value in distribution.requires or ():
    requirement = Requirement(value)
    if requirement.marker is not None and not requirement.marker.evaluate():
        continue
    try:
        installed = metadata.version(requirement.name)
    except metadata.PackageNotFoundError:
        installed = None
    requirements.append({
        "name": requirement.name,
        "required": str(requirement.specifier),
        "installed": installed,
        "satisfied": installed is not None and (
            not requirement.specifier
            or requirement.specifier.contains(installed, prereleases=True)
        ),
    })
print(json.dumps({
    "distribution_root": str(Path(distribution.locate_file(".")).resolve()),
    "executable": str(Path(sys.executable).resolve()),
    "module_file": str(Path(bcf_governance.__file__).resolve()),
    "requirements": requirements,
    "version": distribution.version,
}, sort_keys=True))
"""


_CANDIDATE_QUALIFICATION_TRAIN = r"""
import json
from pathlib import Path
import sys

from bcf_governance.tooling.release_adopter_qualification import (
    run_candidate_qualification_train,
)

print(json.dumps(
    run_candidate_qualification_train(Path(sys.argv[1]), Path(sys.argv[2])),
    sort_keys=True,
))
"""


def run_candidate_qualification_train(
    repo_root: Path, project_python: Path
) -> dict[str, Any]:
    """Execute one typed, observation-only adopter qualification proof."""

    from .local_pr import canonical_prospective_inputs, run_prospective_train
    from .local_pr_context import LocalValidationLane

    canonical = canonical_prospective_inputs(repo_root)
    return run_prospective_train(
        repo_root,
        semantic_intent=str(canonical["semantic_intent"]),
        evaluation_target=canonical["evaluation_target"],
        subject_commit=str(canonical["subject_commit"]),
        subject_tree=str(canonical["subject_tree"]),
        python_executable=project_python,
        validation_lane=LocalValidationLane.ISOLATED_CANDIDATE_QUALIFICATION,
    )


def _exact_release_runtime(
    wheel: Path,
    controller: Path,
    *,
    version: str,
    cwd: Path,
    environment: Mapping[str, str],
) -> tuple[tuple[str, ...], dict[str, str]]:
    """Project one exact wheel over the already-admitted invoking runtime."""

    _run([sys.executable, "-m", "venv", str(controller)], cwd=cwd)
    controller_python = controller / "bin/python"
    site_packages = (
        controller / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    site_packages.mkdir(parents=True, exist_ok=True)
    dependency_roots = sorted({
        str(Path(value).resolve())
        for key, value in sysconfig.get_paths().items()
        if key in {"purelib", "platlib"} and Path(value).is_dir()
    })
    if not dependency_roots:
        raise ReleaseQualificationError(
            "invoking release runtime dependency roots are unavailable"
        )
    (site_packages / "bcf-admitted-runtime.pth").write_text(
        "".join(f"{value}\n" for value in dependency_roots), encoding="utf-8"
    )
    _run(
        [
            str(controller_python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-deps",
            "--force-reinstall",
            str(wheel),
        ],
        cwd=cwd,
    )
    runtime_environment = dict(environment)
    runtime_environment.pop("PYTHONHOME", None)
    runtime_environment.pop("PYTHONPATH", None)
    try:
        observation = json.loads(
            _run(
                [str(controller_python), "-P", "-c", _EXACT_RELEASE_PROBE],
                cwd=controller.parent,
                env=runtime_environment,
            )
        )
    except json.JSONDecodeError as exc:
        raise ReleaseQualificationError(
            "exact release runtime probe emitted invalid JSON"
        ) from exc
    if not isinstance(observation, dict) or set(observation) != {
        "distribution_root", "executable", "module_file", "requirements", "version",
    }:
        raise ReleaseQualificationError("exact release runtime identity is malformed")
    controller_root = controller.resolve()
    try:
        Path(observation["distribution_root"]).resolve().relative_to(controller_root)
        Path(observation["module_file"]).resolve().relative_to(controller_root)
        observed_executable = Path(observation["executable"]).resolve()
    except (TypeError, ValueError) as exc:
        raise ReleaseQualificationError(
            "exact release runtime is shadowed by non-release BCF bytes"
        ) from exc
    requirements = observation["requirements"]
    if (
        observation["version"] != version
        or observed_executable != controller_python.resolve()
        or not isinstance(requirements, list)
        or any(
            not isinstance(item, dict)
            or set(item) != {"installed", "name", "required", "satisfied"}
            or item.get("satisfied") is not True
            for item in requirements
        )
    ):
        raise ReleaseQualificationError(
            "exact release runtime dependencies are absent or incompatible"
        )
    return (
        str(controller_python),
        "-P",
        "-c",
        "from bcf_governance.cli import main; main()",
    ), runtime_environment


def parse_contract(contract_bytes: bytes, schema_bytes: bytes) -> dict[str, Any]:
    """Decode the canonical qualification contract and its governing schema."""

    try:
        payload = yaml.safe_load(contract_bytes.decode("utf-8"))
        schema = json.loads(schema_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ReleaseQualificationError("release qualification contract is unreadable") from exc
    errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=lambda item: list(item.path))
    if errors:
        raise ReleaseQualificationError("release qualification contract is invalid: " + errors[0].message)
    repositories = [item["repository"] for item in payload["required_adopters"]]
    identifiers = [item["id"] for item in payload["required_adopters"]]
    if len(repositories) != len(set(repositories)) or len(identifiers) != len(set(identifiers)):
        raise ReleaseQualificationError("release qualification adopters must be unique")
    return payload


def load_contract(repo_root: Path) -> dict[str, Any]:
    path = repo_root / "governance/release-qualification.yml"
    schema_path = repo_root / "schemas/release-qualification.schema.json"
    try:
        return parse_contract(path.read_bytes(), schema_path.read_bytes())
    except OSError as exc:
        raise ReleaseQualificationError("release qualification contract is unreadable") from exc


def _source_identity(root: Path) -> tuple[str, str, str]:
    status = _run(["git", "status", "--porcelain"], cwd=root)
    if status:
        raise ReleaseQualificationError(f"adopter checkout is not clean: {root}")
    remote = _run(["git", "remote", "get-url", "origin"], cwd=root)
    try:
        repository = remote_repository(remote)
    except GitHubValueError as exc:
        raise ReleaseQualificationError("adopter remote is not an exact GitHub repository") from exc
    commit = _run(["git", "rev-parse", "HEAD"], cwd=root)
    tree = _run(["git", "rev-parse", "HEAD^{tree}"], cwd=root)
    if re.fullmatch(r"[a-f0-9]{40}", commit) is None or re.fullmatch(r"[a-f0-9]{40}", tree) is None:
        raise ReleaseQualificationError("adopter Git identity is malformed")
    return repository, commit, tree


def _commit(root: Path, message: str) -> None:
    _run(["git", "add", "-A"], cwd=root)
    result = subprocess.run(
        ["git", "diff", "--cached", "--quiet"], cwd=root, check=False
    )
    if result.returncode == 1:
        _run(["git", "-c", "user.name=BCF Qualification", "-c", "user.email=bcf-qualification@invalid.local", "commit", "-m", message], cwd=root)
    elif result.returncode != 0:
        raise ReleaseQualificationError("cannot inspect qualification candidate changes")


def _isolated_project_python(
    source_root: Path, source_python: Path, destination_root: Path
) -> Path:
    """Copy a repository-owned environment and rewrite only its own editable path."""

    executable = source_python.resolve()
    try:
        relative = source_python.absolute().relative_to(source_root.resolve())
    except ValueError:
        probe = subprocess.run(
            [str(executable), "-c", "import json,sys; print(json.dumps(sys.path))"],
            capture_output=True, text=True, check=False,
        )
        if probe.returncode or str(source_root.resolve()) in probe.stdout:
            raise ReleaseQualificationError(
                "external adopter interpreter exposes the maintained checkout"
            )
        return executable
    if len(relative.parts) < 3 or relative.parts[-2:] != ("bin", "python"):
        raise ReleaseQualificationError(
            "repository-owned adopter interpreter must be ENV/bin/python"
        )
    environment_root = source_root / relative.parts[0]
    projected_root = destination_root / ".bcf-qualification-venv"
    shutil.copytree(environment_root, projected_root, symlinks=True)
    projected_python = projected_root / "bin/python"
    source_text = str(source_root.resolve())
    destination_text = str(destination_root.resolve())
    for path in projected_root.rglob("*.pth"):
        if path.is_symlink() or not path.is_file():
            raise ReleaseQualificationError("adopter environment contains unsafe path hooks")
        text = path.read_text(encoding="utf-8")
        if source_text in text:
            path.write_text(text.replace(source_text, destination_text), encoding="utf-8")
        if re.search(r"/(?:docker|home)/", path.read_text(encoding="utf-8")):
            raise ReleaseQualificationError(
                "adopter environment retains an unrelated workspace path hook"
            )
    probe = subprocess.run(
        [str(projected_python), "-c", "import json,sys; print(json.dumps(sys.path))"],
        cwd=destination_root, capture_output=True, text=True, check=False,
    )
    if probe.returncode or source_text in probe.stdout:
        raise ReleaseQualificationError(
            "isolated adopter interpreter still exposes the maintained checkout"
        )
    return projected_python


def qualify_release(
    repo_root: Path,
    *,
    release_assets: Path,
    adopter_roots: Sequence[Path],
    adopter_pythons: Mapping[str, Path],
    output: Path,
) -> dict[str, Any]:
    """Qualify exact assets without mutating any maintained adopter checkout."""

    contract = load_contract(repo_root.resolve())
    version, assets = _release_assets(release_assets.resolve())
    supplied: dict[str, tuple[Path, str, str]] = {}
    for root in adopter_roots:
        resolved = root.resolve()
        repository, commit, tree = _source_identity(resolved)
        if repository in supplied:
            raise ReleaseQualificationError(f"duplicate adopter checkout: {repository}")
        supplied[repository] = (resolved, commit, tree)
    required = {item["repository"]: item for item in contract["required_adopters"]}
    if set(supplied) != set(required) or set(adopter_pythons) != set(required):
        raise ReleaseQualificationError("supplied adopter roots/interpreters do not exactly match the contract")
    release_repository, release_commit, release_tree = _source_identity(
        repo_root.resolve()
    )
    environment = dict(os.environ)
    if not environment.get("GITHUB_TOKEN"):
        raise ReleaseQualificationError("GITHUB_TOKEN is required for release custody")
    reports: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="bcf-release-qualification-") as temporary:
        temporary_root = Path(temporary)
        controller = temporary_root / "controller"
        wheel = release_assets.resolve() / next(name for name in assets if name.endswith(".whl"))
        bcf, environment = _exact_release_runtime(
            wheel,
            controller,
            version=version,
            cwd=repo_root,
            environment=environment,
        )
        for repository in sorted(required):
            adopter_source, adopter_commit, adopter_tree = supplied[repository]
            adopter_python = adopter_pythons[repository]
            if not adopter_python.is_file() or not os.access(adopter_python, os.X_OK):
                raise ReleaseQualificationError(f"adopter interpreter is unavailable: {repository}")
            destination = temporary_root / required[repository]["id"]
            _run(["git", "clone", "--local", "--no-hardlinks", str(adopter_source), str(destination)], cwd=temporary_root)
            remote = _run(["git", "remote", "get-url", "origin"], cwd=adopter_source)
            _run(["git", "remote", "set-url", "origin", remote], cwd=destination)
            _run(["git", "checkout", "-B", f"qualification/bcf-{version}", adopter_commit], cwd=destination)
            project_python = _isolated_project_python(
                adopter_source, adopter_python, destination
            )
            _run([*bcf, "install", "--target", str(destination), "--upgrade", "--candidate-qualification-source", str(repo_root.resolve()), "--require-strict-validation"], cwd=destination, env=environment)
            _commit(destination, f"test: install immutable BCF {version}")
            _run([*bcf, "reconcile", "--repo-root", str(destination), "--python", str(project_python), "--apply"], cwd=destination, env=environment)
            _commit(destination, f"test: reconcile BCF {version} qualification")
            result = _run(
                [
                    bcf[0],
                    "-P",
                    "-c",
                    _CANDIDATE_QUALIFICATION_TRAIN,
                    str(destination),
                    str(project_python),
                ],
                cwd=destination,
                env=environment,
            )
            try:
                report = json.loads(result)
            except json.JSONDecodeError as exc:
                raise ReleaseQualificationError(f"adopter qualification emitted invalid JSON: {repository}") from exc
            if report.get("status") != "prospectively_admissible_provider_proof_required":
                raise ReleaseQualificationError(f"adopter qualification did not close: {repository}")
            profile = yaml.safe_load((destination / "governance-profile.yml").read_text(encoding="utf-8"))
            selected_profile = (
                profile.get("profile", {}).get("selected")
                if isinstance(profile, dict) and isinstance(profile.get("profile"), dict)
                else None
            )
            if selected_profile != required[repository]["profile"]:
                raise ReleaseQualificationError(f"adopter profile differs from contract: {repository}")
            reports.append({
                "id": required[repository]["id"],
                "repository": repository,
                "profile": required[repository]["profile"],
                "source_commit": adopter_commit,
                "source_tree": adopter_tree,
                "candidate_commit": report["subject"]["commit_sha"],
                "candidate_tree": report["subject"]["tree_sha"],
                "evaluation": report["post_merge_evaluation"],
                "status": "pass",
            })
    receipt = {
        "schema_version": "1.0",
        "kind": "release_adopter_qualification",
        "authority": False,
        "subject": {
            "repository": release_repository,
            "commit_sha": release_commit,
            "tree_sha": release_tree,
        },
        "release": {"version": version, "assets": assets},
        "contract_sha256": _sha256(repo_root / "governance/release-qualification.yml"),
        "adopters": reports,
        "status": "pass",
        "publication_eligible_observation": True,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def validate_qualification_receipt(
    receipt: object,
    *,
    contract: dict[str, Any],
    contract_sha256: str,
    repository: str,
    commit_sha: str,
    tree_sha: str,
    version: str,
    assets: Mapping[str, str],
) -> dict[str, Any]:
    """Validate the exact non-authoritative observation required by publication."""

    if not isinstance(receipt, dict) or set(receipt) != {
        "schema_version", "kind", "authority", "subject", "release",
        "contract_sha256", "adopters", "status",
        "publication_eligible_observation",
    }:
        raise ReleaseQualificationError("release qualification receipt inventory is not exact")
    if (
        receipt.get("schema_version") != "1.0"
        or receipt.get("kind") != "release_adopter_qualification"
        or receipt.get("authority") is not False
        or receipt.get("status") != "pass"
        or receipt.get("publication_eligible_observation") is not True
    ):
        raise ReleaseQualificationError("release qualification did not pass as observation only")
    if receipt.get("subject") != {
        "repository": repository,
        "commit_sha": commit_sha,
        "tree_sha": tree_sha,
    }:
        raise ReleaseQualificationError("release qualification subject is not exact")
    if receipt.get("release") != {
        "version": version,
        "assets": dict(sorted(assets.items())),
    }:
        raise ReleaseQualificationError("release qualification assets are not exact")
    if receipt.get("contract_sha256") != contract_sha256:
        raise ReleaseQualificationError("release qualification contract is stale")
    required = {
        item["repository"]: (item["id"], item["profile"])
        for item in contract["required_adopters"]
    }
    adopters = receipt.get("adopters")
    if not isinstance(adopters, list) or len(adopters) != len(required):
        raise ReleaseQualificationError("release qualification adopter inventory is incomplete")
    observed: dict[str, tuple[str, str]] = {}
    exact_keys = {
        "id", "repository", "profile", "source_commit", "source_tree",
        "candidate_commit", "candidate_tree", "evaluation", "status",
    }
    for adopter in adopters:
        if not isinstance(adopter, dict) or set(adopter) != exact_keys:
            raise ReleaseQualificationError("release qualification adopter identity is invalid")
        repo = adopter.get("repository")
        if not isinstance(repo, str) or repo in observed or adopter.get("status") != "pass":
            raise ReleaseQualificationError("release qualification adopter result is invalid")
        identities = (
            adopter.get("source_commit"), adopter.get("source_tree"),
            adopter.get("candidate_commit"), adopter.get("candidate_tree"),
        )
        if any(not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{40}", value) is None for value in identities):
            raise ReleaseQualificationError("release qualification Git identity is malformed")
        if not isinstance(adopter.get("evaluation"), dict):
            raise ReleaseQualificationError("release qualification evaluation is absent")
        observed[repo] = (str(adopter.get("id")), str(adopter.get("profile")))
    if observed != required:
        raise ReleaseQualificationError("release qualification adopter contract differs")
    return receipt

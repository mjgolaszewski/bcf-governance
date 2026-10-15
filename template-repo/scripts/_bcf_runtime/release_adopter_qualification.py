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
from .ci_github_identity import GitHubControllerError, resolve_main
from .local_execution_admission import ensure_local_project_python
from .release_adopter_sources import (
    AdopterSourceError,
    AdopterSourceIdentity,
    materialize_provider_source,
    require_adopter_profile,
    resolve_adopter_sources,
    source_inventory_sha256,
)
from .release_asset_inventory import (
    checksum_declared_assets,
    exact_assets,
    release_asset_paths,
    release_asset_version,
)


class ReleaseQualificationError(ValueError):
    """Exact release assets or an adopter qualification are incomplete."""


_QUALIFICATION_BASE_REMOTE = "bcf-qualification-base"


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


def _release_assets(
    root: Path,
) -> tuple[str, dict[str, str], dict[str, str]]:
    try:
        paths = release_asset_paths(root)
        version = release_asset_version(paths).value
        return version, exact_assets(paths), checksum_declared_assets(paths)
    except GitHubControllerError as exc:
        raise ReleaseQualificationError(str(exc)) from exc


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

    from .local_pr import run_prospective_train
    from .local_pr_context import LocalValidationLane
    from .prospective_candidate_identity import canonical_prospective_inputs

    canonical = canonical_prospective_inputs(
        repo_root, remote=_QUALIFICATION_BASE_REMOTE
    )
    return run_prospective_train(
        repo_root,
        semantic_intent=str(canonical["semantic_intent"]),
        evaluation_target=canonical["evaluation_target"],
        subject_commit=str(canonical["subject_commit"]),
        subject_tree=str(canonical["subject_tree"]),
        remote=_QUALIFICATION_BASE_REMOTE,
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
        environment = dict(os.environ)
        environment.update(
            {
                "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
                "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
            }
        )
        _run(
            [
                "git", "-c", "user.name=BCF Qualification",
                "-c", "user.email=bcf-qualification@invalid.local",
                "commit", "-m", message,
            ],
            cwd=root,
            env=environment,
        )
    elif result.returncode != 0:
        raise ReleaseQualificationError("cannot inspect qualification candidate changes")


def _project_qualification_base_remote(
    candidate_root: Path, base_root: Path, base_commit: str
) -> None:
    """Materialize one immutable local remote for the captured adopter base."""

    _run(["git", "init", "--bare", str(base_root)], cwd=base_root.parent)
    _run(
        ["git", "-C", str(base_root), "symbolic-ref", "HEAD", "refs/heads/main"],
        cwd=base_root.parent,
    )
    _run(
        ["git", "push", str(base_root), f"{base_commit}:refs/heads/main"],
        cwd=candidate_root,
    )
    _run(
        ["git", "remote", "add", _QUALIFICATION_BASE_REMOTE, str(base_root)],
        cwd=candidate_root,
    )


def _isolated_project_python(
    source_root: Path,
    source_python: Path,
    destination_root: Path,
    projected_root: Path,
) -> Path:
    """Copy a repository-owned environment and rewrite only its own editable path."""

    executable = source_python.resolve()
    try:
        relative = source_python.absolute().relative_to(source_root.resolve())
    except ValueError:
        probe = subprocess.run(
            [str(source_python.absolute()), "-c", "import json,sys; print(json.dumps(sys.path))"],
            capture_output=True, text=True, check=False,
        )
        if probe.returncode or str(source_root.resolve()) in probe.stdout:
            raise ReleaseQualificationError(
                "external adopter interpreter exposes the maintained checkout"
            )
        return source_python.absolute()
    if len(relative.parts) < 3 or relative.parts[-2:] != ("bin", "python"):
        raise ReleaseQualificationError(
            "repository-owned adopter interpreter must be ENV/bin/python"
        )
    environment_root = source_python.absolute().parent.parent
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
    provider_api: GitHubAPI,
    repository: str,
    release_assets: Path,
    release_build_manifest: Path,
    adopter_roots: Sequence[Path],
    adopter_pythons: Mapping[str, Path],
    producer: Mapping[str, Any],
    output: Path,
) -> dict[str, Any]:
    """Qualify provider-resolved sources without mutating maintained checkouts."""

    contract = load_contract(repo_root.resolve())
    version, build_assets, assets = _release_assets(release_assets.resolve())
    release_main = resolve_main(provider_api, repository)
    try:
        build = json.loads(release_build_manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseQualificationError(
            "release build manifest is unreadable"
        ) from exc
    if (
        not isinstance(build, dict)
        or build.get("subject")
        != {
            "commit_sha": release_main.checkout_sha,
            "tree_sha": release_main.tree_sha,
        }
        or build.get("assets") != build_assets
    ):
        raise ReleaseQualificationError(
            "release assets are not bound to the current exact build manifest"
        )
    release_repository, release_commit, release_tree = _source_identity(
        repo_root.resolve()
    )
    if release_repository != repository or (
        release_commit != release_main.checkout_sha
        or release_tree != release_main.tree_sha
    ):
        raise ReleaseQualificationError(
            "release qualification source is not current provider exact main"
        )
    try:
        sources = resolve_adopter_sources(provider_api, contract)
    except AdopterSourceError as exc:
        raise ReleaseQualificationError(str(exc)) from exc
    source_by_repository = {source.repository: source for source in sources}
    supplied: dict[str, Path] = {}
    for root in adopter_roots:
        resolved = root.resolve()
        cache_repository, _commit_sha, _tree_sha = _source_identity(resolved)
        if cache_repository in supplied:
            raise ReleaseQualificationError(
                f"duplicate adopter checkout cache: {cache_repository}"
            )
        supplied[cache_repository] = resolved
    required = set(source_by_repository)
    if set(supplied) - required or set(adopter_pythons) - required:
        raise ReleaseQualificationError(
            "supplied adopter caches/interpreters are outside the contract"
        )
    if set(adopter_pythons) - set(supplied):
        raise ReleaseQualificationError(
            "adopter interpreter requires its matching checkout cache"
        )
    expected_producer_keys = {
        "repository_id", "workflow", "job", "run_id", "run_attempt"
    }
    if set(producer) != expected_producer_keys or (
        str(producer.get("repository_id")) != release_main.repository_id
        or str(producer.get("run_id", "")).isdigit() is False
        or str(producer.get("run_attempt", "")).isdigit() is False
        or not all(
            isinstance(producer.get(key), str) and producer.get(key)
            for key in ("workflow", "job")
        )
    ):
        raise ReleaseQualificationError(
            "qualification producer identity is not exact"
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
        for source in sources:
            repository_name = source.repository
            destination = temporary_root / source.id
            try:
                materialize_provider_source(source, destination)
                require_adopter_profile(destination, source)
            except AdopterSourceError as exc:
                raise ReleaseQualificationError(str(exc)) from exc
            _run(
                [
                    "git", "checkout", "-B", f"qualification/bcf-{version}",
                    source.commit_sha,
                ],
                cwd=destination,
            )
            _project_qualification_base_remote(
                destination,
                temporary_root / f"{source.id}-base.git",
                source.commit_sha,
            )
            if repository_name in adopter_pythons:
                adopter_python = adopter_pythons[repository_name]
                if not adopter_python.is_file() or not os.access(adopter_python, os.X_OK):
                    raise ReleaseQualificationError(
                        f"adopter interpreter is unavailable: {repository_name}"
                    )
                project_python = _isolated_project_python(
                    supplied[repository_name],
                    adopter_python,
                    destination,
                    temporary_root / f"{source.id}-environment",
                )
                project_python = ensure_local_project_python(
                    destination,
                    Path(sys.executable),
                    requested=project_python,
                )
            else:
                project_python = ensure_local_project_python(
                    destination, Path(sys.executable)
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
                raise ReleaseQualificationError(f"adopter qualification emitted invalid JSON: {repository_name}") from exc
            if report.get("status") != "prospectively_admissible_provider_proof_required":
                raise ReleaseQualificationError(f"adopter qualification did not close: {repository_name}")
            reports.append({
                "id": source.id,
                "repository": repository_name,
                "repository_id": source.repository_id,
                "profile": source.profile,
                "source_branch": source.default_branch,
                "source_commit": source.commit_sha,
                "source_tree": source.tree_sha,
                "candidate_commit": report["subject"]["commit_sha"],
                "candidate_tree": report["subject"]["tree_sha"],
                "evaluation": report["post_merge_evaluation"],
                "status": "pass",
            })
    receipt = {
        "schema_version": "1.1",
        "kind": "release_adopter_qualification",
        "authority": False,
        "subject": {
            "repository": release_repository,
            "commit_sha": release_commit,
            "tree_sha": release_tree,
        },
        "release": {"version": version, "assets": assets},
        "contract_sha256": _sha256(repo_root / "governance/release-qualification.yml"),
        "source_inventory_sha256": source_inventory_sha256(sources),
        "producer": dict(producer),
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
    producer: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the exact non-authoritative observation required by publication."""

    if not isinstance(receipt, dict) or set(receipt) != {
        "schema_version", "kind", "authority", "subject", "release",
        "contract_sha256", "source_inventory_sha256", "producer", "adopters", "status",
        "publication_eligible_observation",
    }:
        raise ReleaseQualificationError("release qualification receipt inventory is not exact")
    if (
        receipt.get("schema_version") != "1.1"
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
    if receipt.get("producer") != dict(producer):
        raise ReleaseQualificationError("release qualification producer is not exact")
    required_order = [item["repository"] for item in contract["required_adopters"]]
    required = {
        item["repository"]: (item["id"], item["profile"])
        for item in contract["required_adopters"]
    }
    adopters = receipt.get("adopters")
    if not isinstance(adopters, list) or len(adopters) != len(required):
        raise ReleaseQualificationError("release qualification adopter inventory is incomplete")
    observed: dict[str, tuple[str, str]] = {}
    exact_keys = {
        "id", "repository", "repository_id", "profile", "source_branch",
        "source_commit", "source_tree",
        "candidate_commit", "candidate_tree", "evaluation", "status",
    }
    source_identities: list[AdopterSourceIdentity] = []
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
        repository_id = adopter.get("repository_id")
        branch = adopter.get("source_branch")
        if (
            not isinstance(repository_id, str)
            or not repository_id.isdigit()
            or int(repository_id) < 1
            or not isinstance(branch, str)
            or re.fullmatch(r"[A-Za-z0-9._/-]+", branch) is None
        ):
            raise ReleaseQualificationError(
                "release qualification provider identity is malformed"
            )
        if not isinstance(adopter.get("evaluation"), dict):
            raise ReleaseQualificationError("release qualification evaluation is absent")
        observed[repo] = (str(adopter.get("id")), str(adopter.get("profile")))
        source_identities.append(
            AdopterSourceIdentity(
                id=str(adopter["id"]),
                repository=repo,
                repository_id=repository_id,
                profile=str(adopter["profile"]),
                default_branch=branch,
                commit_sha=str(adopter["source_commit"]),
                tree_sha=str(adopter["source_tree"]),
            )
        )
    if observed != required:
        raise ReleaseQualificationError("release qualification adopter contract differs")
    if [item.get("repository") for item in adopters] != required_order:
        raise ReleaseQualificationError("release qualification adopter order differs")
    if receipt.get("source_inventory_sha256") != source_inventory_sha256(
        source_identities
    ):
        raise ReleaseQualificationError(
            "release qualification source inventory digest differs"
        )
    return receipt

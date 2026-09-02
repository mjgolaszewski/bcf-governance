"""Run repeatable offline adoption and upgrade soaks without mutating source repos."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from bcf_governance.tooling.ci_graph_diagnostics import diagnose_ci_graph
from bcf_governance.tooling.ci_graph_import import inventory_github_workflows
from bcf_governance.tooling.ci_graph_render import check_ci_graph
from bcf_governance.tooling.install_governance_pack import (
    UPGRADE_PROJECT_OWNED_PATHS,
    UPGRADE_REFRESH_PATHS,
)
from bcf_governance.tooling.migrate_contracts import plan_contract_migration


PROJECT_OWNED = UPGRADE_PROJECT_OWNED_PATHS


def _run(*argv: str, cwd: Path | None = None) -> str:
    return subprocess.run(
        argv, cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def _git(repo: Path, *args: str) -> str:
    return _run("git", *args, cwd=repo)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _owned_inventory(repo: Path) -> dict[str, str]:
    inventory: dict[str, str] = {}
    for relative in PROJECT_OWNED:
        root = repo / relative
        if root.is_file() and not root.is_symlink():
            inventory[relative] = _sha256(root)
        elif root.is_dir() and not root.is_symlink():
            inventory.update(
                {
                    path.relative_to(repo).as_posix(): _sha256(path)
                    for path in sorted(root.rglob("*"))
                    if path.is_file() and not path.is_symlink()
                }
            )
    return inventory


def _clone(source: str, commit: str, target: Path) -> None:
    _run("git", "clone", "--quiet", "--no-checkout", source, str(target))
    _git(target, "checkout", "--quiet", "--detach", commit)


def _upgrade(python: Path, installer: Path, repo: Path) -> None:
    _run(
        str(python),
        str(installer),
        "--target",
        str(repo),
        "--upgrade",
        "--skip-validation",
    )


def _changed_paths(repo: Path) -> tuple[str, ...]:
    result = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    paths: list[str] = []
    for entry in result.stdout.split(b"\0"):
        if not entry:
            continue
        if len(entry) < 4 or entry[2:3] != b" ":
            raise RuntimeError("unexpected Git porcelain status entry")
        if b"R" in entry[:2] or b"C" in entry[:2]:
            raise RuntimeError("adoption soak does not admit renamed or copied paths")
        try:
            paths.append(entry[3:].decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise RuntimeError("adoption soak path is not UTF-8") from exc
    return tuple(paths)


def _upgrade_change_allowed(path: str) -> bool:
    allowed = (*UPGRADE_REFRESH_PATHS, "schemas", "scripts/_bcf_runtime")
    return any(path == root or path.startswith(root.rstrip("/") + "/") for root in allowed)


def _changed_inventory(repo: Path) -> dict[str, str]:
    inventory: dict[str, str] = {}
    for relative in _changed_paths(repo):
        path = repo / relative
        inventory[relative] = _sha256(path) if path.is_file() and not path.is_symlink() else "absent"
    return inventory


def _reset_temporary_clone(repo: Path) -> None:
    resolved = repo.resolve()
    if not resolved.as_posix().startswith("/tmp/bcf-adoption-soak-"):
        raise RuntimeError("refusing to reset a non-soak repository")
    _git(repo, "restore", "--source=HEAD", "--staged", "--worktree", ".")
    _git(repo, "clean", "-fd")
    if _changed_paths(repo):
        raise RuntimeError("temporary clone rollback was incomplete")


def run_soak(
    *,
    bcf_source: Path,
    identity_source: str,
    identity_commit: str,
    python: Path,
    cycles: int,
) -> dict[str, object]:
    """Exercise current and legacy-custom adoption paths in isolated clones."""

    if cycles != 5:
        raise ValueError("the release-candidate soak requires exactly five cycles")
    bcf_commit = _git(bcf_source, "rev-parse", "HEAD")
    if _changed_paths(bcf_source):
        raise RuntimeError("BCF source must be clean and committed before soak")
    installer = bcf_source / "scripts/install_governance_pack.py"
    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="bcf-adoption-soak-") as temporary:
        root = Path(temporary)
        for cycle in range(1, cycles + 1):
            bcf = root / f"bcf-{cycle}"
            identity = root / f"identity-{cycle}"
            _clone(str(bcf_source), bcf_commit, bcf)
            _clone(identity_source, identity_commit, identity)

            bcf_owned = _owned_inventory(bcf)
            if check_ci_graph(bcf).status != "clean":
                raise RuntimeError(f"BCF graph drift in soak cycle {cycle}")
            _upgrade(python, installer, bcf)
            if _owned_inventory(bcf) != bcf_owned:
                raise RuntimeError(f"BCF project-owned bytes changed in soak cycle {cycle}")
            bcf_changed = _changed_paths(bcf)
            unexpected = [path for path in bcf_changed if not _upgrade_change_allowed(path)]
            if unexpected:
                raise RuntimeError(
                    f"BCF upgrade touched unexpected paths in cycle {cycle}: {unexpected}"
                )
            bcf_refresh = _changed_inventory(bcf)
            _upgrade(python, installer, bcf)
            if _changed_inventory(bcf) != bcf_refresh:
                raise RuntimeError(f"BCF pack refresh was not idempotent in soak cycle {cycle}")
            if check_ci_graph(bcf).status != "clean":
                raise RuntimeError(f"BCF graph changed after upgrade in soak cycle {cycle}")
            bcf_migration, _ = plan_contract_migration(bcf)
            if bcf_migration.status != "current":
                raise RuntimeError(f"BCF contract was not current in soak cycle {cycle}")
            _reset_temporary_clone(bcf)

            identity_owned = _owned_inventory(identity)
            workflow_inventory = inventory_github_workflows(identity)
            _upgrade(python, installer, identity)
            if _owned_inventory(identity) != identity_owned:
                raise RuntimeError(
                    f"Identity project-owned bytes changed in soak cycle {cycle}"
                )
            changed = _changed_paths(identity)
            unexpected = [path for path in changed if not _upgrade_change_allowed(path)]
            if unexpected:
                raise RuntimeError(
                    f"Identity upgrade touched unexpected paths in cycle {cycle}: {unexpected}"
                )
            identity_refresh = _changed_inventory(identity)
            _upgrade(python, installer, identity)
            if _changed_inventory(identity) != identity_refresh:
                raise RuntimeError(
                    f"Identity pack refresh was not idempotent in soak cycle {cycle}"
                )
            identity_migration, _ = plan_contract_migration(identity)
            diagnostics = diagnose_ci_graph(identity)
            if identity_migration.status != "blocked" or diagnostics["status"] != "fail":
                raise RuntimeError(
                    f"Identity legacy adoption did not fail closed in soak cycle {cycle}"
                )
            _reset_temporary_clone(identity)
            results.append(
                {
                    "cycle": cycle,
                    "bcf_status": "project_owned_preserved_pack_refresh_idempotent",
                    "bcf_refreshed_path_count": len(bcf_changed),
                    "identity_status": "project_owned_preserved_pack_refresh_idempotent_fail_closed",
                    "identity_refreshed_path_count": len(changed),
                    "identity_workflow_count": len(workflow_inventory["workflows"]),
                    "identity_migration_blockers": list(identity_migration.blockers),
                    "identity_graph_diagnostic": diagnostics["diagnostics"][0],
                }
            )
    return {
        "status": "pass",
        "cycles": results,
        "bcf_commit": bcf_commit,
        "identity_commit": identity_commit,
        "remote_actions_runs": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bcf-source", type=Path, default=REPO_ROOT)
    parser.add_argument("--identity-source", required=True)
    parser.add_argument("--identity-commit", required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--cycles", type=int, default=5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_soak(
        bcf_source=args.bcf_source.resolve(),
        identity_source=args.identity_source,
        identity_commit=args.identity_commit,
        python=args.python.resolve(),
        cycles=args.cycles,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()

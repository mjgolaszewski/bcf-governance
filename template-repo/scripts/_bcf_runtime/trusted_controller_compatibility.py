"""Prove that the pinned trusted controller covers the current runtime source."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import subprocess
from typing import Iterable


TRUSTED_ENTRYPOINT = PurePosixPath(
    "bcf_governance/tooling/ci_github_commands.py"
)
DIRECT_RUNTIME_FILES = (
    PurePosixPath("bcf_governance/__init__.py"),
    PurePosixPath("bcf_governance/_version.py"),
    PurePosixPath("bcf_governance/cli.py"),
)
PACKAGED_SCHEMA_ROOT = PurePosixPath(
    "bcf_governance/pack/template-repo/schemas"
)


class TrustedControllerCompatibilityError(ValueError):
    """Raised when trusted jobs need runtime bytes newer than their target."""


@dataclass(frozen=True)
class TrustedControllerCompatibility:
    target_commit: str
    source_files: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "target_commit": self.target_commit,
            "source_file_count": len(self.source_files),
        }


def _git(repo_root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise TrustedControllerCompatibilityError(
            result.stderr.strip() or f"git {' '.join(arguments)} failed"
        )
    return result.stdout.strip()


def _module_file(repo_root: Path, module: str) -> PurePosixPath | None:
    if module != "bcf_governance" and not module.startswith("bcf_governance."):
        return None
    relative = PurePosixPath(*module.split("."))
    file_candidate = PurePosixPath(str(relative) + ".py")
    package_candidate = relative / "__init__.py"
    if (repo_root / file_candidate).is_file():
        return file_candidate
    if (repo_root / package_candidate).is_file():
        return package_candidate
    return None


def _imported_modules(path: PurePosixPath, tree: ast.Module) -> Iterable[str]:
    package = list(path.with_suffix("").parts[:-1])
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
            continue
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:
            keep = len(package) - (node.level - 1)
            if keep < 1:
                continue
            base = package[:keep]
            if node.module:
                base.extend(node.module.split("."))
                yield ".".join(base)
            else:
                for alias in node.names:
                    yield ".".join([*base, alias.name])
        elif node.module:
            yield node.module


def trusted_runtime_source_files(repo_root: Path) -> tuple[str, ...]:
    """Derive the trusted CLI's Python import closure and packaged schemas."""

    root = repo_root.resolve()
    pending = [TRUSTED_ENTRYPOINT]
    observed = set(DIRECT_RUNTIME_FILES)
    while pending:
        relative = pending.pop()
        if relative in observed:
            continue
        source = root / relative
        if not source.is_file() or source.is_symlink():
            raise TrustedControllerCompatibilityError(
                f"trusted controller source is absent or unsafe: {relative}"
            )
        observed.add(relative)
        try:
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(relative))
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            raise TrustedControllerCompatibilityError(
                f"trusted controller source is invalid: {relative}"
            ) from exc
        for module in _imported_modules(relative, tree):
            imported = _module_file(root, module)
            if imported is not None and imported not in observed:
                pending.append(imported)
    schema_root = root / PACKAGED_SCHEMA_ROOT
    if not schema_root.is_dir() or schema_root.is_symlink():
        raise TrustedControllerCompatibilityError(
            "trusted controller packaged schema root is absent or unsafe"
        )
    observed.update(
        path.relative_to(root)
        for path in schema_root.glob("*.json")
        if path.is_file() and not path.is_symlink()
    )
    return tuple(sorted(path.as_posix() for path in observed))


def verify_trusted_controller_compatibility(
    repo_root: Path, *, target_commit: str
) -> TrustedControllerCompatibility:
    """Reject a target whose trusted runtime closure differs from committed HEAD."""

    root = repo_root.resolve()
    _git(root, "cat-file", "-e", f"{target_commit}^{{commit}}")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", target_commit, "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if ancestor.returncode != 0:
        raise TrustedControllerCompatibilityError(
            "trusted controller target is not an ancestor of committed HEAD"
        )
    paths = trusted_runtime_source_files(root)
    changed = _git(root, "diff", "--name-only", target_commit, "HEAD", "--", *paths)
    if changed:
        raise TrustedControllerCompatibilityError(
            "trusted controller target is stale for runtime files: "
            + ", ".join(changed.splitlines())
        )
    return TrustedControllerCompatibility(target_commit, paths)

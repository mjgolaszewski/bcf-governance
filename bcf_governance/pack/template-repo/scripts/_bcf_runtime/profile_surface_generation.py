"""Deterministic Makefile and GitHub workflow rendering for profile contracts."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from .ci_github_actions import action_pin


def write_makefile(repo_root: Path, contract: dict[str, Any]) -> None:
    """Render the profile-owned Makefile fragment."""
    if contract.get("profile_contract_version") == "2.0":
        from .profile_v2_surfaces import render_v2_makefile

        (repo_root / "Makefile.fragment").write_text(
            render_v2_makefile(contract), encoding="utf-8"
        )
        return
    gates = contract["gates"]
    targets = " ".join(gates)
    lines = [
        "SHELL := /bin/bash",
        "PYTHON ?= python3",
        "BCF_EVIDENCE_DIR ?= .artifacts/bcf",
        "",
        f".PHONY: governance-truthfulness release-check {targets}",
        "",
        "governance-truthfulness:",
        "\t$(PYTHON) scripts/governance_truth.py --repo-root . --evidence-dir $(BCF_EVIDENCE_DIR)",
        "",
    ]
    for target, gate in gates.items():
        argv = shlex.join(gate["invocation"]["argv"])
        env = " ".join(
            f"{key}={shlex.quote(value)}"
            for key, value in gate["invocation"]["env"].items()
        )
        cwd = shlex.quote(gate["invocation"]["cwd"])
        command = f"cd {cwd} && {env + ' ' if env else ''}{argv}"
        lines.extend([f"{target}:", f"\t@{command}", ""])
    lines.extend(
        [
            "release-check:",
            "\t@mkdir -p $(BCF_EVIDENCE_DIR)",
            f"\t@for gate in {targets}; do \\",
            "\t\t$(PYTHON) scripts/governance_evidence.py --repo-root . run --gate $$gate --output $(BCF_EVIDENCE_DIR)/$$gate || exit $$?; \\",
            "\tdone",
            "\t$(MAKE) governance-truthfulness",
            "",
        ]
    )
    (repo_root / "Makefile.fragment").write_text("\n".join(lines), encoding="utf-8")


def write_workflow(repo_root: Path, contract: dict[str, Any]) -> None:
    """Render the profile-owned GitHub workflow."""
    gates = list(contract["gates"])
    profile = yaml.safe_load(
        (repo_root / "governance-profile.yml").read_text(encoding="utf-8")
    )
    labels = profile.get("ci_profile", {}).get("runner_labels", ["ubuntu-latest"])
    if contract.get("profile_contract_version") == "2.0":
        from .profile_v2_surfaces import render_v2_workflow

        path = repo_root / ".github/workflows/governance.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_v2_workflow(contract, labels), encoding="utf-8")
        return
    label_yaml = yaml.safe_dump(labels, default_flow_style=True).strip()
    matrix = "\n".join(f"          - {target}" for target in gates)
    text = f'''name: governance

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

env:
  BCF_ENFORCE_PR_CHANGELOG: ${{{{ github.event_name == 'pull_request' }}}}
  BCF_PR_BASE_SHA: ${{{{ github.event.pull_request.base.sha }}}}

jobs:
  evidence:
    runs-on: {label_yaml}
    strategy:
      fail-fast: false
      matrix:
        gate:
{matrix}
    steps:
      - uses: {action_pin("checkout")}
        with: {{fetch-depth: 0}}
      - uses: {action_pin("setup-python")}
        with: {{python-version: "3.12"}}
      - run: python3 -m pip install -r requirements-governance.txt
      - name: Capture ${{{{ matrix.gate }}}} evidence
        run: python3 scripts/governance_evidence.py --repo-root . run --gate "${{{{ matrix.gate }}}}" --output ".artifacts/bcf/${{{{ matrix.gate }}}}"
      - if: always()
        uses: {action_pin("upload-artifact")}
        with:
          name: bcf-evidence-${{{{ matrix.gate }}}}
          path: .artifacts/bcf/${{{{ matrix.gate }}}}
          if-no-files-found: error

  governance-truthfulness:
    if: always()
    needs: [evidence]
    runs-on: {label_yaml}
    steps:
      - uses: {action_pin("checkout")}
        with: {{fetch-depth: 0}}
      - uses: {action_pin("setup-python")}
        with: {{python-version: "3.12"}}
      - run: python3 -m pip install -r requirements-governance.txt
      - uses: {action_pin("download-artifact")}
        with: {{pattern: bcf-evidence-*, path: .artifacts/bcf, merge-multiple: true}}
      - run: python3 scripts/governance_truth.py --repo-root . --evidence-dir .artifacts/bcf --format json --durable-ref "github-actions://${{{{ github.repository }}}}/runs/${{{{ github.run_id }}}}/bcf-governance-truth" --output .artifacts/bcf/truth-report.json
      - if: always()
        uses: {action_pin("upload-artifact")}
        with: {{name: bcf-governance-truth, path: .artifacts/bcf/truth-report.json, if-no-files-found: error}}
'''
    path = repo_root / ".github/workflows/governance.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")

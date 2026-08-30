"""Generated profile-v2 Make and GitHub evidence-session surfaces."""

from __future__ import annotations

import shlex
from typing import Any

import yaml


def render_v2_makefile(contract: dict[str, Any]) -> str:
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
        lines.extend(
            [f"{target}:", f"\t@cd {cwd} && {env + ' ' if env else ''}{argv}", ""]
        )
    lines.extend(
        [
            "release-check:",
            "\t@mkdir -p $(BCF_EVIDENCE_DIR)",
            "\t@session=\"$$($(PYTHON) scripts/preflight_governance.py --repo-root . --mode release --python $(PYTHON) --artifact-root $(BCF_EVIDENCE_DIR) --expected-producer local --local-producer-id local --format text | tail -n 1)\"; \\",
            "\tsession_dir=\"$${session%/evidence-session.json}\"; \\",
            f"\tfor gate in {targets}; do \\",
            "\t\t$(PYTHON) scripts/governance_evidence.py --repo-root . run --gate $$gate --output \"$$session_dir/$$gate\" --python $(PYTHON) --session-manifest \"$$session\" || exit $$?; \\",
            "\tdone; \\",
            "\t$(PYTHON) scripts/governance_truth.py --repo-root . --evidence-dir $(BCF_EVIDENCE_DIR)",
            "",
        ]
    )
    return "\n".join(lines)


def render_v2_workflow(contract: dict[str, Any], labels: list[str]) -> str:
    gates = list(contract["gates"])
    label_yaml = yaml.safe_dump(labels, default_flow_style=True).strip()
    matrix = "\n".join(f"          - {target}" for target in gates)
    return f'''name: governance

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

env:
  BCF_ENFORCE_PR_CHANGELOG: ${{{{ github.event_name == 'pull_request' }}}}
  BCF_PR_BASE_SHA: ${{{{ github.event.pull_request.base.sha }}}}
  BCF_PREFLIGHT_MODE: ${{{{ github.event_name == 'pull_request' && 'pr' || 'release' }}}}

jobs:
  preflight:
    runs-on: {label_yaml}
    outputs:
      session_manifest: ${{{{ steps.seed.outputs.session_manifest }}}}
    steps:
      - uses: actions/checkout@v4
        with: {{fetch-depth: 0, persist-credentials: false}}
      - uses: actions/setup-python@v5
        with: {{python-version: "3.12"}}
      - run: python3 -m pip install -r requirements-governance.txt
      - id: seed
        name: Validate cheap front door and seed immutable session
        shell: bash
        run: |
          set -euo pipefail
          manifest="$(python3 scripts/preflight_governance.py --repo-root . --mode "$BCF_PREFLIGHT_MODE" --python python3 --artifact-root .artifacts/bcf --expected-producer evidence --format text | tail -n 1)"
          printf 'session_manifest=%s\\n' "$manifest" >> "$GITHUB_OUTPUT"
      - uses: actions/upload-artifact@v4
        with:
          name: bcf-session-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}
          path: .artifacts/bcf/sessions
          if-no-files-found: error

  evidence:
    needs: [preflight]
    runs-on: {label_yaml}
    strategy:
      fail-fast: false
      matrix:
        gate:
{matrix}
    steps:
      - uses: actions/checkout@v4
        with: {{fetch-depth: 0, persist-credentials: false}}
      - uses: actions/setup-python@v5
        with: {{python-version: "3.12"}}
      - run: python3 -m pip install -r requirements-governance.txt
      - uses: actions/download-artifact@v4
        with:
          name: bcf-session-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}
          path: .artifacts/bcf/sessions
      - name: Capture ${{{{ matrix.gate }}}} evidence once
        shell: bash
        run: |
          set -euo pipefail
          session="${{{{ needs.preflight.outputs.session_manifest }}}}"
          session_dir="${{session%/evidence-session.json}}"
          chmod 700 .artifacts/bcf/sessions "$session_dir"
          chmod 400 "$session"
          python3 scripts/governance_evidence.py --repo-root . run --gate "${{{{ matrix.gate }}}}" --output "$session_dir/${{{{ matrix.gate }}}}" --python python3 --session-manifest "$session"
      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: bcf-evidence-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}-${{{{ matrix.gate }}}}
          path: .artifacts/bcf/sessions
          if-no-files-found: error

  governance-truthfulness:
    if: always()
    needs: [preflight, evidence]
    runs-on: {label_yaml}
    steps:
      - uses: actions/checkout@v4
        with: {{fetch-depth: 0, persist-credentials: false}}
      - uses: actions/setup-python@v5
        with: {{python-version: "3.12"}}
      - run: python3 -m pip install -r requirements-governance.txt
      - uses: actions/download-artifact@v4
        with:
          name: bcf-session-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}
          path: .artifacts/bcf/sessions
      - uses: actions/download-artifact@v4
        with:
          pattern: bcf-evidence-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}-*
          path: .artifacts/bcf/fan-in
      - name: Restore private session modes after artifact transport
        shell: bash
        run: |
          set -euo pipefail
          find .artifacts/bcf/fan-in -type f -name evidence-session.json -execdir chmod 700 . \\; -exec chmod 400 {{}} +
      - run: python3 scripts/governance_truth.py --repo-root . --evidence-dir .artifacts/bcf/fan-in --format json --durable-ref "github-actions://${{{{ github.repository }}}}/runs/${{{{ github.run_id }}}}/attempts/${{{{ github.run_attempt }}}}/bcf-governance-truth" --output .artifacts/bcf/truth-report.json
      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: bcf-governance-truth-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}
          path: .artifacts/bcf/truth-report.json
          if-no-files-found: error
'''

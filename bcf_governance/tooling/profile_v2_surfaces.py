"""Generated profile-v2 Make and GitHub evidence-session surfaces."""

from __future__ import annotations

import shlex
from typing import Any

import yaml

from .ci_github_actions import action_pin


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
        command = list(gate["invocation"]["argv"])
        argv = (
            "$(PYTHON)" + (" " + shlex.join(command[1:]) if len(command) > 1 else "")
            if command[0] in {"python", "python3"}
            else shlex.join(command)
        )
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
            "\t@preflight_output=\"$$($(PYTHON) scripts/preflight_governance.py --repo-root . --mode release --python $(PYTHON) --artifact-root $(BCF_EVIDENCE_DIR) --expected-producer local --local-producer-id local --format text)\" || exit $$?; \\",
            "\tprintf '%s\\n' \"$$preflight_output\"; \\",
            "\tsession=\"$$(printf '%s\\n' \"$$preflight_output\" | tail -n 1)\"; \\",
            "\ttest -n \"$$session\" && test -f \"$$session\" || { echo 'preflight did not produce an evidence session' >&2; exit 1; }; \\",
            "\tsession_dir=\"$${session%/evidence-session.json}\"; \\",
            f"\tfor gate in {targets}; do \\",
            "\t\t$(PYTHON) scripts/governance_evidence.py --repo-root . run --gate $$gate --output \"$$session_dir/$$gate\" --python $(PYTHON) --session-manifest \"$$session\" || exit $$?; \\",
            "\tdone; \\",
            "\t$(PYTHON) scripts/governance_truth.py --repo-root . --evidence-dir \"$$session_dir\"",
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
      - uses: {action_pin("checkout")}
        with: {{fetch-depth: 0, persist-credentials: false}}
      - uses: {action_pin("setup-python")}
        with: {{python-version: "3.12"}}
      - run: python3 -m pip install -r requirements-governance.txt
      - id: seed
        name: Validate cheap front door and seed immutable session
        shell: bash
        run: |
          set -euo pipefail
          manifest="$(python3 scripts/preflight_governance.py --repo-root . --mode "$BCF_PREFLIGHT_MODE" --python python3 --artifact-root .artifacts/bcf --expected-producer evidence --format text | tail -n 1)"
          printf 'session_manifest=%s\\n' "$manifest" >> "$GITHUB_OUTPUT"
      - uses: {action_pin("upload-artifact")}
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
      - uses: {action_pin("checkout")}
        with: {{fetch-depth: 0, persist-credentials: false}}
      - uses: {action_pin("setup-python")}
        with: {{python-version: "3.12"}}
      - run: python3 -m pip install -r requirements-governance.txt
      - uses: {action_pin("download-artifact")}
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
        uses: {action_pin("upload-artifact")}
        with:
          name: bcf-evidence-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}-${{{{ matrix.gate }}}}
          path: .artifacts/bcf/sessions
          if-no-files-found: error

  governance-truthfulness:
    if: always()
    needs: [preflight, evidence]
    runs-on: {label_yaml}
    steps:
      - uses: {action_pin("checkout")}
        with: {{fetch-depth: 0, persist-credentials: false}}
      - uses: {action_pin("setup-python")}
        with: {{python-version: "3.12"}}
      - run: python3 -m pip install -r requirements-governance.txt
      - uses: {action_pin("download-artifact")}
        with:
          name: bcf-session-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}
          path: .artifacts/bcf/sessions
      - uses: {action_pin("download-artifact")}
        with:
          pattern: bcf-evidence-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}-*
          path: .artifacts/bcf/fan-in
      - name: Restore private session modes after artifact transport
        shell: bash
        run: |
          set -euo pipefail
          find .artifacts/bcf/fan-in -type f -name evidence-session.json -execdir chmod 700 . \\; -exec chmod 400 {{}} +
      - run: python3 scripts/governance_truth.py --repo-root . --evidence-dir .artifacts/bcf/fan-in --evaluation-mode "${{{{ github.event_name == 'pull_request' && 'pr' || 'closure' }}}}" --format json --durable-ref "github-actions://${{{{ github.repository }}}}/runs/${{{{ github.run_id }}}}/attempts/${{{{ github.run_attempt }}}}/bcf-governance-truth" --output .artifacts/bcf/truth-report.json
      - if: always()
        uses: {action_pin("upload-artifact")}
        with:
          name: bcf-governance-truth-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}
          path: .artifacts/bcf/truth-report.json
          if-no-files-found: error
'''


def apply_profile_v2_artifact_defaults(
    profile: dict[str, Any], *, selected_profile: str, contract_version: str
) -> None:
    if contract_version != "2.0" or selected_profile not in {"standard", "regulated"}:
        return
    selected = next(
        item
        for item in profile["profile"]["available_profiles"]
        if item.get("name") == selected_profile
    )
    if "governance/ci-graph.yml" not in selected["required_artifacts"]:
        selected["required_artifacts"].append("governance/ci-graph.yml")

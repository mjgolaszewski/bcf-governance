"""Typed gate contracts and deterministic profile surface generation."""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


BUILTIN_TARGETS = {"governance-validate", "governance-exposure-scan"}
PROFILE_ORDER = {"lite": 0, "standard": 1, "regulated": 2}
TEST_POLICIES = {
    "automated_tests",
    "contract_tests",
    "architecture_tests",
    "architecture_module_size",
    "architecture_layer_membership",
    "architecture_context_membership",
    "architecture_import_boundaries",
    "architecture_cqrs_side",
    "architecture_router_thinness",
    "architecture_duplication",
}
DIRECT_CLAIMS = (
    "workitems_closed",
    "required_suites_green",
    "architecture_gates_green",
    "health_checks_green",
    "security_review_complete",
    "findings_resolved",
)


class ProfileContractError(ValueError):
    """Raised when a profile cannot become operational safely."""


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ProfileContractError(f"{path} must deserialize to a mapping")
    return payload


def _safe_relative(value: object, *, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProfileContractError(f"{context} must be a non-empty path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ProfileContractError(f"{context} must stay inside the repository")
    return path.as_posix()


def _builtin_contracts() -> dict[str, dict[str, Any]]:
    return {
        "governance-validate": {
            "invocation": {
                "argv": ["python3", "scripts/validate_governance_yaml.py", "--repo-root", "."],
                "cwd": ".",
                "env": {},
                "required_env": [],
            },
            "evidence": {"kind": "gate"},
            "negative_controls": [
                {
                    "id": "authored-verified-state-is-rejected",
                    "mutation": {
                        "path": "@active_phase_log",
                        "yaml_path": "document.status",
                        "value": "verified",
                    },
                    "oracle": {
                        "kind": "diagnostic",
                        "exit_codes": [1],
                        "stream": "stderr",
                        "regex": "verified.*(?:not one of|computed)",
                    },
                }
            ],
        },
        "governance-exposure-scan": {
            "invocation": {
                "argv": ["python3", "scripts/check_governance_exposure.py", "--repo-root", "."],
                "cwd": ".",
                "env": {},
                "required_env": [],
            },
            "evidence": {"kind": "gate"},
            "negative_controls": [
                {
                    "id": "local-workspace-path-is-rejected",
                    "mutation": {
                        "path": "MEMORY.yml",
                        "search": '  canonical_repo_root: "."',
                        "replace_base64": "ICBjYW5vbmljYWxfcmVwb19yb290OiAiL1VzZXJzL2V4YW1wbGUvcHJpdmF0ZSI=",
                    },
                    "oracle": {
                        "kind": "diagnostic",
                        "exit_codes": [1],
                        "stream": "stdout",
                        "regex": "local_workspace_path",
                    },
                }
            ],
        },
    }


def _v2_builtin_contracts() -> dict[str, dict[str, Any]]:
    return {
        "semantic-ownership": {
            "invocation": {
                "argv": ["python3", "scripts/semantic_ownership.py", "--repo-root", "."],
                "cwd": ".",
                "env": {},
                "required_env": [],
            },
            "evidence": {
                "kind": "gate",
                "output_requirements": [
                    {
                        "path": ".artifacts/semantic-ownership/report.json",
                        "media_type": "application/json",
                    }
                ],
            },
            "negative_controls": [
                {
                    "id": "evidence-session-owner-is-enforced",
                    "mutation": {
                        "path": "governance/canonical-representations.yml",
                        "search": "authorized_constructors_and_factories: ['scripts/_bcf_runtime/evidence_sessions.py::allocate_session', 'scripts/_bcf_runtime/evidence_sessions.py::load_session']",
                        "replace": "authorized_constructors_and_factories: ['scripts/_bcf_runtime/missing.py::owner']",
                    },
                    "oracle": {
                        "kind": "diagnostic",
                        "exit_codes": [1],
                        "stream": "stdout",
                        "regex": "governance.evidence-session.v1 owner must be an authorized constructor",
                    },
                }
            ],
        }
    }


def _validate_oracle(raw: object, *, context: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ProfileContractError(f"{context} must be a mapping")
    kind = raw.get("kind")
    if kind == "test_node_failure":
        node_ids = raw.get("node_ids")
        if not isinstance(node_ids, list) or not node_ids or not all(
            isinstance(value, str) and value for value in node_ids
        ):
            raise ProfileContractError(f"{context}.node_ids must be a non-empty string list")
        return {"kind": kind, "node_ids": list(dict.fromkeys(node_ids))}
    if kind != "diagnostic":
        raise ProfileContractError(f"{context}.kind must be diagnostic or test_node_failure")
    exit_codes = raw.get("exit_codes")
    stream = raw.get("stream")
    pattern = raw.get("regex")
    if (
        not isinstance(exit_codes, list)
        or not exit_codes
        or not all(isinstance(value, int) and 1 <= value <= 125 for value in exit_codes)
        or stream not in {"stdout", "stderr"}
        or not isinstance(pattern, str)
        or not pattern
    ):
        raise ProfileContractError(
            f"{context} diagnostic requires exit_codes 1..125, stdout|stderr, and regex"
        )
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ProfileContractError(f"{context}.regex is invalid: {exc}") from exc
    return {
        "kind": kind,
        "exit_codes": sorted(set(exit_codes)),
        "stream": stream,
        "regex": pattern,
    }


def _validate_control(raw: object, *, context: str) -> dict[str, Any]:
    if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not raw["id"]:
        raise ProfileContractError(f"{context} requires a non-empty id")
    mutation = raw.get("mutation")
    if not isinstance(mutation, dict):
        raise ProfileContractError(f"{context}.mutation must be a mapping")
    path = mutation.get("path")
    if path != "@active_phase_log":
        _safe_relative(path, context=f"{context}.mutation.path")
    text_mode = isinstance(mutation.get("search"), str) and (
        isinstance(mutation.get("replace"), str)
        != isinstance(mutation.get("replace_base64"), str)
    )
    yaml_mode = isinstance(mutation.get("yaml_path"), str) and "value" in mutation
    if text_mode == yaml_mode:
        raise ProfileContractError(
            f"{context}.mutation must declare exactly one of text replacement or YAML assignment"
        )
    return {
        "id": raw["id"],
        "mutation": dict(mutation),
        "oracle": _validate_oracle(raw.get("oracle"), context=f"{context}.oracle"),
    }


def _validate_gate(target: str, raw: object, *, command_policy: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ProfileContractError(f"gate {target} must be a mapping")
    invocation = raw.get("invocation")
    if not isinstance(invocation, dict):
        raise ProfileContractError(f"gate {target}.invocation must be a mapping")
    argv = invocation.get("argv")
    if not isinstance(argv, list) or not argv or not all(
        isinstance(value, str) and value for value in argv
    ):
        raise ProfileContractError(f"gate {target}.invocation.argv must be a non-empty string list")
    if Path(argv[0]).name.lower() in {"true", "false", "echo", "printf", ":"}:
        raise ProfileContractError(
            f"gate {target}.invocation.argv is a no-op, not executable evidence"
        )
    for index, argument in enumerate(argv):
        path_argument = Path(argument)
        if path_argument.is_absolute() or ".." in path_argument.parts:
            raise ProfileContractError(
                f"gate {target}.invocation.argv[{index}] must not escape the repository"
            )
    interpreter = Path(argv[0]).name.lower()
    if interpreter.startswith(("python", "node", "ruby", "perl")):
        if len(argv) < 2 or argv[1].startswith("-"):
            raise ProfileContractError(
                f"gate {target} must invoke a tracked script, not inline/module interpreter code"
            )
        _safe_relative(argv[1], context=f"gate {target}.invocation.argv[1]")
    cwd = _safe_relative(invocation.get("cwd", "."), context=f"gate {target}.invocation.cwd")
    env = invocation.get("env", {})
    required_env = invocation.get("required_env", [])
    if not isinstance(env, dict) or not all(
        isinstance(key, str) and key and isinstance(value, str) for key, value in env.items()
    ):
        raise ProfileContractError(f"gate {target}.invocation.env must contain string values")
    if not isinstance(required_env, list) or not all(
        isinstance(value, str) and value for value in required_env
    ):
        raise ProfileContractError(f"gate {target}.invocation.required_env must be a string list")
    controls = raw.get("negative_controls")
    if not isinstance(controls, list) or not controls:
        raise ProfileContractError(f"gate {target} requires at least one negative control")
    evidence = raw.get("evidence", {})
    if not isinstance(evidence, dict):
        raise ProfileContractError(f"gate {target}.evidence must be a mapping")
    evidence = dict(evidence)
    output_requirements = evidence.get("output_requirements", [])
    if not isinstance(output_requirements, list):
        raise ProfileContractError(f"gate {target}.evidence.output_requirements must be a list")
    normalized_outputs: list[dict[str, Any]] = []
    for index, output in enumerate(output_requirements):
        if not isinstance(output, dict) or not isinstance(output.get("media_type"), str):
            raise ProfileContractError(
                f"gate {target}.evidence.output_requirements[{index}] is invalid"
            )
        normalized_outputs.append(
            {
                "path": _safe_relative(
                    output.get("path"),
                    context=f"gate {target}.evidence.output_requirements[{index}].path",
                ),
                "media_type": output["media_type"],
                "authority": "non_authoritative_until_captured",
            }
        )
    if normalized_outputs:
        evidence["output_requirements"] = normalized_outputs
    validated_controls = [
        _validate_control(value, context=f"gate {target}.negative_controls[{index}]")
        for index, value in enumerate(controls)
    ]
    if command_policy in TEST_POLICIES:
        test_contract = evidence.get("test_contract")
        if not isinstance(test_contract, dict):
            raise ProfileContractError(f"gate {target} requires evidence.test_contract")
        junit_xml = _safe_relative(
            test_contract.get("junit_xml"),
            context=f"gate {target}.evidence.test_contract.junit_xml",
        )
        thresholds: dict[str, int] = {}
        for key, default in (("min_collected", 1), ("min_executed", 1), ("max_skipped", 0)):
            value = test_contract.get(key, default)
            if not isinstance(value, int) or value < 0:
                raise ProfileContractError(
                    f"gate {target}.evidence.test_contract.{key} must be a non-negative integer"
                )
            thresholds[key] = value
        if thresholds["min_executed"] < 1:
            raise ProfileContractError(f"gate {target} must execute at least one required test")
        if any(control["oracle"]["kind"] != "test_node_failure" for control in validated_controls):
            raise ProfileContractError(
                f"test gate {target} controls must use named test_node_failure oracles"
            )
        evidence = {
            **evidence,
            "test_contract": {
                **test_contract,
                **thresholds,
                "junit_xml": junit_xml,
                "artifact_binding": "non_authoritative_until_captured",
            },
        }
    return {
        "invocation": {
            "argv": argv,
            "cwd": cwd,
            "env": dict(sorted(env.items())),
            "required_env": sorted(set(required_env)),
        },
        "evidence": evidence,
        "negative_controls": validated_controls,
    }


def required_targets(
    repo_root: Path, profile: str, *, contract_version: str = "1.0"
) -> set[str]:
    payload = _load_yaml(repo_root / "governance-profile.yml")
    gates = payload.get("release_gate_profile", {}).get("gates", {})
    if not isinstance(gates, dict):
        raise ProfileContractError("governance-profile.yml gates are missing")
    if contract_version not in {"1.0", "2.0"}:
        raise ProfileContractError("profile contract version must be 1.0 or 2.0")
    if profile == "lite":
        return set(BUILTIN_TARGETS)
    targets = {
        str(gate["target"])
        for gate in gates.values()
        if isinstance(gate, dict) and isinstance(gate.get("target"), str)
    }
    targets.discard("ci-certification")
    if contract_version == "1.0":
        targets.discard("semantic-ownership")
    else:
        targets.add("semantic-ownership")
    return targets


def load_contract(
    repo_root: Path,
    profile: str,
    config_path: Path | None,
    *,
    asset_root: Path | None = None,
    contract_version: str = "1.0",
    config_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    targets = required_targets(repo_root, profile, contract_version=contract_version)
    raw_gates: dict[str, Any] = {}
    provenance: dict[str, Any] = {}
    if config_path is not None or config_payload is not None:
        payload = _load_yaml(config_path.resolve()) if config_path is not None else config_payload
        if not isinstance(payload, dict):
            raise ProfileContractError("profile config must be a mapping")
        if payload.get("schema_version") != "1.0" or payload.get("target_profile") != profile:
            raise ProfileContractError(
                f"profile config must declare schema_version 1.0 and target_profile {profile}"
            )
        configured_version = payload.get("profile_contract_version")
        if configured_version is not None and str(configured_version) != contract_version:
            raise ProfileContractError(
                "profile config profile_contract_version does not match requested version"
            )
        candidate = payload.get("gates")
        if not isinstance(candidate, dict):
            raise ProfileContractError("profile config gates must be a mapping")
        raw_gates = candidate
        if contract_version == "1.0":
            raw_gates = {
                key: value
                for key, value in raw_gates.items()
                if key not in {"semantic-ownership", "ci-certification"}
            }
        elif "ci-certification" in raw_gates:
            targets.add("ci-certification")
        overridden_builtins = sorted(set(raw_gates).intersection(BUILTIN_TARGETS))
        if overridden_builtins:
            raise ProfileContractError(
                "profile config cannot override built-in governance gates: "
                + ", ".join(overridden_builtins)
            )
        provenance = payload.get("provenance", {})
        if not isinstance(provenance, dict):
            raise ProfileContractError("profile config provenance must be a mapping")
    elif profile != "lite":
        raise ProfileContractError(f"--profile-config is required for {profile}")
    merged = {
        **_builtin_contracts(),
        **(_v2_builtin_contracts() if contract_version == "2.0" else {}),
        **raw_gates,
    }
    missing = sorted(targets - set(merged))
    extra = sorted(set(merged) - targets)
    if missing or extra:
        raise ProfileContractError(f"profile gate set mismatch: missing={missing}, extra={extra}")
    metadata = _profile_gate_metadata(repo_root)
    gates = {
        target: _validate_gate(
            target,
            merged[target],
            command_policy=metadata[target][1],
        )
        for target in sorted(targets)
    }
    if profile == "regulated":
        keys = provenance.get("trusted_verifier_keys")
        authorities = provenance.get("permitted_risk_authorities")
        if (
            not isinstance(keys, dict)
            or not keys
            or not isinstance(authorities, list)
            or not authorities
            or not all(isinstance(value, str) and value for value in authorities)
        ):
            raise ProfileContractError(
                "regulated profile requires trusted_verifier_keys and permitted_risk_authorities"
            )
        key_root = (asset_root or repo_root).resolve()
        normalized_keys: dict[str, str] = {}
        for key_id, raw_path in keys.items():
            if not isinstance(key_id, str) or not key_id:
                raise ProfileContractError("regulated verifier key IDs must be non-empty strings")
            relative = _safe_relative(
                raw_path,
                context=f"provenance.trusted_verifier_keys.{key_id}",
            )
            key_path = key_root / relative
            if key_path.is_symlink() or not key_path.is_file():
                raise ProfileContractError(
                    f"trusted verifier key {key_id} must be a regular repository file: {relative}"
                )
            normalized_keys[key_id] = relative
        provenance = {
            **provenance,
            "trusted_verifier_keys": normalized_keys,
            "permitted_risk_authorities": sorted(set(authorities)),
        }
    profile_payload = _load_yaml(repo_root / "governance-profile.yml")
    gate_catalog = profile_payload.get("release_gate_profile", {}).get("gates")
    if not isinstance(gate_catalog, dict):
        raise ProfileContractError("governance profile gate catalog is missing")
    return {
        "schema_version": "1.0",
        "profile_contract_version": contract_version,
        "target_profile": profile,
        "gates": gates,
        "gate_catalog": gate_catalog,
        "provenance": provenance,
    }


def _evidence_kind(command_policy: str) -> str:
    if command_policy in TEST_POLICIES:
        return "test_suite"
    if command_policy == "security_review":
        return "security_review"
    if command_policy == "runtime_smoke":
        return "runtime_health"
    return "gate"


def _profile_gate_metadata(repo_root: Path) -> dict[str, tuple[str, str]]:
    payload = _load_yaml(repo_root / "governance-profile.yml")
    gates = payload["release_gate_profile"]["gates"]
    return {
        str(value["target"]): (str(key), str(value["command_policy"]))
        for key, value in gates.items()
        if isinstance(value, dict)
    }


def derived_closeout_requirements(
    repo_root: Path, contract: dict[str, Any]
) -> dict[str, Any]:
    """Map the selected profile's executable gates to computed lifecycle claims."""
    metadata = _profile_gate_metadata(repo_root)
    claims: dict[str, list[str]] = {claim: [] for claim in DIRECT_CLAIMS}
    for target in contract["gates"]:
        command_policy = metadata[target][1]
        if target == "governance-validate":
            claims["workitems_closed"].append(target)
        if command_policy.startswith("architecture_") or command_policy == "architecture_tests":
            claims["architecture_gates_green"].append(target)
        elif command_policy in {"automated_tests", "contract_tests", "lint", "typecheck"}:
            claims["required_suites_green"].append(target)
        if command_policy == "runtime_smoke":
            claims["health_checks_green"].append(target)
        if command_policy == "security_review":
            claims["security_review_complete"].append(target)
            claims["findings_resolved"].append(target)
        if command_policy == "security_vulnerability_scan":
            claims["findings_resolved"].append(target)

    # Even the lite profile must prove that the canonical finding registry was
    # structurally checked on the governed tree before findings can be resolved.
    if not claims["findings_resolved"] and "governance-validate" in contract["gates"]:
        claims["findings_resolved"].append("governance-validate")
    return {
        "claims": {key: sorted(set(value)) for key, value in claims.items()},
        "reconciliation": sorted(
            set(contract["gates"]).intersection(BUILTIN_TARGETS)
        ),
    }


def apply_scaffold_requirements(
    repo_root: Path,
    contract: dict[str, Any],
    generated_artifacts: dict[str, Path],
) -> None:
    """Seed new artifacts from the profile without touching pre-existing phases."""
    requirements = derived_closeout_requirements(repo_root, contract)
    log_path = generated_artifacts["log"]
    log = _load_yaml(log_path)
    closeout = log["closeout_requirements"]
    closeout["claims"] = {
        claim: {"required_evidence": gates}
        for claim, gates in requirements["claims"].items()
    }
    closeout["reconciliation"] = {
        "required_evidence": requirements["reconciliation"]
    }
    log_path.write_text(yaml.safe_dump(log, sort_keys=False, width=120), encoding="utf-8")

    workitems_path = generated_artifacts["workitems"]
    workitems = _load_yaml(workitems_path)
    acceptance = requirements["claims"]["required_suites_green"]
    if not acceptance:
        acceptance = requirements["claims"]["workitems_closed"]
    for workitem in workitems.get("workitems", []):
        if isinstance(workitem, dict):
            workitem["acceptance_evidence"] = acceptance
    workitems_path.write_text(
        yaml.safe_dump(workitems, sort_keys=False, width=120), encoding="utf-8"
    )


def _write_makefile(repo_root: Path, contract: dict[str, Any]) -> None:
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
            f"{key}={shlex.quote(value)}" for key, value in gate["invocation"]["env"].items()
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


def _write_workflow(repo_root: Path, contract: dict[str, Any]) -> None:
    gates = list(contract["gates"])
    profile = _load_yaml(repo_root / "governance-profile.yml")
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
      - uses: actions/checkout@v4
        with: {{fetch-depth: 0}}
      - uses: actions/setup-python@v5
        with: {{python-version: "3.12"}}
      - run: python3 -m pip install -r requirements-governance.txt
      - name: Capture ${{{{ matrix.gate }}}} evidence
        run: python3 scripts/governance_evidence.py --repo-root . run --gate "${{{{ matrix.gate }}}}" --output ".artifacts/bcf/${{{{ matrix.gate }}}}"
      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: bcf-evidence-${{{{ matrix.gate }}}}
          path: .artifacts/bcf/${{{{ matrix.gate }}}}
          if-no-files-found: error

  governance-truthfulness:
    if: always()
    needs: [evidence]
    runs-on: {label_yaml}
    steps:
      - uses: actions/checkout@v4
        with: {{fetch-depth: 0}}
      - uses: actions/setup-python@v5
        with: {{python-version: "3.12"}}
      - run: python3 -m pip install -r requirements-governance.txt
      - uses: actions/download-artifact@v4
        with: {{pattern: bcf-evidence-*, path: .artifacts/bcf, merge-multiple: true}}
      - run: python3 scripts/governance_truth.py --repo-root . --evidence-dir .artifacts/bcf --format json --durable-ref "github-actions://${{{{ github.repository }}}}/runs/${{{{ github.run_id }}}}/bcf-governance-truth" --output .artifacts/bcf/truth-report.json
      - if: always()
        uses: actions/upload-artifact@v4
        with: {{name: bcf-governance-truth, path: .artifacts/bcf/truth-report.json, if-no-files-found: error}}
'''
    path = repo_root / ".github/workflows/governance.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def apply_profile_contract(
    repo_root: Path,
    contract: dict[str, Any],
    *,
    write_workflow: bool = True,
) -> None:
    profile_name = str(contract["target_profile"])
    metadata = {
        str(value["target"]): (str(key), str(value["command_policy"]))
        for key, value in contract["gate_catalog"].items()
        if isinstance(value, dict)
    }
    active_targets = set(contract["gates"])
    profile = _load_yaml(repo_root / "governance-profile.yml")
    contract_version = str(contract.get("profile_contract_version", "1.0"))
    if contract_version not in {"1.0", "2.0"}:
        raise ProfileContractError("profile contract version must be 1.0 or 2.0")
    profile["profile_contract_version"] = contract_version
    profile["profile"]["selected"] = profile_name
    profile["release_gate_profile"]["gates"] = contract["gate_catalog"]
    for value in profile["release_gate_profile"]["gates"].values():
        value["status"] = "required" if value["target"] in active_targets else "deferred"
    profile["ci_profile"]["required_push_jobs"] = sorted(active_targets)
    (repo_root / "governance-profile.yml").write_text(
        yaml.safe_dump(profile, sort_keys=False, width=120, default_flow_style=None), encoding="utf-8"
    )

    persisted = {
        "document": {
            "kind": "gate_contract_registry",
            "version": "1.0",
            "path": "governance/gate-contracts.yml",
        },
        **contract,
    }
    contract_path = repo_root / "governance/gate-contracts.yml"
    contract_path.parent.mkdir(parents=True, exist_ok=True)
    contract_path.write_text(yaml.safe_dump(persisted, sort_keys=False, width=120, default_flow_style=None), encoding="utf-8")

    evidence_policy = _load_yaml(repo_root / "governance/evidence-policy.yml")
    evidence_policy["gate_overrides"] = {}
    for target, gate in contract["gates"].items():
        command_policy = metadata[target][1]
        evidence = dict(gate.get("evidence", {}))
        test_contract = evidence.get("test_contract")
        if isinstance(test_contract, dict):
            policy_test_contract = dict(test_contract)
            policy_test_contract.pop("selectors", None)
            evidence["test_contract"] = policy_test_contract
        evidence_policy["gate_overrides"][target] = {
            "evidence_kind": evidence.pop("kind", _evidence_kind(command_policy)),
            "negative_controls": gate["negative_controls"],
            **evidence,
        }
    if profile_name == "regulated":
        evidence_policy["provenance"].update(contract.get("provenance", {}))
    (repo_root / "governance/evidence-policy.yml").write_text(
        yaml.safe_dump(evidence_policy, sort_keys=False, width=120, default_flow_style=None), encoding="utf-8"
    )
    _write_makefile(repo_root, contract)
    if write_workflow:
        _write_workflow(repo_root, contract)
    if profile_name == "regulated":
        regulated_docs = {
            "governance/MODEL_RISK_AND_PROVENANCE.md": (
                "# Model Risk and Provenance\n\n"
                "This regulated profile requires typed actor provenance, independent Critical/High "
                "verification, exact-tree evidence, and a trusted detached DSSE/Ed25519 attestation.\n"
            ),
            "governance/HOTFIX_LANE.md": (
                "# Regulated Hotfix Lane\n\n"
                "Emergency work retains finding accounting, exact-tree evidence, behavioral controls, "
                "independent verification, reconciliation, and merge-back recapture requirements.\n"
            ),
        }
        for relative, text in regulated_docs.items():
            path = repo_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_text(text, encoding="utf-8")


def promote(
    repo_root: Path,
    target_profile: str,
    config_path: Path | None,
    *,
    contract_version: str | None = None,
) -> dict[str, Any]:
    profile_payload = _load_yaml(repo_root / "governance-profile.yml")
    current = profile_payload.get("profile", {}).get("selected")
    current_version = str(profile_payload.get("profile_contract_version", "1.0"))
    target_version = contract_version or current_version
    if current not in PROFILE_ORDER or target_profile not in PROFILE_ORDER:
        raise ProfileContractError("current and target profiles must be lite, standard, or regulated")
    if current_version not in {"1.0", "2.0"} or target_version not in {"1.0", "2.0"}:
        raise ProfileContractError("profile contract version must be 1.0 or 2.0")
    profile_advances = PROFILE_ORDER[target_profile] > PROFILE_ORDER[str(current)]
    contract_advances = current_version == "1.0" and target_version == "2.0"
    if PROFILE_ORDER[target_profile] < PROFILE_ORDER[str(current)] or (
        current_version == "2.0" and target_version == "1.0"
    ):
        raise ProfileContractError("profile and contract promotion must be monotonic")
    if not profile_advances and not contract_advances:
        raise ProfileContractError(
            f"profile promotion must advance beyond {current} contract {current_version}"
        )
    if target_version == "2.0":
        from .profile_contract_v2 import validate_profile_v2_readiness

        validate_profile_v2_readiness(repo_root, profile=target_profile)
    config_payload: dict[str, Any] | None = None
    if config_path is None:
        persisted = _load_yaml(repo_root / "governance/gate-contracts.yml")
        gates = persisted.get("gates")
        if not isinstance(gates, dict):
            raise ProfileContractError("canonical gate contracts are missing")
        config_payload = {
            "schema_version": "1.0",
            "profile_contract_version": target_version,
            "target_profile": target_profile,
            "gates": {
                key: value
                for key, value in gates.items()
                if key not in BUILTIN_TARGETS
            },
            "provenance": persisted.get("provenance", {}),
        }
    return load_contract(
        repo_root,
        target_profile,
        config_path,
        contract_version=target_version,
        config_payload=config_payload,
    )

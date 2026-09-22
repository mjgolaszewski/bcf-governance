"""Claim-specific receipt fields and reusable qualification projection."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Iterable, Mapping

from .evidence_execution import EvidenceError
from .evidence_planning import (
    build_dependency_manifest,
    claims_for_legacy_gate,
    load_claim_model,
    parse_claim_model,
)
from .evidence_claim_resolution import claim_gate_projection, load_claim_gate_projection


def _qualification_digest(material: Any) -> str:
    return hashlib.sha256(json.dumps(
        material, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()


def qualification_equivalence(
    repo_root: Path, receipt: dict[str, Any], claim_id: str,
    *, contract_payload: Mapping[str, Any] | None = None,
    tree_entries: Iterable[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Recompute one claim's qualified detector proof on current main bytes.

    Source proof remains a separate provider-custody question.  A reference to
    another receipt is not admitted here without authenticating that chain.
    """
    model = (load_claim_model(repo_root) if contract_payload is None
             else parse_claim_model(contract_payload))
    claim = model["claims"].get(claim_id)
    if not isinstance(claim, dict):
        raise EvidenceError(f"unknown claim {claim_id}")
    scope = claim.get("qualification_scope")
    if scope == "none":
        digest = _qualification_digest({"scope": "none"})
        return {"source_sha256": digest, "main_sha256": digest, "equivalent": True}
    qualified = receipt.get("qualifications")
    source = qualified.get(claim_id) if isinstance(qualified, dict) else receipt.get("qualification")
    controls = source.get("control_ids") if isinstance(source, dict) else None
    valid_controls = (
        isinstance(controls, list)
        and all(isinstance(value, str) and value for value in controls)
        and controls == sorted(set(controls))
    )
    selected_controls = controls if valid_controls else []
    dependencies = build_dependency_manifest(
        repo_root, [claim_id], model=model, tree_entries=tree_entries,
    )["claim_dependencies"][claim_id]
    classes = ({"detector", "test_population", "subject"} if scope == "subject"
               else {"detector", "test_population", "toolchain", "trust"})
    main_digest = _qualification_digest({
        "scope": scope, "controls": selected_controls,
        "dependencies": [value for value in dependencies if value["class"] in classes],
    })
    source_digest = source.get("fingerprint") if isinstance(source, dict) else None
    if not isinstance(source_digest, str) or re.fullmatch(r"[a-f0-9]{64}", source_digest) is None:
        source_digest = _qualification_digest(source)
    references = receipt.get("qualification_refs")
    referenced = {
        value.get("claim_id") for value in references if isinstance(value, dict)
    } if isinstance(references, list) else set()
    expected_controls: set[str] = set()
    contract_valid = True
    try:
        projection = (
            load_claim_gate_projection(repo_root, receipt.get("claims", []))
            if contract_payload is None else
            claim_gate_projection(contract_payload, receipt.get("claims", []))
        )
        for receipt_claim in receipt.get("claims", []):
            if receipt_claim in referenced:
                continue
            for control in projection[receipt_claim]["gate"].get("negative_controls", []):
                if not isinstance(control, dict) or not isinstance(control.get("id"), str):
                    contract_valid = False
                    continue
                expected_controls.add(control["id"])
    except (OSError, ValueError, KeyError, TypeError):
        contract_valid = False
    equivalent = (
        claim_id not in referenced and contract_valid and valid_controls
        and selected_controls == sorted(expected_controls)
        and isinstance(source, dict) and source.get("scope") == scope
        and source.get("satisfied") is True and source_digest == main_digest
    )
    return {
        "source_sha256": source_digest, "main_sha256": main_digest,
        "equivalent": equivalent,
    }


def capture_subject_preflight(repo_root: Path, output_dir: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all", "--ignored=no"],
        cwd=repo_root, capture_output=True, text=True, check=False,
    )
    status = result.stdout.strip()
    if result.returncode or status:
        raise EvidenceError(
            "claim evidence requires a clean committed worktree; non-ignored untracked "
            "or modified inputs are not admissible:\n" + status
        )
    root = repo_root.resolve()
    resolved_output = output_dir.resolve()
    if resolved_output == root:
        raise EvidenceError("evidence output cannot be the governed repository root")
    if resolved_output.is_relative_to(root):
        relative = resolved_output.relative_to(root).as_posix()
        ignored = subprocess.run(["git", "check-ignore", "--no-index", "--quiet", relative],
                                 cwd=repo_root, check=False)
        if ignored.returncode:
            raise EvidenceError("in-repository evidence output must be ignored by Git")
    links = subprocess.run(["git", "ls-files", "-s"], cwd=repo_root,
                           capture_output=True, text=True, check=True).stdout
    for line in links.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) != 4 or fields[0] != "120000":
            continue
        relative = Path(fields[3])
        link = repo_root / relative
        target = Path(os.readlink(link))
        resolved = target if target.is_absolute() else (link.parent / target).resolve()
        if target.is_absolute() or not resolved.is_relative_to(root):
            raise EvidenceError(f"tracked symlink escapes governed tree: {relative.as_posix()}")
    return {"tracked_clean": True, "untracked_clean": True,
            "status_porcelain_sha256": hashlib.sha256(status.encode()).hexdigest()}


def claim_capture(
    repo_root: Path, target: str, contract_version: str, session: Any | None
) -> tuple[list[str], list[dict[str, str]]]:
    claim_ids = claims_for_legacy_gate(repo_root, target) if contract_version == "3.0" else [target]
    if not claim_ids:
        raise EvidenceError(f"gate {target} does not produce a declared claim")
    references: list[dict[str, str]] = []
    if session is not None and session.payload.get("schema_version") == "2.0":
        dag = session.payload.get("execution_dag")
        nodes = dag.get("nodes") if isinstance(dag, dict) else []
        node = next((value for value in nodes if isinstance(value, dict)
                     and value.get("producer") == target), {})
        references = [
            {key: str(value[key]) for key in ("claim_id", "evidence_id", "artifact_sha256")}
            for value in node.get("qualification_refs", [])
            if isinstance(value, dict) and all(isinstance(value.get(key), str)
                                               for key in ("claim_id", "evidence_id", "artifact_sha256"))
        ]
    return claim_ids, references


def legacy_gates_requiring_qualification(
    repo_root: Path, claim_ids: list[str], references: list[dict[str, str]]
) -> list[str]:
    model = load_claim_model(repo_root)
    qualified = {value["claim_id"] for value in references}
    return sorted({str(model["claims"][claim_id]["legacy_gate"])
                   for claim_id in claim_ids if claim_id not in qualified})


def claim_receipt_fields(
    repo_root: Path, claim_ids: list[str], references: list[dict[str, str]],
    probes: list[dict[str, Any]],
) -> dict[str, Any]:
    manifest = build_dependency_manifest(repo_root, claim_ids)
    model = load_claim_model(repo_root)
    scopes = {str(model["claims"][claim_id]["qualification_scope"]) for claim_id in claim_ids}
    scope = "subject" if "subject" in scopes else "detector"
    dependency_classes = (
        {"detector", "test_population", "subject"}
        if scope == "subject" else {"detector", "test_population", "toolchain"}
    )
    controls = sorted(str(value.get("id")) for value in probes if isinstance(value, dict))
    material = {"scope": scope, "controls": controls,
                "dependencies": [value for value in manifest["classes"]
                                 if value["class"] in dependency_classes]}
    qualification = None
    qualifications: dict[str, dict[str, Any]] = {}
    if probes:
        qualification = {"scope": scope,
                         "satisfied": all(isinstance(value.get("oracle_observation"), dict)
                                          and value["oracle_observation"].get("satisfied") is True
                                          for value in probes),
                         "fingerprint": hashlib.sha256(json.dumps(
                             material, sort_keys=True, separators=(",", ":")
                         ).encode("utf-8")).hexdigest(),
                         "control_ids": controls}
        for claim_id in claim_ids:
            claim_scope = str(model["claims"][claim_id]["qualification_scope"])
            if claim_scope == "none":
                continue
            claim_classes = ({"detector", "test_population", "subject"}
                             if claim_scope == "subject"
                             else {"detector", "test_population", "toolchain", "trust"})
            claim_dependencies = manifest["claim_dependencies"][claim_id]
            claim_material = {"scope": claim_scope, "controls": controls,
                              "dependencies": [value for value in claim_dependencies
                                               if value["class"] in claim_classes]}
            qualifications[claim_id] = {
                "scope": claim_scope,
                "satisfied": qualification["satisfied"],
                "fingerprint": hashlib.sha256(json.dumps(
                    claim_material, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")).hexdigest(),
                "control_ids": controls,
            }
    return {"claims": claim_ids, "dependency_manifest": manifest,
            **({"qualification": qualification} if qualification is not None else {}),
            **({"qualifications": qualifications} if qualifications else {}),
            "qualification_refs": references}

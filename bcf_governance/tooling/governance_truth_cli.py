"""Command-line projection for governance truth."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .release_receipts import ReleaseReceiptError, build_release_receipt, emit_release_receipt


def main(argv: list[str] | None = None) -> None:
    from .governance_truth import TruthfulnessError, derive_truth

    parser = argparse.ArgumentParser(description="Derive governance truth from evidence.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--evaluation-mode", choices=("closure", "pr", "workitem"), default="closure")
    parser.add_argument("--evaluation-target")
    parser.add_argument("--trusted-digest")
    parser.add_argument("--ci-authority", type=Path)
    parser.add_argument("--ci-certification", type=Path)
    parser.add_argument("--ci-session-manifest", type=Path)
    parser.add_argument("--release-receipt-output", type=Path)
    parser.add_argument("--release-artifact", type=Path, action="append", default=[])
    parser.add_argument("--durable-ref")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = derive_truth(
            args.repo_root,
            args.evidence_dir,
            evaluation_mode=args.evaluation_mode,
            evaluation_target=args.evaluation_target or None,
            trusted_digest=args.trusted_digest,
            ci_authority_path=args.ci_authority,
            ci_certification_path=args.ci_certification,
            ci_session_manifest_path=args.ci_session_manifest,
        )
    except TruthfulnessError as exc:
        print(str(exc), file=os.sys.stderr)
        raise SystemExit(1)
    if args.durable_ref:
        report["durable_ref"] = args.durable_ref
    rendered = json.dumps(
        report,
        indent=None if args.compact else 2,
        separators=(",", ":") if args.compact else None,
        sort_keys=True,
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    if args.release_receipt_output and args.evaluation_mode != "closure":
        raise SystemExit("release receipts require closure truth evaluation")
    if args.release_receipt_output and report["status"] == "pass":
        if not all((args.output, args.ci_certification, args.ci_session_manifest, args.release_artifact)):
            raise SystemExit(
                "release receipt requires truth output, CI certification, session manifest, and release artifacts"
            )
        try:
            certification = json.loads(args.ci_certification.read_text(encoding="utf-8"))
            receipt = build_release_receipt(
                args.repo_root.resolve(),
                truth_report=report,
                truth_report_path=args.output,
                certification=certification,
                certification_path=args.ci_certification,
                certification_verification=report["ci_certification"],
                session_manifest_path=args.ci_session_manifest,
                evidence_dir=args.evidence_dir,
                release_artifacts=args.release_artifact,
                output_path=args.release_receipt_output,
            )
            emit_release_receipt(args.release_receipt_output, receipt)
        except (OSError, json.JSONDecodeError, ReleaseReceiptError) as exc:
            raise SystemExit(str(exc)) from exc
    if args.format == "json":
        print(rendered)
    else:
        print(f"governance-truth-{report['status']} state={report['effective_state']}")
        for issue in report["issues"]:
            print(f"- {issue}")
    if report["status"] != "pass":
        raise SystemExit(1)

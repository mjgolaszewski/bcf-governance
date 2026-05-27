"""Install command text reporting."""

from __future__ import annotations

from typing import Any, Callable


def print_summary(
    args: Any,
    result: Any,
    *,
    required_standard_gates: tuple[str, ...],
    all_required_gates_wired: Callable[[str, dict[str, str]], bool],
) -> None:
    target_root = args.target.resolve()
    verb = "upgraded" if args.upgrade else "installed"
    print(f"{verb} governance pack into {target_root}")
    print(f"profile: {args.profile}")
    print(f"adoption mode: {args.adoption_mode}")
    print(f"copied files: {result.copied_files}")
    if result.rescaffold_removed_paths:
        print("force-rescaffold removed: " + ", ".join(result.rescaffold_removed_paths))
    if result.removed_template_examples:
        print("removed template examples: " + ", ".join(result.removed_template_examples))
    for artifact_type, path in result.generated_artifacts.items():
        print(f"{artifact_type}: {path.relative_to(target_root).as_posix()}")

    if args.skip_validation:
        print("validation: skipped")
    elif result.strict_validation_passed:
        print("validation: strict pass")
    elif result.bootstrap_validation_passed:
        print("validation: bootstrap pass; strict validation is blocked by unwired release gates")
        if not all_required_gates_wired(args.profile, dict(args.gate_command)):
            built_in_targets = {"governance-validate", "governance-exposure-scan"}
            missing = [
                target
                for target in required_standard_gates
                if target not in built_in_targets and target not in dict(args.gate_command)
            ]
            print("wire release gates: " + ", ".join(missing))
    else:
        print("validation: failed")
        if result.strict_validation_output:
            print(result.strict_validation_output)
        if result.bootstrap_validation_output:
            print(result.bootstrap_validation_output)

    if args.adoption_mode == "existing":
        print(
            "next: follow governance/EXISTING_REPO_ADOPTION.md and "
            "governance/existing-repo-adoption.yml to inventory existing boundaries and wire gates"
        )
    print("next: merge Makefile.fragment into the repo Makefile or include it from the repo Makefile")

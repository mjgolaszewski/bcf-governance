# Maintaining and Releasing BCF

This guide is for the BCF framework repository. Product-repository operations
are documented in [Using BCF](USAGE.md) and the installed
`template-repo/docs/OPERATIONS.md`. Architectural rationale belongs in
[Architecture](ARCHITECTURE.md); trust flow and provider certification belong
in [CI authority](CI_AUTHORITY.md).

## Source ownership

- `bcf_governance/` is the packaged implementation.
- `bcf_governance/_version.py` is the sole version source.
- `template-repo/` is the canonical installed pack.
- `bcf_governance/pack/template-repo/` is the packaged copy.
- `scripts/` contains non-packaged thin wrappers for a source checkout.
- `template-repo/scripts/_bcf_runtime/` is the private standalone runtime copy.
- `tests/` owns behavioral and contract coverage.

Do not patch generated copies independently. After changing packaged tooling or
the template, synchronize and regenerate the checksummed pack manifests:

```bash
rsync -a --delete --exclude='__pycache__' --exclude='*.pyc' \
  bcf_governance/tooling/ template-repo/scripts/_bcf_runtime/
rsync -a --delete --exclude='__pycache__' --exclude='*.pyc' \
  template-repo/ bcf_governance/pack/template-repo/
python3 .github/scripts/build_pack_manifest.py
```

Pack/runtime parity tests fail on drift. Keep implementation modules below 800
lines and split by stable security or validation concepts, preserving focused
characterization tests before a split.

Profile-contract behavior has one packaged owner. Fresh Standard and Regulated
installs use v2; Lite and version-absent consumers remain v1. Ordinary upgrades
preserve the selected profile, contract version, and workflow bytes. Promotion
is explicit, monotonic, transactional, and also preserves workflow bytes;
GitHub workflow changes belong only to fresh installation or the explicit CI
adopter. Tests must compare those bytes, not merely decoded job names.

After changing v2 profile surfaces, test all four copies: packaged tooling,
standalone private runtime, template source, and packaged template. Generated
v2 workflows must allocate one session before evidence, execute positive gates
once, use exact run/attempt artifact namespaces, and contain no polling,
sleeping, or capacity-wait jobs.

## Change contract

Every pull request:

- updates `CHANGELOG.md` under `Unreleased` or the pending release section;
- updates behavior, tests, templates, schemas, and docs together;
- removes superseded instructions instead of documenting another parallel
  workflow;
- preserves root README as an overview, `docs/USAGE.md` as canonical operator
  guidance, `docs/ARCHITECTURE.md` as design rationale,
  `docs/CI_AUTHORITY.md` as the trust model, and this file as canonical
  maintainer guidance;
- runs focused tests while editing and the full source suite before handoff.

The governance validator enforces the changelog diff in pull-request CI using
the event's exact base SHA. Generated workflows use full history so an
unavailable base fails rather than bypassing the rule.

Run the editorial contract after changing prose or examples:

```bash
python3 .github/scripts/check_editorial_contract.py
```

It checks the documentation ownership map, local links and anchors, current
version and CLI examples, required architecture/trust sections, and measured
tone constraints. It is a mechanical consistency check, not a substitute for
reviewing clarity or technical accuracy.

## Verification

Run the source and template checks:

```bash
pytest tests
python3 scripts/validate_governance_yaml.py \
  --repo-root template-repo \
  --allow-placeholders \
  --allow-release-gate-placeholders
python3 scripts/check_governance_exposure.py --repo-root template-repo
```

Mutation profiles first run an unmodified baseline. A mutant dies only when
its explicit killer nodes pass on the baseline and fail behaviorally after the
mutation—not on collection, import, syntax, or infrastructure failure:

```bash
python3 .github/scripts/run_validator_mutants.py --profile high-value
python3 .github/scripts/run_validator_mutants.py --profile full
```

Pull requests run source tests and semantic mutants; larger implementation and
semantic profiles run nightly and the full profiles run weekly.

## Distribution tests

Release verification builds first. A clean wheel environment runs CLI, lite
install, validation, doctor, evidence, and truth smoke tests. A separate clean
environment installs the extracted sdist and runs its complete bundled suite.
The sdist must carry tests, fixtures, templates, schemas, examples, and workflow
data needed by those tests. `twine check`, checksums, and provenance happen only
after both artifact tests pass.

Run the local artifact harness with:

```bash
python3 -m build
python3 .github/scripts/test_release_artifacts.py --dist-dir dist
python3 -m twine check dist/*
```

## Version and release

For a release:

1. Set `bcf_governance/_version.py` to `X.Y.Z`.
2. Update the release heading and comparison links in `CHANGELOG.md`.
3. Update `manifest.yml`; regenerate template runtime/version surfaces and pack
   manifests.
4. Run source, profile-flow, mutation, template, exposure, wheel, sdist, and
   editorial verification.
5. Merge the reviewed pull request after required CI passes and certify that
   exact main commit through the trusted control plane.
6. Owner-dispatch `bcf/certified-release` on exact main. Its fresh candidate
   worker builds and tests the distributions once and emits an output-only
   release receipt.
7. Verify the certified artifact bundle and create one annotated `vX.Y.Z` tag
   at that exact commit.
8. Push the tag. The trusted publisher authenticates the tag and latest exact
   successful release run, verifies the Actions artifact digest, receipt, and
   `SHA256SUMS`, attests the already-certified files, and publishes them.

The tag event does not rebuild. The publisher checks out no repository code and
executes no candidate-provided script. If documentation included in the sdist
changes after certification, repeat exact-main certification and artifact
construction; supersede the older bytes instead of reusing their receipt. PyPI
is not used. All GitHub actions are pinned and release permissions are scoped
to the trusted publication job.

The BCF repository is itself standard-governed. Its generated governance
workflow and gate contracts must pass on the merge commit; a release tag never
turns older-tree evidence into current evidence.

# Maintaining and Releasing BCF

This guide is for the BCF framework repository. Product-repository operations
are documented in [Using BCF](USAGE.md) and the installed
`template-repo/docs/OPERATIONS.md`.

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

## Change contract

Every pull request:

- updates `CHANGELOG.md` under `Unreleased` or the pending release section;
- updates behavior, tests, templates, schemas, and docs together;
- removes superseded instructions instead of documenting another parallel
  workflow;
- preserves root README as an overview, `docs/USAGE.md` as canonical operator
  guidance, and this file as canonical maintainer guidance;
- runs focused tests while editing and the full source suite before handoff.

The governance validator enforces the changelog diff in pull-request CI using
the event's exact base SHA. Generated workflows use full history so an
unavailable base fails rather than bypassing the rule.

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
4. Run source, profile-flow, mutation, template, exposure, wheel, and sdist
   verification.
5. Merge the reviewed pull request after required CI passes.
6. Create immutable tag `vX.Y.Z` at the merge commit and push it.

The tag workflow verifies that tag and package versions agree, repeats artifact
testing, runs `twine check`, generates `SHA256SUMS`, creates GitHub build
provenance attestations, and publishes the wheel, sdist, and checksums to the
GitHub Release. PyPI is not used. Release actions have minimal pinned
permissions.

The BCF repository is itself standard-governed. Its generated governance
workflow and gate contracts must pass on the merge commit; a release tag never
turns older-tree evidence into current evidence.

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

For profile v2, `governance/gate-contracts.yml` is the only owner of gate argv,
evidence assertions, and negative controls. `governance/evidence-policy.yml`
owns claims, workflow requirements, provenance, and cross-gate policy; its
`gate_overrides` mapping must remain empty. The validator rejects a duplicated
per-gate declaration, so maintainers do not synchronize two semantic copies.

For BCF's own authority workflows, make the final workflow-byte commit first. Run
`bcf ci pin-authority --definition-commit "$(git rev-parse HEAD)" --apply` in the
following commit. The compiler updates the full registry and all exact job inventories;
never copy blob hashes, workflow digests, definition commits, or display names into the
authority document. Preflight verifies the projection from Git on every governed tree.

Likewise, never copy a controller artifact ID, run ID, provider digest, tree, or wheel
hash into bootstrap YAML. Use the trusted `ci-github controller-pin resolve|compile`
sequence, then `bcf ci sync-self-controller --pin PIN.json --apply`. The canonical pin
record is the single source for the target. Active workflows remain on the separately
recorded installed controller until exact-main bootstrap and probe runs succeed on all
trusted runners. Compile that provider proof with `bcf ci-github controller-pin confirm`
and pass it to `bcf ci sync-self-controller --confirmation`; never edit the installed
commit or proof run identities. A pending rotation blocks selection of another target.

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
semantic profiles run nightly and the full profiles run weekly. Both scheduled
workflows run `scripts/preflight_governance.py` with the selected interpreter
after dependency installation and before their first mutant. Do not bypass or
move that step: interpreter, virtualenv, manifest, syntax, source-lock, and
ownership defects belong at the cheap front door, not in mutant evidence.

## Distribution tests

Release verification resolves dependencies once into the committed
CPython-3.12/Linux-x86-64 hash lock and exact wheelhouse manifest. Both build
and verification install with `--no-index --require-hashes`, and build uses
`--no-isolation`. A clean wheel environment runs CLI, lite
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
6. Owner-dispatch the release authorization on exact certified main. A fresh
   hosted builder emits untrusted bytes; a different fresh hosted verifier
   installs and tests them from the closed wheelhouse.
7. Let the no-checkout trusted collector authenticate both runs and emit the
   sole output-only release receipt. Run provider inspection with publication
   disabled.
   The controller must reconstruct each authorization, build, verification, and
   receipt artifact from provider metadata; copied run IDs or digests never satisfy
   this step by themselves. It also parses `SHA256SUMS` and recomputes the exact wheel
   and source-archive digests before the trusted collector can issue a receipt.
   The authorizer independently hashes the downloaded controller wheel as well.
8. After owner approval, enable immutable releases and create one annotated
   unsigned `vX.Y.Z` tag at that exact commit.
9. The no-checkout publisher creates a draft, attaches and attests the
   pre-certified files, verifies their digests, and publishes without rebuild.
10. Re-fetch provider state and require an immutable, non-draft, exact release
    before recording closeout.

The tag event does not rebuild. The publisher checks out no repository code and
executes no candidate-provided script. Release publication remains disabled
during an authority migration; the old path is not a rollback option. If documentation included in the sdist
changes after certification, repeat exact-main certification and artifact
construction; supersede the older bytes instead of reusing their receipt. PyPI
is not used. All GitHub actions are pinned and release permissions are scoped
to the trusted publication job.

The BCF repository is itself standard-governed. Its generated governance
workflow and gate contracts must pass on the merge commit; a release tag never
turns older-tree evidence into current evidence.

# Lifecycle Walkthrough

This walkthrough demonstrates the BCF 1.1 lifecycle: bootstrap Lite, declare
Standard-v2 gates and semantic authority, promote transactionally, author
`completed`, and let exact evidence compute `verified` and `closed`.

## 1. Bootstrap Lite

The target must be the root of an initialized Git repository with a committed,
clean HEAD.

```bash
bcf install \
  --target /tmp/demo-governed-app \
  --profile lite \
  --project-id demo-governed-app \
  --project-name "Demo Governed App" \
  --product-name "Demo Governed App" \
  --date "$(date -u +%F)" \
  --require-strict-validation
```

Lite installs the inexpensive structural front door. It does not claim that
the repository's application operations or semantic families have been
classified.

## 2. Declare Standard Gates And Semantics

Create the complete Standard gate configuration described in
[Using BCF](../../docs/USAGE.md). Every gate uses exact argv, declared outputs
and environment, and a typed causal control. Do not embed shell pipelines or
copy test-node populations into the configuration.

Generate a non-authoritative semantic candidate:

```bash
bcf semantic-ownership scaffold \
  --repo-root /tmp/demo-governed-app \
  --output /tmp/demo-semantic-config.yml
```

Complete its unresolved family, public-operation, and secondary-representation
classifications. The scaffold is not evidence and cannot approve its own
contents. Preview the complete transaction before applying it:

```bash
bcf profile promote \
  --repo-root /tmp/demo-governed-app \
  --to standard \
  --contract-version 2.0 \
  --config /tmp/demo-standard-gates.yml \
  --semantic-config /tmp/demo-semantic-config.yml \
  --check

bcf profile promote \
  --repo-root /tmp/demo-governed-app \
  --to standard \
  --contract-version 2.0 \
  --config /tmp/demo-standard-gates.yml \
  --semantic-config /tmp/demo-semantic-config.yml \
  --apply
```

Promotion is monotonic and atomic. Missing classifications are reported
together before the repository is mutated.

## 3. Author Completion

After implementation, set the active phase plan and log status to `completed`,
set matching workitems to `DONE`, and set the ledger lifecycle to `completed`.
Do not author `verified`, `closed`, suite-health booleans, finding closure, or
release readiness; their schemas and deterministic evaluators own those claims.

Commit the completed tree before evidence capture.

## 4. Preflight, Capture, And Compute

Use the canonical release front door:

```bash
cd /tmp/demo-governed-app
make -f Makefile.fragment release-check
```

The generated target validates the clean committed HEAD, allocates one evidence
session, derives the required gate population from the gate contract, captures
each positive result and causal control once in isolated worktrees, and passes
that exact session to truth. There is no hand-built gate loop and no operator-
selected session path.

`bcf validate` answers whether authored governance is structurally legal.
`bcf truth` independently recomputes factual claims from schema-2 receipts.
Current evidence computes `verified`; reconciliation plus evidence-backed
finding closure computes `closed` and release readiness. Any governed-tree
change invalidates the receipts and returns effective state to `completed`.

# Lifecycle Walkthrough

This walkthrough demonstrates the BCF 0.6 lifecycle: bootstrap with the only
partial profile (`lite`), promote transactionally with a complete executable
gate contract, author `completed`, and let evidence compute `verified` and
`closed`.

## 1. Bootstrap Lite

The target must be the root of an initialized Git repository.

```bash
git -C /tmp/demo-governed-app init

bcf install \
  --target /tmp/demo-governed-app \
  --profile lite \
  --project-id demo-governed-app \
  --project-name "Demo Governed App" \
  --product-name "Demo Governed App" \
  --date "$(date -u +%F)" \
  --require-strict-validation
```

Lite generates exactly two mandatory gates—`governance-validate` and
`governance-exposure-scan`—with contained negative controls. It does not
generate `true` aliases or CI jobs for deferred standard gates.

## 2. Define And Check Standard Gates

Create `/tmp/demo-standard-gates.yml` with `schema_version: "1.0"`,
`target_profile: standard`, and a `gates` mapping for every non-built-in target
listed in `governance-profile.yml`. Each gate must contain:

```yaml
invocation:
  argv: [python3, scripts/run_gate.py, test]
  cwd: .
  env: {}
  required_env: []
evidence:
  kind: test_suite
  test_contract:
    junit_xml: .artifacts/junit/test.xml
    min_collected: 1
    min_executed: 1
    max_skipped: 0
negative_controls:
  - id: test-assertion-is-required
    mutation:
      path: tests/test_gate.py
      search: "EXPECTED = True"
      replace: "EXPECTED = False"
    oracle:
      kind: test_node_failure
      node_ids: [tests/test_gate.py::test_gate]
```

Use argv only. Complex behavior belongs in a tracked script. Production gates
also declare their non-secret environment, required environment names, output
artifacts, and environment assertions. Every control must identify the
specific expected diagnostic or test-node transition; an arbitrary nonzero
exit is not a valid oracle.

Preview promotion, then apply the exact reviewed transaction:

```bash
bcf profile promote \
  --repo-root /tmp/demo-governed-app \
  --to standard \
  --config /tmp/demo-standard-gates.yml \
  --check

bcf profile promote \
  --repo-root /tmp/demo-governed-app \
  --to standard \
  --config /tmp/demo-standard-gates.yml \
  --apply
```

Promotion is monotonic and does not regenerate or overwrite phase artifacts.
Any conflict or validation failure leaves the repository byte-identical.

## 3. Author Completion

After implementation, set the active phase log status to `completed`, set its
workitems and the matching plan workitems to `DONE`, and set the active ledger
lifecycle to `completed`:

```yaml
document:
  status: completed
```

Do not write `verified`, `closed`, `all_tickets_closed`, suite/health booleans,
or a release-ready status. Those assertions are computed and writable schema
fields for them do not exist.

Commit the completed governed tree before capturing evidence:

```bash
git -C /tmp/demo-governed-app add .
git -C /tmp/demo-governed-app commit -m "Complete governed phase"
```

## 4. Capture Evidence And Compute Truth

Capture every required gate into an ignored directory. Each command executes
the positive gate and every negative control in separate pristine detached
worktrees:

```bash
cd /tmp/demo-governed-app
for gate in $(python3 - <<'PY'
import yaml
payload = yaml.safe_load(open('governance/gate-contracts.yml', encoding='utf-8'))
print(' '.join(payload['gates']))
PY
); do
  bcf evidence run --gate "$gate" --output .artifacts/bcf
done

bcf validate --repo-root .
bcf truth --evidence-dir .artifacts/bcf --output .artifacts/bcf/truth-report.json
```

`bcf validate` answers whether governance artifacts are structurally legal.
`bcf truth` independently recomputes factual claims from schema-2.0 receipts.
Current evidence computes `verified`; current reconciliation plus balanced,
evidence-backed finding closure computes `closed` and release readiness.

Any staged, unstaged, or non-ignored untracked content prevents capture. Any
subsequent governed-tree change makes the receipts stale and returns effective
state to `completed`. Evidence produced by BCF 0.5 is intentionally rejected as
`unsupported_schema_version` and must be recaptured.

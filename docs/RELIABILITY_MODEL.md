# Reliability Model

This guide owns BCF's engineering failure model, verification economics,
common objections, and the measurements that could support or falsify its
central thesis. The [README](../README.md) provides the overview,
[Architecture](ARCHITECTURE.md) owns detailed design positions,
[CI authority](CI_AUTHORITY.md) owns provider-backed certification, and
[Using BCF](USAGE.md) owns operator procedures.

## Failure model

BCF is specifically designed to govern software production by probabilistic AI
agents. It is not a general human-led DevOps framework. BCF treats an agent as
a capable but probabilistic software producer. Better models may reduce error
frequency, but they do not make generation,
observation, or self-evaluation deterministic. Relevant failure modes include:

- reasoning from incomplete working context;
- architectural or responsibility drift across successive changes;
- competing representations, defaults, normalizers, or state transitions;
- tests that reproduce the same incorrect assumption as the implementation;
- gates that exist but are insensitive to the defect they claim to detect;
- test-population, workflow, or configuration drift;
- stale evidence presented as current evidence;
- incorrect run, attempt, session, or artifact association;
- lifecycle or release claims based on incomplete observations;
- hidden environmental state changing a result; and
- probabilistic synchronization of duplicated configuration.

BCF assumes that some such errors will occur. It surrounds the production
process with deterministic constraints and observations intended to make them
bounded, visible, or release-blocking. This is not a judgment about a model's
competence or intent.

## Redundant verification, single authority

BCF distinguishes deliberately redundant observations from duplicated
semantic authority. It may use several checks around one claim:

- tests challenge an implementation;
- causal negative controls challenge a detector;
- truth recomputes recorded observations;
- trusted code reconstructs provider state independently of candidate claims;
- hashes and a separate verifier challenge release artifacts; and
- workflow parity challenges rendered bytes against their graph owner.

These observations are useful only if the meaning of the claim has one owner.
SOIP, graph contracts, gate contracts, schemas, and generated projections are
designed to prevent each observer from inventing a competing definition. BCF
may therefore add execution while reducing independent sources of truth.

The analogy to checksums or error-correcting systems is limited but useful:
additional structured observations can expose disagreement. They do not prove
that the original specification describes the right product.

## Compute and attention

BCF deliberately spends compute on structural validation, behavioral tests,
causal controls, isolated worktrees, exact manifests, evidence sessions,
provider-state reconstruction, truth computation, artifact verification, and
scheduled controls. It also adds authoring and maintenance work for the
contracts that define those checks.

The framework attempts to control that cost:

- cheap deterministic preflight precedes expensive fanout;
- causal controls target declared invariants and exact failure oracles rather
  than unrestricted mutation volume;
- exact manifests reject empty or silently reduced test runs;
- independent lanes may fan out when the resource map permits it;
- expensive controls may remain scheduled instead of extending every PR;
- one evidence session prevents completed work from becoming ambiguous input;
  and
- graph changes may optimize setup and ordering while preserving controls.

The intended economic question is not whether verification is free. It is
whether its marginal cost is justified by lower expected defect, remediation,
audit, and human-reconstruction cost. Individual validation latency and
sustainable delivery throughput are different measures: BCF may increase the
former without necessarily improving the latter.

## Common objections

### This is too much ceremony

It can be. Low-risk, low-throughput repositories may not justify Standard or
Regulated controls. Lite provides a smaller bootstrap. Stronger profiles cost
more because they represent and test more claims. As generation throughput
rises beyond a reviewer's ability to reconstruct every change, explicit state
can replace some repeated reconstruction; that does not make it free.

### This wastes compute

BCF intentionally performs work that a conventional pipeline may omit. The
relevant comparison includes escaped defects, remediation, audit effort, and
human attention—not runner minutes alone. BCF does not yet claim a universal
positive return on this trade, and controls that provide no distinct evidence
should be removed rather than defended as assurance.

### Why not use a better model?

Model improvements should reduce how often controls fire. They do not convert
probabilistic generation into deterministic authority, remove context limits,
or guarantee that implementation and tests do not share a mistaken assumption.
The controls make correctness less dependent on consistent model behavior,
including when models or providers change.

### Why not rely on human review?

Human review remains necessary for intent, architecture, risk appetite,
exceptions, and merge decisions. BCF moves mechanically decidable
reconstruction away from scarce reviewer attention: automate what machines can
prove so people can concentrate on what machines cannot.

### Does BCF force one architecture?

BCF is intentionally opinionated because ambiguity and weak ownership add
reliability cost in agent-led work. Profiles, project configuration, and graph
extensions preserve scope and specialized topology. Choosing not to enforce a
boundary is valid, but it also removes that part of the error-correction model.
The defaults are reliability biases, not assertions of universal superiority.

### Are thresholds arbitrary?

Module and context budgets are heuristics, not laws. A visible, configurable
threshold is mechanically testable and can be evaluated with repository data;
an implicit judgment that a module feels too large cannot. Teams should adjust
thresholds when evidence supports a different boundary.

### Will mutation testing make CI enormous?

BCF's causal negative controls are narrower than unrestricted mutation
testing. They ask whether a gate that claims to protect invariant X rejects a
declared violation of X for the expected reason. A missing dependency, timeout,
signal, unrelated failure, or red positive baseline is not successful negative
evidence. Broader mutation profiles can remain scheduled.

### Is this another configuration language?

BCF adds machine-readable artifacts. Much of their content otherwise exists
implicitly across workflows, scripts, conventions, prompts, repository
settings, and reviewer memory. Canonical ownership and deterministic
projections can add files while reducing independently maintained definitions.

### Is this only policy-as-code?

Policy is one component. BCF also asks what exact subject was observed, which
run and attempt produced the evidence, whether the detector is sensitive to its
claimed failure, whether evidence is stale, who may author a state, and which
lifecycle conclusion follows. It combines policy, evidence, provenance,
causal controls, and computed claims.

### Does a green run prove correctness?

No. It proves only the declared claims supported by the accepted inputs and
rules for that subject. BCF cannot discover an omitted requirement, prove
arbitrary business correctness, prove that no vulnerability exists, or repair
wrong intent. SOIP demonstrates structural ownership, not semantic correctness.

### Can an agent change the controls too?

Tests, contracts, governance files, workflow definitions, and evidence policy
are themselves governed surfaces; changing them invalidates relevant evidence
and must satisfy the resulting contracts. A deeper boundary remains: if one
authority may redefine intent, implementation, tests, and policy together,
internal consistency cannot establish the original intent. Independent intent,
acceptance, or review authorities are appropriate when that risk matters.

### Will agents spend their time fighting constraints?

Some rejection is intentional. A constraint that never rejects a declared
violation contributes little evidence. The useful measure is whether early,
specific rejection prevents a more expensive defect from progressing, and
whether false positives remain acceptably low.

## Empirical question

BCF's compute-for-quality proposition is an engineering hypothesis, not a
published universal result:

> How much additional compute and validation latency buys how much reduction
> in escaped defects, architectural drift, remediation effort, and human
> reconstruction?

Repository-specific measurement could include runner minutes per accepted
change, wall-clock validation latency, remediation iterations, preflight and
causal-control rejection rates, pre-merge architecture findings, escaped
regressions, reviewer reconstruction time, false-positive rates, evidence
recapture frequency, defect severity, and remediation cost.

These measures should be interpreted together. Optimizing only wall time can
remove useful observations; optimizing only control count can create expensive
work with no distinct claim. BCF supplies mechanisms for such evaluation but
does not currently publish a controlled comparative result.

## Limits

BCF does not make a probabilistic producer deterministic. It makes selected
constraints and observations deterministic. Its assurance is bounded by the
completeness and correctness of requirements, contracts, detectors, evidence,
provider data, and human decisions. It also introduces maintenance, compute,
latency, storage, architecture, and adoption costs.

Use the least costly profile that represents the claims the repository must
make. A repository for which those claims do not justify the cost should not
adopt stronger controls merely for consistency with BCF's defaults.

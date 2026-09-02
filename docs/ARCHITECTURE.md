# Architecture

This guide explains BCF's design positions. The [README](../README.md) gives the
short rationale, [Using BCF](USAGE.md) owns operator procedures, and
[CI authority](CI_AUTHORITY.md) owns provider-backed certification. The
[Reliability model](RELIABILITY_MODEL.md) owns the failure model, verification
economics, common objections, and empirical measures.

BCF's architectural defaults are reliability biases for probabilistic software
production, not claims of universal optimality. They exchange some flexibility
for properties that deterministic programs can observe: bounded context,
explicit ownership, directed dependencies, and thin boundaries. A repository
chooses the applicable controls and may configure their thresholds.

## Authority model

BCF separates proposals, recorded facts, and computed conclusions. People,
agents, services, and workflows may produce changes or evidence according to
their declared roles. Only deterministic code evaluates structural legality,
evidence currency, and lifecycle state. Human authority remains explicit for
product choices, accepted risk, and approvals that cannot be mechanically
derived.

This boundary is useful in AI-led work because a model can generate a plausible
claim without having observed every relevant fact. It also avoids asking the
same actor to implement and certify a change. The cost is additional policy,
evidence, and role configuration; deterministic evaluation is only as sound as
its inputs and rules.

## CQRS-lite

BCF uses a small command/query separation:

- commands such as install, promote, cleanup, scaffold, and evidence capture
  may change state;
- queries such as validate, doctor, exposure scan, semantic ownership, and
  computed truth inspect state;
- a query does not repair the condition it reports.

This is CQRS-lite: it does not require event sourcing, a message bus, or
separate databases. The split makes side effects visible and supports dry-run
transactions. It also makes mutation versus observation mechanically
distinguishable, reducing the chance that a query quietly acquires side effects
during an agent-authored change. The split creates interfaces that a smaller
project might otherwise combine.

## Single semantic ownership

SOIP assigns each governed representation one canonical owner and construction
path. A representation may be a state enum, normalized identifier, workflow
identity, default, projection, or language-boundary translation. Consumers
refer to that owner instead of independently decoding or normalizing it.

The source-first scanner inventories tracked types before loading the registry,
then evaluates declared ownership and causal paths. Standard v2 blocks declared
families; Regulated can require repository-wide completeness. Optional
TypeScript analysis uses the consumer's locked compiler and configuration and
does not download tools or fall back to Docker.

SOIP is structural evidence. It can expose competing owners and unresolved
flows, but it cannot determine whether a single owner implements the intended
business rule. Maintaining the registry and language-boundary declarations is
the principal adoption cost.

Single layer and bounded-context membership apply the same bias to
responsibility. Thin adapters and routers keep business decisions out of
transport and infrastructure edges, while explicit dependency direction makes
cross-boundary drift testable. Shared-abstraction constraints discourage a new
helper for every local need: reuse must follow a declared common concept rather
than superficial similarity. These constraints reduce semantic reinvention but
can require refactoring or limited duplication until a stable abstraction is
known.

## Mechanical and negative testing

BCF prefers a deterministic test when an invariant can be evaluated from
versioned inputs. Examples include exact test populations, module budgets,
workflow graphs, action pins, artifact namespaces, cleanup roots, and source
locks. Narrative review remains useful for intent and ambiguous risk, but it
does not replace a repeatable check.

A required gate also carries at least one causal negative control. The control
applies a declared mutation in an isolated worktree and passes only when the
responsible node or diagnostic fails for the declared cause. Missing tools,
timeouts, signals, syntax errors, unrelated failures, and a red positive
baseline are infrastructure or test failures—not successful controls.

Negative controls consume compute and can become brittle when they target
incidental syntax. BCF favors authoritative, early mutations and exact failure
nodes to keep that cost bounded.

## Exact evidence and computed lifecycle

Schema-2 receipts bind invocation, environment, outputs, raw process material,
commit, tree, execution tree, cleanliness, and negative-control observations.
Profile-v2 sessions additionally bind producer, provider run, attempt, profile,
and the expected gate inventory. Truth recomputes observations rather than
trusting the receipt's reported result.

Authors report only `planned` or `completed`. `verified`, `closed`, and release
readiness are computed for the current subject. This avoids retroactive claims
and makes invalidation explicit. It also means meaningful changes require new
evidence even when their content resembles a previously certified tree.

## Fail-fast and bounded execution

The canonical cheap preflight checks deterministic repository defects before
evidence fanout. It validates clean committed state, source locks, exact test
manifests, workflow and architecture ownership, line budgets, applicable SOIP,
syntax, and artifact namespace separation. Expensive integration and runtime
gates still run after preflight; a green preflight is not release evidence by
itself.

Selected-environment declarations follow the same ownership rule. Project,
build-system, optional, and gate-specific requirements compile into one bootstrap
projection; preflight compares its exact bytes with the canonical plan before checking
the interpreter. This adds a generated file and regeneration step, but removes an
operator-maintained dependency list and prevents build-isolation side effects from
deciding whether later jobs happen to work.

Implementation modules have declared size and context budgets. Bounded modules
reduce the chance that a producer reasons from only part of a concept. The
thresholds are configurable, measurable heuristics rather than universal
optima. They make complete review more likely for both people and agents, but
occasionally require a concept to be split across a stable private boundary.

## CI graph as a compiled contract

BCF separates CI intent from provider syntax. `governance/ci-graph.yml` owns
the common graph and registers every project extension by path and digest. The
compiler resolves defaults and declared value sources once, composes extensions
at typed attachment points, validates graph and trust invariants, and only then
renders GitHub workflow bytes.

This is the same authority boundary used elsewhere in BCF: an agent may propose
a graph edit, but it does not become correct because the generated YAML looks
plausible. Deterministic checks own cycles, reachability, gate uniqueness,
resource mapping, trust compatibility, evidence fan-in, artifact namespaces,
single main-push authority, and hosted-wait prohibition. A generated-file hash
header supplies provenance, while exact workflow authority separately pins the
committed provider bytes used for certification.

Extensions preserve application-specific topology. They may add jobs,
workflows, dependencies, artifacts, and bounded executors; they may not insert
raw YAML, duplicate semantic owners, or weaken preflight, truth, permissions,
runner trust, or cleanup. This adds a compiler and extension schema to CI
maintenance. In return, graph customization stays explicit without asking an
agent or maintainer to synchronize derived workflow files manually.

## Profiles and scope

Lite provides inexpensive bootstrap checks. Standard v2 blocks declared SOIP
families and requires complete executable gate contracts. Regulated adds
repository-wide and cryptographic requirements. Typed N/A records describe a
genuinely absent optional capability with scope, evidence, approval, subject,
and expiry; they do not waive a release dependency that is actually in use.

BCF profiles establish governance semantics, not a universal application
topology. A consumer retains its architecture, CI partition, runner capacity,
and product-specific gates unless it explicitly adopts a generated capability.

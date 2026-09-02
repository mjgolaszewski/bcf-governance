# Editorial Review Checklist

This checklist records the current documentation review. It is non-authoritative:
mechanical validation and exact-main certification determine repository and
release state.

- [x] README identifies BCF as a deterministic error-correction framework
  specifically for software produced by probabilistic AI agents and does not
  present human-led development as a design target.
- [x] Trusted automation is described as bounded deterministic service
  authority, not AI authority, approval, or merge authority.
- [x] The Design thesis states the failure model, response sequence, concise
  failure-mode map, authority boundary, and proof limit.
- [x] Each position includes a cost or limitation.
- [x] Reliability model, architecture, CI authority, usage, maintenance, and
  installed operations have distinct canonical responsibilities.
- [x] Redundant verification is distinguished from duplicated semantic
  authority.
- [x] Compute cost and individual-change latency are acknowledged without an
  unsupported productivity or return-on-investment claim.
- [x] Common objections and the falsifiable empirical question are addressed in
  the reliability model rather than duplicated across operator guides.
- [x] Requirements are distinguished from recommendations; absolute wording is
  reserved for enforced contracts and security boundaries.
- [x] Workflow display names are described as presentation, not identity.
- [x] CI state flow and the trust boundary are represented in a diagram and
  table.
- [x] CLI and release examples use the exact package-versioned GitHub Release
  URL and identify GitHub Releases as the supported distribution channel.
- [x] Local links and anchors resolve.
- [x] Adoption, cleanup, hotfix, model-risk, and walkthrough documents remain
  focused branches of the canonical guides.
- [x] Hype, moral framing, anthropomorphic claims, and unnecessarily dramatic
  language were removed.
- [x] Generated template and packaged copies are checked for byte parity.

# Model Risk and Provenance

`{{PROJECT_NAME}}` uses the regulated BCF profile only when `governance/gate-contracts.yml`
contains trusted verifier keys and permitted risk authorities. Evidence producers, reviewers,
remediators, and verifiers are recorded as typed actors. Critical and High finding closure
requires an independently verifiable behavioral proof and a verifier distinct from the
producer and remediator.

Evidence receipts and truth reports are content addressed, exact-tree bound, and retained
outside the governed tree. A trusted detached DSSE/Ed25519 attestation is required for a
regulated closeout. Risk acceptance is valid only when its authority ID appears in the
canonical evidence policy generated from the regulated profile configuration.

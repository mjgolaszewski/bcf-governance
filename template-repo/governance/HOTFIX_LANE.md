# Regulated Hotfix Lane

Hotfixes remain authored as `planned` or `completed`; `verified` and `closed` are computed.
Every hotfix must bind its required gates, finding registry, reconciliation evidence, and
detached regulated attestation to the same commit and tree as the release candidate.

Emergency implementation does not waive finding accounting, independent Critical/High
verification, negative controls, or exact-tree evidence. Merge-back changes invalidate the
hotfix evidence and require recapture before release.

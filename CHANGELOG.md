# Changelog

All notable changes to BCF Governance are recorded here. This file follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Opened the BCF 0.7.0 release train for generalized SOIP, exact-commit CI
  authority, disposable candidate execution, Standard-v2 self-adoption, and
  certified immutable release artifacts.

### Fixed

- Made the explicitly selected Python interpreter authoritative in positive and
  detached negative-control evidence sessions, including the loader environment
  required by toolcache Python installations, without changing canonical gate
  argv or schema-2 receipt compatibility.

### Security

- Defined a hard separation between one-job disposable candidate workers and a
  persistent trusted control plane that never checks out or executes candidate
  code.
- Added a time-bounded owner-only local-runner fallback for exhausted hosted
  credits, with fork PR admission rejected before allocation and privileged
  release publication disabled while the pool is shared.
- Protected `main` with pull-request-only updates, current governance checks,
  resolved conversations, and force-push/deletion prevention.

## [0.6.1] - 2026-08-14

### Added

- Made `README.md`, `LICENSE`, and `CHANGELOG.md` standard required governed
  artifacts with closed schema, semantic contract enforcement, and
  preserve-existing installation behavior.
- Required every pull request to update `CHANGELOG.md`, enforced against the
  exact PR base SHA by generated governance CI and contract tests.
- Put the BCF source repository under its own standard governance profile with
  executable gate contracts and schema-2 evidence.

### Changed

- Consolidated duplicated governance guidance and removed stale lifecycle,
  adoption, upgrade, and release instructions.
- Made repository-specific evidence gates bootstrap the isolated source checkout
  without relying on an ambient editable installation.
- Scoped pull-request changelog enforcement to an explicit, semantically
  validated CI contract so nested test repositories remain hermetic.

## [0.6.0] - 2026-08-14

### Added

- Added manifest-scoped transactional installation, monotonic profile
  promotion, exact-tree isolated evidence execution, and typed behavioral
  controls.
- Added schema-2 receipts, computed lifecycle consistency, profile-derived
  applicability, finding provenance, and artifact-level release verification.

### Changed

- Moved packaged implementation under `bcf_governance` and left root scripts as
  source-compatible thin wrappers.
- Made mutation profiles baseline-aware with explicit killer test nodes.

### Removed

- Removed unsafe `bcf install --force`, legacy `--gate-command`, and acceptance
  of BCF 0.5 evidence bundles.

## [0.5.0] - 2026-08-12

### Added

- Introduced evidence-backed computed `verified` and `closed` lifecycle states,
  truthfulness reports, exact-tree invalidation, finding accounting, and
  evidence semantic mutants.

[Unreleased]: https://github.com/mjgolaszewski/bcf-governance/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/mjgolaszewski/bcf-governance/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/mjgolaszewski/bcf-governance/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/mjgolaszewski/bcf-governance/releases/tag/v0.5.0

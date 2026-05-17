---
source: mixed
---
# Changelog

All notable changes to `arbiter` are recorded here.

## [Unreleased]

## [2.0.1] — 2026-05-17

### Changed

- Bumped Converge floor to `3.9.1` (`converge-core`, `converge-pack`).
- Migrated Arbiter `ProposedFact` provenance to the `converge-pack`
  `ProvenanceSource` trait; removed the per-crate provenance vocabulary.
- Removed per-crate `suggestor_span`; the engine now emits the
  `arbiter.suggestor.execute` span itself.
- Dropped stale `[patch.crates-io]` bedrock-platform overrides from CI.

## [2.0.0] — 2026-05-17

(Committed 2026-05-15 as Arbiter v2.0.0 tag; first crates.io publish on
2026-05-17 together with v2.0.1.)

### Added

- Typed `FactPayload` support for Cedar Analysis input, plan, and report
  payloads so Arbiter analysis no longer depends on string-content
  proposal payloads in process.
- `CedarAnalysisBackend` and `LocalCvc5AnalysisBackend` for optional
  solver-backed Cedar Analysis without making CVC5 a required CI
  dependency.
- Model-adequacy review material for the expense / non-finance
  high-value commit invariant.

### Changed

- **BREAKING:** `CedarAnalysisReport` now uses payload family version `2`
  and carries a required `ExecutionIdentity` describing the SymCC/CVC5
  execution backend.
- Cedar Analysis proposal construction now emits typed plan/report
  payloads and preserves solver execution identity as promotion evidence.
- Cedar Analysis structs now use strict `serde` field validation at the
  typed payload boundary.

## [1.1.1] — 2026-05-14

Converge 3.8.1 policy foundation; see root `CHANGELOG.md` for full details.

## [1.1.0] — 2026-05-07

Cargo package renamed from `arbiter` to `converge-arbiter-policy`;
internal clippy cleanups.

## [1.0.0] — 2026-05-05

Initial extension release; extracted from `converge/crates/policy` per
[ADR-008](https://github.com/Reflective-Lab/converge/blob/main/kb/Architecture/ADRs/ADR-008-extension-crate-boundaries.md).

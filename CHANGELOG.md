# Changelog

All notable changes to arbiter will be documented in this file.

## [Unreleased]

## [2.0.1] - 2026-05-17

### Changed

- Bumped Converge floor to `3.9.1` (`converge-core`, `converge-pack`).
- Migrated Arbiter `ProposedFact` provenance to the `converge-pack`
  `ProvenanceSource` trait; removed the per-crate provenance vocabulary.
- Removed per-crate `suggestor_span`; the engine now emits the
  `arbiter.suggestor.execute` span itself.
- Dropped stale `[patch.crates-io]` bedrock-platform overrides from CI.

## [2.0.0] - 2026-05-15

### Added

- Added typed `FactPayload` support for Cedar Analysis input, plan, and report
  payloads so Arbiter analysis no longer depends on string-content proposal
  payloads in process.
- Added `CedarAnalysisBackend` and `LocalCvc5AnalysisBackend` for optional
  solver-backed Cedar Analysis execution without making CVC5 a required CI
  dependency.
- Added model-adequacy review material for the expense/non-finance high-value
  commit invariant.

### Changed

- **BREAKING:** `CedarAnalysisReport` now uses payload family version `2` and
  carries a required `ExecutionIdentity` describing the SymCC/CVC5 execution
  backend.
- Cedar Analysis proposal construction now emits typed plan/report payloads and
  preserves solver execution identity as promotion evidence.
- Cedar Analysis structs now use strict `serde` field validation at the typed
  payload boundary.

## [1.1.1] - 2026-05-14

### Added

- Added Formation-facing Arbiter capability descriptors under the stable
  `arbiter.cedar` family, including `arbiter.cedar.policy_gate`,
  `arbiter.cedar.hitl_gate`, and `arbiter.cedar.analysis_evidence`.
- Added `CedarHitlGateSuggestor` as the explicit strict Cedar-backed HITL gate
  registration point for Formations.
- Added `arbiter.suggestor.execute` tracing spans around Arbiter suggestor
  execution boundaries with provenance, suggestor name, context key, and input
  count fields.
- Added `ProvenanceSource`, a typed extension provenance vocabulary, and routed
  Arbiter `ProposedFact` creation through `ProvenanceSource::Arbiter`.
- Added an ignored real-CVC5 Cedar Analysis smoke test plus scheduled/manual CI
  wiring; required CI continues to use fake-solver SymCC tests.
- Added the conditional `ExpenseNonFinanceHighValueCommitDenied` Cedar Analysis
  query for the high-risk expense invariant.

### Changed

- Tightened HITL escalation: Arbiter now returns `Escalate` only when Cedar
  would allow the same request with `human_approval_present = true`; hard
  policy denials remain `Reject`.
- Replaced raw Arbiter provenance strings in suggestor proposal construction
  with the typed provenance adapter.
- Rate-limit gate tracing now emits the same `input_key` and `output_key`
  fields as other Arbiter suggestor spans.
- Release profiling now skips Criterion baseline generation cleanly when no
  benchmark targets are configured.

## [1.1.0] - 2026-05-07

### Changed

- Cargo package renamed from `arbiter` to `converge-arbiter-policy`; Rust
  library and binary names remain `arbiter`.
- Internal clippy cleanups: collapsed nested `if let` chains using
  let-chains and replaced empty-string conversions with `String::new()`.

## [1.0.0] - 2026-05-05

### Added

Initial release. Extracted from `converge/crates/policy` as a Converge
extension per [ADR-008](https://github.com/Reflective-Lab/converge/blob/main/kb/Architecture/ADRs/ADR-008-extension-crate-boundaries.md).

- Cedar-based Policy Decision Point
- `PolicyGate`, `FlowGate`, `DelegationVerify` suggestors
- ed25519-signed delegation tokens
- HTTP service binary (`arbiter`)
- Data classification with regex-based redaction

### Changed

- Crate renamed from `converge-policy` to `arbiter`
- Library name renamed from `converge_policy` to `arbiter`
- Binary renamed from `converge-policy` to `arbiter`

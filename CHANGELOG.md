# Changelog

All notable changes to arbiter will be documented in this file.

## [Unreleased]

### Added

- Added Formation-facing Arbiter capability descriptors under the stable
  `arbiter.cedar` family, including `arbiter.cedar.policy_gate`,
  `arbiter.cedar.hitl_gate`, and `arbiter.cedar.analysis_evidence`.
- Added `CedarHitlGateSuggestor` as the explicit strict Cedar-backed HITL gate
  registration point for Formations.

### Changed

- Tightened HITL escalation: Arbiter now returns `Escalate` only when Cedar
  would allow the same request with `human_approval_present = true`; hard
  policy denials remain `Reject`.

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

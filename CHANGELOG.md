# Changelog

All notable changes to arbiter will be documented in this file.

## [Unreleased]

### Changed

- Cargo package renamed from `arbiter` to `converge-arbiter-policy`; Rust
  library and binary names remain `arbiter`.

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

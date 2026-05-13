---
tags: [architecture, surface]
source: mixed
---
# Surface

`arbiter` exposes one canonical published crate,
`converge-arbiter-policy`, with Rust library name `arbiter`.

## Public surface

- `PolicyEngine` — Cedar policy evaluation engine.
- `PolicyGateSuggestor` — runtime Cedar decision suggestor over
  `DecideRequest`.
- `FlowGateSuggestor` — flow-level Cedar authorization suggestor.
- `CedarHitlGateSuggestor` — explicit strict Cedar-backed HITL suggestor for
  Formations.
- `DelegationVerifySuggestor` — Ed25519 delegation verification suggestor.
- `CedarAnalysisInput`, `CedarAnalysisPlan`, and `CedarAnalysisReport` under
  the `analysis` feature — offline Cedar Analysis evidence.
- `formation_capabilities()` — Formation-facing capability catalog for
  `arbiter.cedar`.

## Formation capability IDs

- `arbiter.cedar.policy_gate`
- `arbiter.cedar.hitl_gate`
- `arbiter.cedar.analysis_evidence`

## Contract dependencies

- `converge-pack` — `Suggestor`, context facts, and promotion records.
- `converge-core` — stable flow gate vocabulary and `FlowGateAuthorizer`.

## Forbidden imports

Per [Extension Release Checklist §1](https://github.com/Reflective-Lab/converge/blob/main/kb/Standards/Extension%20Release%20Checklist.md):

- No imports of `converge-core` internals.
- No imports of foundation `runtime`, `provider`, or transport crates.
- No re-exports of foundation types except those promised stable.

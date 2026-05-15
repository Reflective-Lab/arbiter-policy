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
- `CedarAnalysisSuggestor` under the `analysis` feature — Converge suggestor
  for searched Cedar Analysis evidence.
- `CedarAnalysisBackend` under the `analysis` feature — backend trait for
  caller-supplied SymCC solver execution.
- `LocalCvc5AnalysisBackend` under the `analysis` feature — local `cvc5`
  process backend for manual/scheduled solver checks.
- `EXPENSE_NON_FINANCE_HIGH_VALUE_COMMIT_CLAIM_POLICY` under the `analysis`
  feature — reviewable Cedar policy that encodes the first conditional claim
  space.
- `CedarAnalysisInput`, `CedarAnalysisPlan`, and `CedarAnalysisReport` v2 under
  the `analysis` feature — typed offline Cedar Analysis evidence payloads.
  Reports include shared Converge `ExecutionIdentity` metadata.
- `CostEstimatePayload`, `ApprovalRiskPayload`, `ComplianceDocumentPayload`,
  and the gate constraint payloads — typed in-loop policy-gate payloads used
  instead of semantic JSON strings.
- `formation_capabilities()` — Formation-facing capability catalog for
  `arbiter.cedar`.
- `ProvenanceSource` — typed extension provenance vocabulary used before
  converting to `converge-pack::Provenance` at proposal construction.

## Observability

Arbiter suggestors emit an `arbiter.suggestor.execute` tracing span at the
execution boundary. The `provenance` field is derived from
`ProvenanceSource::Arbiter`. Current fields are:

- `provenance`
- `suggestor`
- `input_key`
- `output_key`
- `input_count`

## Formation capability IDs

- `arbiter.cedar.policy_gate`
- `arbiter.cedar.hitl_gate`
- `arbiter.cedar.analysis_evidence`

`arbiter.cedar.analysis_evidence` maps to `CedarAnalysisSuggestor` with
suggestor name `cedar-analysis`. It emits `Searched` evidence and does not
promote facts directly.

## Contract dependencies

- `converge-pack` — `Suggestor`, context facts, and promotion records.
- `converge-core` — stable flow gate vocabulary and `FlowGateAuthorizer`.

## Forbidden imports

Per [Extension Release Checklist §1](https://github.com/Reflective-Lab/converge/blob/main/kb/Standards/Extension%20Release%20Checklist.md):

- No imports of `converge-core` internals.
- No imports of foundation `runtime`, `provider`, or transport crates.
- No re-exports of foundation types except those promised stable.

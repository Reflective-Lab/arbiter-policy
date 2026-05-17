---
source: mixed
---
# Milestones

> See `~/dev/reflective/stack/bedrock-platform/EPIC.md` for the coarse-grained outcomes these milestones advance.

## Shipped: v2.0.1 — Converge 3.9.1 alignment (2026-05-17)

**Tracks:** Converge 3.9.1

- [x] Bump workspace `converge-core` / `converge-pack` deps to `3.9.1`.
- [x] Drop stale `[patch.crates-io]` bedrock-platform overrides from CI.
- [x] Migrate Arbiter `ProposedFact` provenance to the `converge-pack`
  `ProvenanceSource` trait (no per-crate provenance vocabulary).
- [x] Remove per-crate `suggestor_span`; rely on the engine-emitted
  `arbiter.suggestor.execute` span.
- [x] Clean `just release-check` run.
- [x] Tag and publish `converge-arbiter-policy@2.0.1` to crates.io.

## Shipped: v2.0.0 — Cedar analysis ExecutionIdentity (2026-05-17)

**Tracks:** Converge 3.8.1 (committed 2026-05-15, published 2026-05-17)

- [x] **BREAKING:** `CedarAnalysisReport` family version `2`, with a required
  `ExecutionIdentity` describing the SymCC/CVC5 execution backend.
- [x] Typed `FactPayload` boundary for Cedar Analysis input, plan, and report
  payloads (no string-content proposal payloads in process).
- [x] `CedarAnalysisBackend` + `LocalCvc5AnalysisBackend` for optional
  solver-backed Cedar Analysis without CVC5 as a required CI dependency.
- [x] Model-adequacy review material for the expense / non-finance
  high-value commit invariant.
- [x] Strict `serde` field validation at the typed payload boundary.

## Historical: v1.1.1 — Converge 3.8.1 Policy Foundation (2026-05-14)

**Tracks:** Converge 3.8.1

- [x] Keep workspace package version at `1.1.1`.
- [x] Keep Converge dependencies on the `3.8.1` contract baseline.
- [x] Adopt Extension Release Checklist (security-audit, coverage, performance-profile, soak)
- [x] Add the first Cedar-first invariant fixture and runtime regression test.
- [x] Plan the Cedar 4.x upgrade required before adding `cedar-policy-symcc`.
- [x] Upgrade Arbiter from Cedar 2.4 to Cedar 4.10.
- [x] Add Formation-facing `arbiter.cedar` capability descriptors and the
  explicit `CedarHitlGateSuggestor` surface.
- [x] First clean `just release-check` run
- [x] Tag v1.1.1

## Next: Cedar Analysis Lane

**Target:** after the Cedar 4.10 evaluator upgrade

- [x] Add the first schema artifact for the expense reference policy.
- [x] Add optional Cedar Analysis preparation backed by `cedar-policy-symcc`.
- [x] Emit pinned preparation artifacts: policy hash, schema hash, query hash,
  Cedar version, and SymCC version.
- [x] Add solver execution and counterexample capture for selected invariants.
- [x] Emit full analysis artifacts: solver status and counterexample details.
- [x] Wire high-risk policy invariants into required CI through fake-solver
  SymCC tests that do not need local CVC5.
- [x] Add ignored real-CVC5 smoke tests for solver-path compatibility.
- [x] Add conditional invariant queries for actual Arbiter claims before real
  CVC5 results are treated as invariant assurance.
- [ ] Add scheduled/manual Arbiter CI that installs or points to `cvc5` and
  runs the ignored real-CVC5 smoke tests.
- [ ] Revisit custom Lean only for claims Cedar Analysis cannot express.

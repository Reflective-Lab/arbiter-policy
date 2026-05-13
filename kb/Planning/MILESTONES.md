---
source: mixed
---
# Milestones

> See `~/dev/reflective/stack/bedrock-platform/EPIC.md` for the coarse-grained outcomes these milestones advance.

## Current: v1.0.0 — Converge 3.8.1 Policy Foundation

**Target:** 2026-05 | **Tracks:** Converge 3.8.1

- [ ] Keep workspace package version at `1.0.0`.
- [ ] Keep Converge dependencies on the `3.8.1` contract baseline.
- [ ] Adopt Extension Release Checklist (security-audit, coverage, performance-profile, soak)
- [x] Add the first Cedar-first invariant fixture and runtime regression test.
- [x] Plan the Cedar 4.x upgrade required before adding `cedar-policy-symcc`.
- [x] Upgrade Arbiter from Cedar 2.4 to Cedar 4.10.
- [x] Add Formation-facing `arbiter.cedar` capability descriptors and the
  explicit `CedarHitlGateSuggestor` surface.
- [ ] First clean `just release-check` run
- [ ] Tag v1.0.0

## Next: Cedar Analysis Lane

**Target:** after the Cedar 4.10 evaluator upgrade

- [x] Add the first schema artifact for the expense reference policy.
- [x] Add optional Cedar Analysis preparation backed by `cedar-policy-symcc`.
- [x] Emit pinned preparation artifacts: policy hash, schema hash, query hash,
  Cedar version, and SymCC version.
- [x] Add solver execution and counterexample capture for selected invariants.
- [x] Emit full analysis artifacts: solver status and counterexample details.
- [ ] Wire high-risk policy invariants into CI.
- [ ] Revisit custom Lean only for claims Cedar Analysis cannot express.

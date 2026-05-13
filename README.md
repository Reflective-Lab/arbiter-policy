# arbiter

[![CI](https://github.com/Reflective-Lab/arbiter-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/Reflective-Lab/arbiter-policy/actions/workflows/ci.yml)
[![Coverage](https://github.com/Reflective-Lab/arbiter-policy/actions/workflows/coverage.yml/badge.svg)](https://github.com/Reflective-Lab/arbiter-policy/actions/workflows/coverage.yml)
[![Security](https://github.com/Reflective-Lab/arbiter-policy/actions/workflows/security.yml/badge.svg)](https://github.com/Reflective-Lab/arbiter-policy/actions/workflows/security.yml)
[![Stability](https://github.com/Reflective-Lab/arbiter-policy/actions/workflows/stability.yml/badge.svg)](https://github.com/Reflective-Lab/arbiter-policy/actions/workflows/stability.yml)
[![Crates.io](https://img.shields.io/crates/v/converge-arbiter-policy.svg)](https://crates.io/crates/converge-arbiter-policy)
[![docs.rs](https://docs.rs/converge-arbiter-policy/badge.svg)](https://docs.rs/converge-arbiter-policy)
[![dependency status](https://deps.rs/repo/github/Reflective-Lab/arbiter-policy/status.svg)](https://deps.rs/repo/github/Reflective-Lab/arbiter-policy)
![MSRV](https://img.shields.io/badge/MSRV-1.94.0-blue)
<img alt="gitleaks badge" src="https://img.shields.io/badge/protected%20by-gitleaks-blue">
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Cedar-backed authorization gates for Converge formations.

`arbiter` is a Converge extension. It keeps policy implementation, Cedar
evaluation, delegation verification, and authorization suggestors outside the
Converge foundation while still using Converge's shared contracts for
in-loop behavior.

Cargo package: `converge-arbiter-policy`. Rust library and binary names remain
`arbiter`.

## Why It Exists

Converge owns the governed promotion path. Arbiter answers a narrower question:
should this proposed action, flow transition, delegation, budget use, or data
movement be allowed under policy?

That lets policy participate as a first-class suggestor without turning the
Converge kernel into a policy engine.

## What Arbiter Owns

- Cedar policy parsing and evaluation.
- Cedar-first policy assurance through validator results, runtime regression
  tests, and planned symbolic analysis.
- Policy decision and outcome types.
- Policy, flow, delegation, rate-limit, budget, approval, data-classification,
  and compliance gate suggestors.
- Formation-facing capability descriptors for Cedar runtime gates and offline
  analysis evidence.
- Structured `arbiter.suggestor.execute` tracing spans at suggestor execution
  boundaries.
- `ProvenanceSource`, a typed extension provenance vocabulary used at Arbiter's
  proposal boundary.
- Ed25519-signed delegation tokens.
- Reference Cedar policies for expense approval, flow governance, and vendor
  selection.

## Boundary

| Layer | Responsibility |
|---|---|
| Converge | Suggestor contract, context, promotion authority, shared gate vocabulary. |
| Arbiter | Cedar wiring, policy decisions, delegation verification, reusable policy gates. |
| Products | Concrete production policies, rollout controls, keys, audit retention, and deployment. |

If a type is a reusable policy contract for all Converge users, promote it
upstream. If it is a Cedar implementation detail or policy-gate behavior, keep
it here.

## Cedar Analysis Direction

Arbiter should use more of Cedar before adding a separate Lean, Coq, or Agda
verification layer. Runtime decisions are ordinary policy provenance; symbolic
analysis results are high-assurance search evidence; only checked proof
artifacts should be labeled formal verification.

The first Arbiter assurance lane is:

```text
Gherkin invariant
  -> Cedar policy/schema validation
  -> Cedar runtime test
  -> Cedar Analysis preparation
  -> solver-backed counterexample or no-violation artifact
```

Arbiter now runs on the Cedar 4.10 line, matching the Cedar line used by the
current `cedar-policy-symcc` releases. The optional `analysis` feature adds
SymCC-backed preparation and execution: parse a Cedar schema, validate a policy
set, compile every schema request environment, emit stable preparation
evidence, and then run a caller-supplied solver to produce no-violation,
unknown, error, or counterexample results.

`execute_analysis_with_cvc5` uses the `CVC5` environment variable first and
then `cvc5` on `PATH`. Tests use an in-process fake solver so CI does not need
a local CVC5 install for ordinary validation.

## HITL Escalation Discipline

Arbiter treats human-in-the-loop escalation as a Cedar-governed path, not as a
fallback for every denial. A denied request becomes `Escalate` only when the
same request with `human_approval_present = true` would be allowed by Cedar.
If approval would not change the Cedar decision, Arbiter returns `Reject`.

This keeps hard policy stops hard: missing gates, wrong domain, and actions not
actually permitted after approval do not become approval tasks.

## Formation Discovery

Formations should discover Arbiter through the capability catalog instead of
guessing suggestor names.

```rust
use arbiter::{formation_capabilities, CedarHitlGateSuggestor};

for capability in formation_capabilities() {
    println!("{} -> {:?}", capability.id, capability.suggestor);
}
```

The stable capability family is `arbiter.cedar`.

| Capability | Surface | Evidence tier |
|---|---|---|
| `arbiter.cedar.policy_gate` | `PolicyGateSuggestor` / `policy-gate` | `decided` |
| `arbiter.cedar.hitl_gate` | `CedarHitlGateSuggestor` / `cedar-hitl-gate` | `decided` |
| `arbiter.cedar.analysis_evidence` | `CedarAnalysisReport` under `analysis` | `searched` |

`CedarHitlGateSuggestor` is the explicit strict-HITL registration point. It
uses the same Cedar flow authorization path as `FlowGateSuggestor`, but exposes
a formation-friendly name for high-risk gates.

## Repository Layout

```text
crates/arbiter/
  invariants/      Human-readable policy invariant fixtures
  policies/        Reference Cedar policies
  schemas/         Cedar schemas used by analysis and invariant checks
  src/formation.rs Formation-facing capability descriptors
  src/engine.rs    Cedar policy engine
  src/suggestor.rs Converge suggestors and gates
  src/delegation.rs
  src/decision.rs
  src/flow.rs
  tests/           Policy, property, and negative tests
```

## Usage

```rust
use arbiter::{PolicyEngine, PolicyGateSuggestor, EXPENSE_APPROVAL_POLICY};
use std::sync::Arc;

let engine = PolicyEngine::from_policy_str(EXPENSE_APPROVAL_POLICY)?;
let gate = PolicyGateSuggestor::new(Arc::new(engine));

converge_engine.register_suggestor(gate);
```

## Development

Use `just` as the command surface:

```sh
just check
just test
just lint
just doc
```

Raw Cargo equivalents:

```sh
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Converge platform dependencies resolve from crates.io.

## Project Files

- [AGENTS.md](AGENTS.md) - agent entrypoint and boundary rules.
- [CHANGELOG.md](CHANGELOG.md) - release notes.
- [CONTRIBUTING.md](CONTRIBUTING.md) - contribution guide.
- [SECURITY.md](SECURITY.md) - vulnerability reporting and operator notes.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - community expectations.

## Status

Extracted from `converge/crates/policy` on 2026-05-05 as part of the v3.8
foundation extraction.

## License

MIT - see [LICENSE](LICENSE).

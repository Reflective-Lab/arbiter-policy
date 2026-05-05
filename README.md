# arbiter

[![CI](https://github.com/Reflective-Lab/arbiter/actions/workflows/ci.yml/badge.svg)](https://github.com/Reflective-Lab/arbiter/actions/workflows/ci.yml)
[![Security](https://github.com/Reflective-Lab/arbiter/actions/workflows/security.yml/badge.svg)](https://github.com/Reflective-Lab/arbiter/actions/workflows/security.yml)
[![dependency status](https://deps.rs/repo/github/Reflective-Lab/arbiter/status.svg)](https://deps.rs/repo/github/Reflective-Lab/arbiter)
![MSRV](https://img.shields.io/badge/MSRV-1.94.0-blue)
<img alt="gitleaks badge" src="https://img.shields.io/badge/protected%20by-gitleaks-blue">
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Cedar-backed authorization gates for Converge formations.

`arbiter` is a Converge extension. It keeps policy implementation, Cedar
evaluation, delegation verification, and authorization suggestors outside the
Converge foundation while still using Converge's shared contracts for
in-loop behavior.

## Why It Exists

Converge owns the governed promotion path. Arbiter answers a narrower question:
should this proposed action, flow transition, delegation, budget use, or data
movement be allowed under policy?

That lets policy participate as a first-class suggestor without turning the
Converge kernel into a policy engine.

## What Arbiter Owns

- Cedar policy parsing and evaluation.
- Policy decision and outcome types.
- Policy, flow, delegation, rate-limit, budget, approval, data-classification,
  and compliance gate suggestors.
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

## Repository Layout

```text
crates/arbiter/
  policies/        Reference Cedar policies
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

While Converge platform crates are unreleased, this workspace patches local
Converge crates at `../../work/converge/crates/...`.

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

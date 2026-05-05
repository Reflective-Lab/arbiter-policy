# arbiter Agent Guide

This is the canonical agent entrypoint for `arbiter`.

`arbiter` is a Converge extension for Cedar-backed policy decisions,
delegation verification, and authorization gates inside the convergence loop.

## Start Here

1. Read `README.md`.
2. Read `/Users/kpernyer/dev/extensions/kb/Modules/Arbiter.md`.
3. Check `Cargo.toml` and `crates/arbiter/Cargo.toml`.
4. Use `just --list` for local commands.

## Commands

```bash
just check
just test
just lint
just doc
```

## Boundaries

- Converge owns the pack and gate contracts.
- `arbiter` owns Cedar wiring, policy decisions, delegation checks, and policy
  suggestors.
- Product repositories own concrete production policy bundles and operational
  rollout.

## Rules

- Preserve `unsafe_code = "forbid"`.
- Do not bypass Converge promotion by manufacturing facts directly.
- Keep policy-specific implementation here; promote only reusable contracts
  upstream to Converge.
- Update `README.md`, `CHANGELOG.md`, and the extensions KB when the public
  policy surface changes.

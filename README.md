# arbiter

Cedar-based Policy Decision Point and policy suggestors for the Converge
platform. Implements `PolicyGate`, `FlowGate`, and `DelegationVerify`
suggestors plus a Cedar policy engine.

`arbiter` is a Converge **extension**. It depends on Converge's stable
contracts (`converge-pack`, `converge-core`) and lives outside the
foundation. The gate trait and authorization vocabulary stay in
`converge-pack`; the Cedar wiring and policy suggestors live here.

See the foundation's [Plug Boundary](https://github.com/Reflective-Lab/converge/blob/main/kb/Architecture/Plug%20Boundary.md) for the layering rule.

## Layout

- `crates/arbiter` — library + binary. Cedar engine, policy suggestors,
  decision/delegation/flow types, ed25519-signed delegation tokens.

## Status

Extracted from `converge/crates/policy` on 2026-05-05 as part of the v3.8
foundation extraction (ADR-008). Pre-1.0 — no published versions yet.

## Build

```sh
cargo check
cargo build --release
```

While Converge platform crates are unreleased, this workspace patches them
to local checkouts at `../../work/converge/crates/...` via
`[patch.crates-io]`.

## License

MIT — see [LICENSE](LICENSE).

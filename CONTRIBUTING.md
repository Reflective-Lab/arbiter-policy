# Contributing to arbiter

arbiter is a Converge extension. Contributions follow the same conventions as the Converge foundation.

## Development

```sh
cargo check --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

While the Converge platform is unreleased, this workspace patches `converge-core` and `converge-pack` to local checkouts at `~/dev/work/converge/crates/...` via `[patch.crates-io]`.

## Boundaries

arbiter implements policy **Suggestors** (`PolicyGate`, `FlowGate`, `DelegationVerify`) on top of a Cedar policy engine. The gate trait and authorization vocabulary live in `converge-pack`; arbiter implements them.

When adding capabilities, ask:

- Is this a new policy Suggestor (purposeful, agency-aware)? Add it.
- Is this a new policy engine backend? It belongs alongside the Cedar engine.
- Is this a contract type that other extensions need? It probably belongs in `converge-pack`, not here.

## No `unsafe`

The workspace forbids `unsafe`.

## License

By contributing, you agree your contributions are licensed under MIT.

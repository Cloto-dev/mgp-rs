# mgp-rs

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Rust workspace hosting the MGP (MCP Generosity Protocol) reference
implementations.

This repo was renamed from `mgp-seal` on 2026-05-08 as part of the
ClotoHub Phase 5a consolidation: per the [5-axes repo split
principle][5axes], `mgp-seal` and the new `mgp-sdk` share the same
language, audience, license, and visibility — split would be net
maintenance loss.

[5axes]: https://github.com/Cloto-dev/ClotoCore/blob/master/docs/MGP_SPEC.md

## Crates

| Crate | Latest | Role |
|---|---|---|
| [`mgp-seal`](crates/mgp-seal/) | `v0.4.1` | MGP §8 L0 Magic Seal — HMAC-SHA256 (Tier 1) + Ed25519 (Tier 2) integrity verification |
| [`mgp-sdk`](crates/mgp-sdk/)   | `v0.7.0` | `cloto-connector.json` v1 types, validation, adapters, registry shape |

## Tag conventions

- Existing tags `v0.1.0`, `v0.2.0` (top-level layout) — historical
  references to `mgp-seal` before workspace conversion. Consumers
  pinning these tags continue to work via GitHub auto-redirect.
- Going forward, tags use a per-crate namespace:
  - `mgp-seal-vX.Y.Z`
  - `mgp-sdk-vX.Y.Z`

## Consuming from another Rust crate

```toml
[dependencies]
mgp-seal = { git = "https://github.com/Cloto-dev/mgp-rs", subdir = "crates/mgp-seal", tag = "mgp-seal-v0.2.0" }
mgp-sdk  = { git = "https://github.com/Cloto-dev/mgp-rs", subdir = "crates/mgp-sdk",  tag = "mgp-sdk-v0.1.0" }
```

## Sibling repositories

- [`mgp-spec`](https://github.com/Cloto-dev/mgp-spec) — language-agnostic protocol specification (Markdown).
- `mgp-py` (planned) — Python SDK; see Phase 5+ design memo.
- [`ClotoCore`](https://github.com/Cloto-dev/ClotoCore) — kernel + MGP reference impl host.
- [`cpersona`](https://github.com/Cloto-dev/cpersona) — CPersona standalone Python distribution.

## License

MIT — see [LICENSE](LICENSE).

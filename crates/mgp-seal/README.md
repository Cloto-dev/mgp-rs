# mgp-seal

Reference implementation of **MGP §8 L0 Magic Seal** — HMAC-SHA256 + Ed25519
binary integrity verification for the [Magic Gateway Protocol](https://github.com/Cloto-dev/mgp-spec).

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

Magic Seal is the cryptographic primitive that backs MGP's binary integrity
guarantee. Each MGP server binary is sealed with an HMAC-SHA256 computed over
its file contents using a per-installation key. At startup the kernel verifies
the seal and translates the result into a trust-level decision per
[MGP §4.0](https://github.com/Cloto-dev/mgp-spec) (the v0.6.3 behavior matrix).

Since v0.2.0 the crate also ships an Ed25519 module ([`mgp_seal::ed25519`])
for **asymmetric** signing — the issuer (e.g. ClotoHub) holds the private key,
verifiers (e.g. ClotoCore) only need the published public key, and verification
works **offline** with no oracle round-trip. HMAC and Ed25519 are designed to
be issued together for defense-in-depth.

This crate is the canonical reference implementation, extracted from
[ClotoCore](https://github.com/Cloto-dev/ClotoCore) so any MGP-compatible
runtime — kernel, registry, or verification tooling — can share the same
cryptographic primitives.

## Install

```toml
[dependencies]
mgp-seal = { git = "https://github.com/Cloto-dev/mgp-rs", subdir = "crates/mgp-seal", tag = "mgp-seal-v0.3.0" }
```

## Quick start

```rust
use std::path::Path;
use mgp_seal::{compute_seal, verify_seal, load_or_generate_seal_key};

fn main() -> anyhow::Result<()> {
    let key = load_or_generate_seal_key(Path::new("/var/lib/mgp"))?;
    let seal = compute_seal(Path::new("/usr/local/bin/my-mgp-server"), &key)?;
    assert!(verify_seal(
        Path::new("/usr/local/bin/my-mgp-server"),
        &seal,
        &key,
    )?);
    Ok(())
}
```

## API

### Tier 1 — HMAC (top-level)

| Function / Type | Purpose |
|---|---|
| `compute_seal(file, key) -> "sha256:HEX"` | HMAC-SHA256 over file contents |
| `verify_seal(file, expected, key) -> bool` | Constant-time check against a stored seal |
| `check_seal(trust_level, seal, file, key, allow_unsigned)` | Full §4.0 behavior matrix |
| `SealStatus` | `Verified` / `Failed` / `Unsigned` / `Skipped` |
| `TrustLevel` | `Untrusted < Experimental < Standard < Core` (§2) |
| `load_or_generate_seal_key(data_dir)` | Env → file → fresh-random fallback |

### Tier 2 — Ed25519 (`mgp_seal::ed25519`, since v0.2.0)

| Function / Type | Purpose |
|---|---|
| `generate_keypair(rng) -> (PrivateKey, PublicKey)` | Fresh keypair from a CSPRNG |
| `sign(&priv, &kid, msg) -> Signature` | Sign with domain-separated input |
| `verify(&pub, &kid, msg, &sig) -> bool` | Offline verification |
| `public_key_to_jwk(&pub, &kid)` | RFC 8037 OKP/Ed25519 JWK |
| `public_key_from_jwk(&jwk) -> (PublicKey, KeyId)` | Parse a JWKS element back into a verifying key (since v0.3.0) |
| `private_key_from_base64(s)` | 12-factor env-var loading |
| `PublicKey::{to_base64, from_base64}` | Out-of-band public-key publishing |
| `Signature::{to_base64, from_base64}` | Wire-format encoding |
| `KeyId::new(s)` | Stable id, bound into every signature |

### Canonical message (top-level, since v0.3.0)

| Function | Purpose |
|---|---|
| `canonical_message(connector_id, version, entry_point_sha256) -> Vec<u8>` | The exact byte string a catalog seal record signs / verifies over |
| `validate_entry_point_sha256(s)` | Reject non-64-char-hex input at the edge |

Both the seal issuer (ClotoHub's Seals API) and any verifier (e.g. ClotoCore
at install time) build the signing input through this one function, so the
wire format cannot drift between the two sides:

```text
mgp-seal/v1
connector_id=<id>
version=<semver>
entry_point_sha256=<64-char lowercase hex>
```

```rust
use mgp_seal::ed25519::{generate_keypair, sign, verify, KeyId};
use rand::rngs::OsRng;

let (priv_key, pub_key) = generate_keypair(&mut OsRng);
let kid = KeyId::new("clotohub-master-v1").unwrap();
let sig = sign(&priv_key, &kid, b"connector=cpersona\nversion=1.2.3\n");
assert!(verify(&pub_key, &kid, b"connector=cpersona\nversion=1.2.3\n", &sig));
```

Signatures are computed over
`b"mgp-seal-ed25519-v1" || 0x00 || key_id || 0x00 || message` so every
signature is bound to (a) this crate / version / use-case (preventing
cross-protocol reuse) and (b) the `key_id` (preventing silent re-attribution
in a JWKS keyring).

## Seal absent: §4.0 (v0.6.3) behavior matrix

| Trust Level   | Seal Present | Seal Absent       | Seal Invalid |
|---------------|--------------|-------------------|--------------|
| Core          | Verify       | Force `untrusted` | Block        |
| Standard      | Verify       | Force `untrusted` | Block        |
| Experimental  | Verify       | Force `untrusted` | Block        |
| Untrusted     | Verify       | Allow             | Block        |

`check_seal` only computes the cryptographic outcome — translating the
result into a startup decision (block / start untrusted / start declared)
is the caller's responsibility. See the [doc comment](src/seal.rs) for
audit-event semantics.

## Key resolution

`load_or_generate_seal_key(data_dir)` resolves in this order:

1. `CLOTO_SEAL_KEY` env-var (hex-encoded). The name is preserved from the
   ClotoCore reference; other runtimes MAY adopt it for portability or wrap
   this function with a runtime-specific env-var.
2. `{data_dir}/seal.key` (raw bytes, 32 bytes recommended).
3. Generate a fresh 32-byte random key, persist it to `{data_dir}/seal.key`,
   return it.

## Versioning & stability

Pre-1.0 the API may change between minor versions. The cryptographic
contract — `"sha256:HEX"` format and the §4.0 behavior matrix — is
stable per the MGP spec and will not change without a corresponding
spec bump.

## License

MIT — see [LICENSE](LICENSE).

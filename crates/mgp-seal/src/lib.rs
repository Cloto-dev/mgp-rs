//! Reference implementation of MGP §8 L0 Magic Seal.
//!
//! Magic Seal is the binary integrity layer of the MGP (Magic Gateway Protocol)
//! security model. Each MGP server binary is sealed with an HMAC-SHA256 computed
//! over its file contents using a per-installation key. At startup the kernel
//! verifies the seal and translates the result into a trust-level decision per
//! MGP §4.0 (the v0.6.3 behavior matrix).
//!
//! This crate is the canonical reference implementation, extracted from
//! ClotoCore so that any MGP-compatible runtime — kernel, registry, or
//! verification tooling — can share the same cryptographic primitives.
//!
//! # Quick start
//!
//! ```no_run
//! use std::path::Path;
//! use mgp_seal::{compute_seal, verify_seal, load_or_generate_seal_key};
//!
//! # fn main() -> anyhow::Result<()> {
//! let key = load_or_generate_seal_key(Path::new("/var/lib/mgp"))?;
//! let seal = compute_seal(Path::new("/usr/local/bin/my-mgp-server"), &key)?;
//! assert!(verify_seal(Path::new("/usr/local/bin/my-mgp-server"), &seal, &key)?);
//! # Ok(())
//! # }
//! ```
//!
//! # Modules
//!
//! - [`seal`] — `compute_seal`, `verify_seal`, `check_seal`, [`SealStatus`]
//!   (Tier 1: HMAC-SHA256 oracle)
//! - [`ed25519`] — `generate_keypair`, `sign`, `verify`, JWK serialization
//!   (Tier 2: asymmetric Ed25519 for offline verification, added in v0.2.0)
//! - [`canonical`] — [`canonical_message`], the catalog seal record signing
//!   message shared between issuer and verifier (added in v0.3.0)
//! - [`key`] — [`load_or_generate_seal_key`]
//! - [`trust`] — [`TrustLevel`] enum (MGP §2)
//!
//! Top-level re-exports are provided for the common HMAC API surface and the
//! canonical-message helpers (used by both tiers). The Ed25519 surface is
//! intentionally namespaced — `mgp_seal::ed25519::sign` reads more clearly at
//! call sites than a flat `mgp_seal::sign`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod canonical;
pub mod ed25519;
pub mod key;
pub mod seal;
pub mod trust;

pub use canonical::{canonical_message, validate_entry_point_sha256};
pub use key::load_or_generate_seal_key;
pub use seal::{check_seal, compute_seal, verify_seal, SealStatus};
pub use trust::TrustLevel;

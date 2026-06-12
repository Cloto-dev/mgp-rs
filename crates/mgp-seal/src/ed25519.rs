//! Ed25519 keypairs, signing, and verification — Tier 2 of the Magic Seal trust model.
//!
//! The HMAC layer ([`crate::seal`]) backs symmetric per-installation sealing
//! and requires the verifier to share the secret key with the signer. Tier 2
//! adds asymmetric Ed25519 signatures alongside HMAC so a verifier (e.g.
//! ClotoCore at runtime) can validate a seal **offline** with only the
//! issuer's public key — no network round-trip to the seal-issuing oracle.
//!
//! This module is a thin, opinionated wrapper around `ed25519-dalek` that
//! pins down the choices a Magic Seal consumer should not have to make:
//!
//! - **Domain separation.** Every signature is computed over
//!   `b"mgp-seal-ed25519-v1" || 0x00 || key_id || 0x00 || message`. This
//!   prevents cross-protocol reuse and binds the signature to a specific
//!   `key_id` so it cannot be silently re-attributed to a different key in a
//!   JWKS keyring.
//! - **Stable on-the-wire format.** Public keys, private keys, and signatures
//!   round-trip through standard base64 (padded). Public keys also serialise
//!   as RFC 8037 §2 OKP/Ed25519 JWKs.
//! - **Zeroisation.** [`PrivateKey`] holds an `ed25519_dalek::SigningKey`,
//!   which wipes its bytes on drop via `zeroize`.
//!
//! # Quick start
//!
//! ```
//! use mgp_seal::ed25519::{generate_keypair, sign, verify, KeyId};
//! use rand::rngs::OsRng;
//!
//! let (private, public) = generate_keypair(&mut OsRng);
//! let key_id = KeyId::new("clotohub-master-v1").unwrap();
//! let message = b"connector=cpersona\nversion=1.2.3\nsha256=abc...";
//! let sig = sign(&private, &key_id, message);
//! assert!(verify(&public, &key_id, message, &sig));
//! ```

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Domain-separation tag mixed into every signing input. Bumping the suffix
/// (e.g. `-v2`) is a breaking change to the wire format and MUST coincide
/// with a major version bump of this crate.
const DOMAIN: &[u8] = b"mgp-seal-ed25519-v1";

/// Maximum permitted `key_id` length, in UTF-8 bytes. The cap exists so the
/// signing input has a bounded prefix and the JWK `kid` stays comfortably
/// within HTTP-header / JWS-header limits.
pub const KEY_ID_MAX_LEN: usize = 256;

/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// Length of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

// ============================================================
// Types
// ============================================================

/// Ed25519 private signing key.
///
/// The wrapped `ed25519_dalek::SigningKey` is `ZeroizeOnDrop`, so the secret
/// material is wiped from memory when this value is dropped. Avoid cloning,
/// avoid logging, and avoid copying the bytes out of [`Self::to_base64`] into
/// long-lived `String`s.
pub struct PrivateKey(SigningKey);

/// Ed25519 public verifying key (32 bytes on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

/// Stable identifier for a keypair (e.g. `"clotohub-master-v1"`).
///
/// Bound into every signature via the domain-separated signing input, so the
/// id MUST be globally unique within a verifier's keyring and SHOULD remain
/// stable across the lifetime of the keypair. Rotation is expressed by
/// minting a new `KeyId` (e.g. `"clotohub-master-2027q1"`), not by mutating
/// an existing one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(String);

/// Ed25519 signature (64 bytes on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(ed25519_dalek::Signature);

// ============================================================
// KeyId
// ============================================================

impl KeyId {
    /// Construct a `KeyId`. Rejects empty strings and ids longer than
    /// [`KEY_ID_MAX_LEN`] UTF-8 bytes.
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s: String = s.into();
        if s.is_empty() {
            bail!("key_id must be non-empty");
        }
        if s.len() > KEY_ID_MAX_LEN {
            bail!("key_id exceeds {} bytes (got {})", KEY_ID_MAX_LEN, s.len());
        }
        Ok(Self(s))
    }

    /// The id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ============================================================
// PrivateKey
// ============================================================

impl PrivateKey {
    /// Derive the corresponding [`PublicKey`].
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Encode the 32-byte secret as base64 (standard alphabet, padded).
    ///
    /// Pair with [`private_key_from_base64`] for round-trip storage in a
    /// 12-factor environment variable (e.g. `CLOTO_SEAL_ED25519_PRIVATE_KEY`).
    #[must_use]
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0.to_bytes())
    }
}

// Deliberately *no* `Debug` / `Display` impl on `PrivateKey` — we never want
// secret bytes in logs.

// ============================================================
// PublicKey
// ============================================================

impl PublicKey {
    /// Raw 32-byte public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// Encode the 32-byte public key as base64 (standard alphabet, padded).
    #[must_use]
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0.to_bytes())
    }

    /// Decode a public key from base64 (standard alphabet, padded).
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = STANDARD
            .decode(s.trim())
            .context("public key is not valid base64")?;
        let arr: [u8; PUBLIC_KEY_LENGTH] = bytes.try_into().map_err(|v: Vec<u8>| {
            anyhow!(
                "public key must be exactly {} bytes (got {})",
                PUBLIC_KEY_LENGTH,
                v.len()
            )
        })?;
        let vk = VerifyingKey::from_bytes(&arr).context("invalid Ed25519 public key bytes")?;
        Ok(Self(vk))
    }
}

// ============================================================
// Signature
// ============================================================

impl Signature {
    /// Raw 64-byte signature.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0.to_bytes()
    }

    /// Encode the signature as base64 (standard alphabet, padded).
    #[must_use]
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0.to_bytes())
    }

    /// Decode a signature from base64 (standard alphabet, padded).
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = STANDARD
            .decode(s.trim())
            .context("signature is not valid base64")?;
        let arr: [u8; SIGNATURE_LENGTH] = bytes.try_into().map_err(|v: Vec<u8>| {
            anyhow!(
                "signature must be exactly {} bytes (got {})",
                SIGNATURE_LENGTH,
                v.len()
            )
        })?;
        Ok(Self(ed25519_dalek::Signature::from_bytes(&arr)))
    }
}

// ============================================================
// Core: keygen / sign / verify
// ============================================================

/// Generate a fresh Ed25519 keypair using the provided CSPRNG.
///
/// Use `rand::rngs::OsRng` for production keys.
pub fn generate_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (PrivateKey, PublicKey) {
    let signing = SigningKey::generate(rng);
    let public = PublicKey(signing.verifying_key());
    (PrivateKey(signing), public)
}

/// Sign `message` under `key`, binding `key_id` into the signed payload.
///
/// The signing input is
/// `b"mgp-seal-ed25519-v1" || 0x00 || key_id || 0x00 || message`. The exact
/// same `key_id` MUST be supplied to [`verify`] — passing a different id is
/// a verification failure, not a configuration shortcut.
#[must_use]
pub fn sign(key: &PrivateKey, key_id: &KeyId, message: &[u8]) -> Signature {
    let input = signing_input(key_id, message);
    Signature(key.0.sign(&input))
}

/// Verify `sig` over `message` using `key`, with `key_id` mixed into the
/// signing input as in [`sign`]. Returns `false` on any mismatch (wrong key,
/// wrong key_id, tampered message, or a bit-flipped signature).
#[must_use]
pub fn verify(key: &PublicKey, key_id: &KeyId, message: &[u8], sig: &Signature) -> bool {
    let input = signing_input(key_id, message);
    key.0.verify(&input, &sig.0).is_ok()
}

fn signing_input(key_id: &KeyId, message: &[u8]) -> Vec<u8> {
    let kid = key_id.0.as_bytes();
    let mut buf = Vec::with_capacity(DOMAIN.len() + 1 + kid.len() + 1 + message.len());
    buf.extend_from_slice(DOMAIN);
    buf.push(0x00);
    buf.extend_from_slice(kid);
    buf.push(0x00);
    buf.extend_from_slice(message);
    buf
}

// ============================================================
// JWK / private-key IO
// ============================================================

/// Serialise a public key as an RFC 8037 §2 OKP/Ed25519 JWK.
///
/// The returned object has the canonical fields a JWKS endpoint needs:
/// `kty=OKP`, `crv=Ed25519`, `alg=EdDSA`, `use=sig`, `kid`, and `x`
/// (base64url-no-pad of the 32-byte public key).
#[must_use]
pub fn public_key_to_jwk(key: &PublicKey, key_id: &KeyId) -> serde_json::Value {
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "use": "sig",
        "kid": key_id.0,
        "x": URL_SAFE_NO_PAD.encode(key.0.to_bytes()),
    })
}

/// Parse a single RFC 8037 §2 OKP/Ed25519 JWK back into a usable
/// `(PublicKey, KeyId)` pair — the inverse of [`public_key_to_jwk`].
///
/// This is what a JWKS consumer (e.g. ClotoCore fetching ClotoHub's
/// `/api/seal/keys`) calls on each element of the `keys` array before
/// verifying seal signatures offline with [`verify`].
///
/// Validation is strict: `kty` must be `OKP`, `crv` must be `Ed25519`,
/// and when the optional `alg` / `use` fields are present they must be
/// `EdDSA` / `sig` respectively. The mandatory `x` field is decoded as
/// base64url-no-pad (note: *not* the standard alphabet that
/// [`PublicKey::from_base64`] expects) and must yield exactly 32 valid
/// public-key bytes.
///
/// Extra fields (e.g. a JWKS server annotating retired keys with
/// `revoked_at`) are ignored here — whether to trust a rotated-out key
/// is caller policy, not a parsing concern.
pub fn public_key_from_jwk(jwk: &serde_json::Value) -> Result<(PublicKey, KeyId)> {
    let field = |name: &str| jwk.get(name).and_then(serde_json::Value::as_str);

    match field("kty") {
        Some("OKP") => {}
        Some(other) => bail!("JWK `kty` must be \"OKP\" (got {other:?})"),
        None => bail!("JWK is missing the `kty` field"),
    }
    match field("crv") {
        Some("Ed25519") => {}
        Some(other) => bail!("JWK `crv` must be \"Ed25519\" (got {other:?})"),
        None => bail!("JWK is missing the `crv` field"),
    }
    if let Some(alg) = field("alg") {
        if alg != "EdDSA" {
            bail!("JWK `alg` must be \"EdDSA\" when present (got {alg:?})");
        }
    }
    if let Some(usage) = field("use") {
        if usage != "sig" {
            bail!("JWK `use` must be \"sig\" when present (got {usage:?})");
        }
    }

    let kid = field("kid").ok_or_else(|| anyhow!("JWK is missing the `kid` field"))?;
    let key_id = KeyId::new(kid)?;

    let x = field("x").ok_or_else(|| anyhow!("JWK is missing the `x` field"))?;
    let raw = URL_SAFE_NO_PAD
        .decode(x)
        .context("JWK `x` is not valid base64url-no-pad")?;
    let arr: [u8; PUBLIC_KEY_LENGTH] = raw.try_into().map_err(|v: Vec<u8>| {
        anyhow!(
            "JWK `x` must decode to exactly {PUBLIC_KEY_LENGTH} bytes (got {})",
            v.len()
        )
    })?;
    let vk = VerifyingKey::from_bytes(&arr).context("JWK `x` is not a valid Ed25519 public key")?;
    Ok((PublicKey(vk), key_id))
}

/// Decode a private key from base64 (standard alphabet, padded; 32 raw secret
/// bytes — the Ed25519 seed, not the expanded scalar).
///
/// Pair with [`PrivateKey::to_base64`] for round-trip storage.
pub fn private_key_from_base64(s: &str) -> Result<PrivateKey> {
    let bytes = STANDARD
        .decode(s.trim())
        .context("private key is not valid base64")?;
    let arr: [u8; SECRET_KEY_LENGTH] = bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow!(
            "private key must be exactly {} bytes (got {})",
            SECRET_KEY_LENGTH,
            v.len()
        )
    })?;
    Ok(PrivateKey(SigningKey::from_bytes(&arr)))
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn fresh() -> (PrivateKey, PublicKey, KeyId) {
        let (sk, pk) = generate_keypair(&mut OsRng);
        let kid = KeyId::new("clotohub-master-test").unwrap();
        (sk, pk, kid)
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, pk, kid) = fresh();
        let msg = b"hello seal";
        let sig = sign(&sk, &kid, msg);
        assert!(verify(&pk, &kid, msg, &sig));
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let (sk, pk, kid) = fresh();
        let sig = sign(&sk, &kid, b"original");
        assert!(!verify(&pk, &kid, b"original!", &sig));
    }

    #[test]
    fn verify_rejects_wrong_key_id() {
        let (sk, pk, _) = fresh();
        let kid_a = KeyId::new("kid-a").unwrap();
        let kid_b = KeyId::new("kid-b").unwrap();
        let sig = sign(&sk, &kid_a, b"payload");
        assert!(verify(&pk, &kid_a, b"payload", &sig));
        assert!(
            !verify(&pk, &kid_b, b"payload", &sig),
            "key_id is part of the signed input — different kid must fail"
        );
    }

    #[test]
    fn verify_rejects_wrong_public_key() {
        let (sk, _, kid) = fresh();
        let (_, other_pk) = generate_keypair(&mut OsRng);
        let sig = sign(&sk, &kid, b"payload");
        assert!(!verify(&other_pk, &kid, b"payload", &sig));
    }

    #[test]
    fn ed25519_is_deterministic() {
        // Ed25519 (RFC 8032) is deterministic: same key + same input → same sig.
        let (sk, _, kid) = fresh();
        let a = sign(&sk, &kid, b"determinism");
        let b = sign(&sk, &kid, b"determinism");
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn key_id_rejects_empty() {
        assert!(KeyId::new("").is_err());
    }

    #[test]
    fn key_id_rejects_too_long() {
        let huge = "x".repeat(KEY_ID_MAX_LEN + 1);
        assert!(KeyId::new(huge).is_err());
        let max = "x".repeat(KEY_ID_MAX_LEN);
        assert!(KeyId::new(max).is_ok());
    }

    #[test]
    fn public_key_base64_roundtrip() {
        let (_, pk, _) = fresh();
        let b64 = pk.to_base64();
        let decoded = PublicKey::from_base64(&b64).unwrap();
        assert_eq!(pk, decoded);
    }

    #[test]
    fn public_key_base64_rejects_wrong_length() {
        let three_bytes = STANDARD.encode([1u8, 2, 3]);
        assert!(PublicKey::from_base64(&three_bytes).is_err());
    }

    #[test]
    fn private_key_base64_roundtrip_preserves_signing() {
        let (sk, pk, kid) = fresh();
        let b64 = sk.to_base64();
        let restored = private_key_from_base64(&b64).unwrap();

        // Restored key produces a signature that the original public key still
        // verifies — i.e. the seed bytes round-tripped, not just any bytes.
        let sig = sign(&restored, &kid, b"restored");
        assert!(verify(&pk, &kid, b"restored", &sig));
    }

    #[test]
    fn private_key_from_base64_rejects_wrong_length() {
        let three_bytes = STANDARD.encode([1u8, 2, 3]);
        assert!(private_key_from_base64(&three_bytes).is_err());
    }

    #[test]
    fn signature_base64_roundtrip() {
        let (sk, pk, kid) = fresh();
        let sig = sign(&sk, &kid, b"sig-roundtrip");
        let b64 = sig.to_base64();
        let restored = Signature::from_base64(&b64).unwrap();
        assert_eq!(sig, restored);
        assert!(verify(&pk, &kid, b"sig-roundtrip", &restored));
    }

    #[test]
    fn jwk_has_canonical_fields() {
        let (_, pk, kid) = fresh();
        let jwk = public_key_to_jwk(&pk, &kid);
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["alg"], "EdDSA");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["kid"], kid.as_str());
        let x = jwk["x"].as_str().unwrap();
        // base64url-no-pad of 32 bytes = 43 chars, no padding.
        assert_eq!(x.len(), 43);
        assert!(!x.contains('='));
        // Round-trip the `x` field back into a usable PublicKey.
        let raw = URL_SAFE_NO_PAD.decode(x).unwrap();
        let arr: [u8; PUBLIC_KEY_LENGTH] = raw.try_into().unwrap();
        assert_eq!(arr, pk.to_bytes());
    }

    #[test]
    fn public_key_derivation_matches_keypair() {
        let (sk, pk) = generate_keypair(&mut OsRng);
        assert_eq!(sk.public_key(), pk);
    }
}

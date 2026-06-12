//! Canonical signing message for catalog seal records.
//!
//! Both the seal **issuer** (ClotoHub's Seals API) and any **verifier**
//! (e.g. ClotoCore at install time) must compute signatures over the exact
//! same byte string. This module pins that byte string in one place so the
//! wire format cannot drift between the issue path and the verify path.
//!
//! Hoisted verbatim from `clotohub-web` `crates/api/src/seals/service.rs`
//! in v0.3.0; the hub now consumes this implementation instead of its own.
//!
//! # Format
//!
//! The message is line-oriented so it stays human-debuggable in audit logs:
//!
//! ```text
//! mgp-seal/v1
//! connector_id=<id>
//! version=<semver>
//! entry_point_sha256=<64-char lowercase hex>
//! ```
//!
//! (each line terminated by `\n`, including the last). Changing this format
//! in any way is a breaking change to the seal wire protocol and MUST
//! coincide with a major version bump of this crate.

use anyhow::{anyhow, Result};

/// Build the canonical signing message for a (connector, version,
/// entry_point_sha256) triple.
///
/// This is the byte string that ClotoHub signs (HMAC-SHA256 and Ed25519,
/// see the hub's `signature_payload`) and that a verifier reconstructs
/// from the catalog entry before calling [`crate::ed25519::verify`].
#[must_use]
pub fn canonical_message(connector_id: &str, version: &str, entry_point_sha256: &str) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(64 + connector_id.len() + version.len() + entry_point_sha256.len());
    buf.extend_from_slice(b"mgp-seal/v1\n");
    buf.extend_from_slice(b"connector_id=");
    buf.extend_from_slice(connector_id.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(b"version=");
    buf.extend_from_slice(version.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(b"entry_point_sha256=");
    buf.extend_from_slice(entry_point_sha256.as_bytes());
    buf.push(b'\n');
    buf
}

/// Sanity-check that an `entry_point_sha256` is a 64-char hex string.
///
/// Call this on untrusted input *before* building the canonical message,
/// so malformed hashes are rejected at the edge instead of being signed
/// or verified as-is.
pub fn validate_entry_point_sha256(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("entry_point_sha256 must be a 64-char hex string"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_message_pins_exact_bytes() {
        // The literal expected bytes — if this test ever needs editing,
        // the wire format changed and every existing seal breaks.
        let msg = canonical_message("cpersona", "1.2.3", "deadbeef");
        assert_eq!(
            msg,
            b"mgp-seal/v1\nconnector_id=cpersona\nversion=1.2.3\nentry_point_sha256=deadbeef\n"
        );
    }

    #[test]
    fn canonical_message_is_stable_and_distinct() {
        let a = canonical_message("cpersona", "1.2.3", "deadbeef");
        let b = canonical_message("cpersona", "1.2.3", "deadbeef");
        assert_eq!(a, b);
        let c = canonical_message("cpersona", "1.2.4", "deadbeef");
        assert_ne!(a, c);
    }

    #[test]
    fn validate_entry_point_sha256_rules() {
        assert!(validate_entry_point_sha256(&"a".repeat(64)).is_ok());
        assert!(validate_entry_point_sha256(&"1".repeat(64)).is_ok());
        assert!(validate_entry_point_sha256("short").is_err());
        assert!(validate_entry_point_sha256(&"a".repeat(65)).is_err());
        assert!(validate_entry_point_sha256(&"!".repeat(64)).is_err()); // non-hex
    }
}

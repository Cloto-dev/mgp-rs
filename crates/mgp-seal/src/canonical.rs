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
//!
//! # v2: binding the distributed artifact
//!
//! v1 signs an assertion about **one file**. It says nothing about the
//! archive the consumer actually downloads, and a catalog response as a
//! whole is not signed — so where a catalog serves an archive digest
//! alongside the seal, that digest is authenticated only by whatever
//! protects the response. An adversary able to forge it can substitute
//! both the archive and its declared digest while the v1 signature still
//! verifies. That is not hypothetical for packaged connectors, whose
//! entry point is an unchanged shim: the signed assertion stays true
//! while the shipped implementation changes underneath it.
//!
//! v2 closes that by binding the artifact's digest **and length** into
//! the signed message:
//!
//! ```text
//! mgp-seal/v2
//! connector_id=<id>
//! version=<semver>
//! entry_point_sha256=<64-char lowercase hex>
//! archive_sha256=<64-char lowercase hex>
//! archive_length=<decimal byte count>
//! ```
//!
//! The length is not redundant with the digest. A verifier learns the
//! expected size *before* streaming the body, so a hostile mirror cannot
//! feed it unbounded data that only fails at the final hash comparison —
//! the same reason TUF signs hash and length together.
//!
//! ## Downgrade
//!
//! v1 and v2 are distinct byte strings (the first line differs), so a v1
//! signature can never be replayed as a v2 one. What the format alone
//! cannot prevent is a *downgrade*: for a (connector, version) that was
//! sealed under v1 before v2 existed, that older signature stays
//! genuinely valid, and an adversary who can forge a catalog response can
//! serve it instead of the v2 seal to escape the artifact binding.
//!
//! Closing that is a policy decision for the verifier, not a property of
//! this module — it needs to know that a given connector *should* have a
//! v2 seal. Re-sealing the corpus under v2 and then refusing v1 is the
//! intended path; until a verifier does both, accepting v1 leaves the
//! weaker claim reachable.

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

/// Build the canonical signing message for a v2 seal, which additionally
/// binds the distributed archive's digest and length.
///
/// Use this for every new seal. [`canonical_message`] remains only so
/// that seals issued before v2 existed can still be verified; see the
/// module docs on downgrade for why continuing to *accept* v1 is a
/// verifier policy question rather than a formatting one.
#[must_use]
pub fn canonical_message_v2(
    connector_id: &str,
    version: &str,
    entry_point_sha256: &str,
    archive_sha256: &str,
    archive_length: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        128 + connector_id.len() + version.len() + entry_point_sha256.len() + archive_sha256.len(),
    );
    buf.extend_from_slice(b"mgp-seal/v2\n");
    buf.extend_from_slice(b"connector_id=");
    buf.extend_from_slice(connector_id.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(b"version=");
    buf.extend_from_slice(version.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(b"entry_point_sha256=");
    buf.extend_from_slice(entry_point_sha256.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(b"archive_sha256=");
    buf.extend_from_slice(archive_sha256.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(b"archive_length=");
    buf.extend_from_slice(archive_length.to_string().as_bytes());
    buf.push(b'\n');
    buf
}

/// Sanity-check that an `entry_point_sha256` is a 64-char hex string.
///
/// Call this on untrusted input *before* building the canonical message,
/// so malformed hashes are rejected at the edge instead of being signed
/// or verified as-is.
pub fn validate_entry_point_sha256(value: &str) -> Result<()> {
    validate_sha256_hex(value)
        .map_err(|_| anyhow!("entry_point_sha256 must be a 64-char hex string"))
}

/// Sanity-check that an `archive_sha256` is a 64-char hex string.
///
/// Same edge-rejection rule as [`validate_entry_point_sha256`]: a
/// malformed digest must never reach the signing or verifying path,
/// where it would become an authenticated claim about nothing.
pub fn validate_archive_sha256(value: &str) -> Result<()> {
    validate_sha256_hex(value).map_err(|_| anyhow!("archive_sha256 must be a 64-char hex string"))
}

fn validate_sha256_hex(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("not a 64-char hex string"));
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
    fn canonical_message_v2_pins_exact_bytes() {
        // As with v1: editing this literal means the wire format changed
        // and every v2 seal already issued breaks.
        let msg = canonical_message_v2("cpersona", "1.2.3", "deadbeef", "cafebabe", 4096);
        assert_eq!(
            msg,
            b"mgp-seal/v2\nconnector_id=cpersona\nversion=1.2.3\nentry_point_sha256=deadbeef\narchive_sha256=cafebabe\narchive_length=4096\n"
        );
    }

    #[test]
    fn v2_is_not_replayable_as_v1() {
        // Domain separation: the versions must never produce the same
        // bytes, or a signature over the weaker v1 claim could be
        // presented as a v2 one.
        let v1 = canonical_message("cpersona", "1.2.3", "deadbeef");
        let v2 = canonical_message_v2("cpersona", "1.2.3", "deadbeef", "cafebabe", 4096);
        assert_ne!(v1, v2);
        assert!(!v2.starts_with(&v1[..]));
    }

    #[test]
    fn every_v2_field_changes_the_message() {
        // The whole point of v2 is that the artifact is bound. If any of
        // these stopped contributing, an attacker could vary it freely
        // under a signature that still verifies.
        let base = canonical_message_v2("cpersona", "1.2.3", "deadbeef", "cafebabe", 4096);
        assert_ne!(
            base,
            canonical_message_v2("cscheduler", "1.2.3", "deadbeef", "cafebabe", 4096)
        );
        assert_ne!(
            base,
            canonical_message_v2("cpersona", "1.2.4", "deadbeef", "cafebabe", 4096)
        );
        assert_ne!(
            base,
            canonical_message_v2("cpersona", "1.2.3", "deadbeee", "cafebabe", 4096)
        );
        // The substitution attack v2 exists to stop: same shim entry
        // point, different archive.
        assert_ne!(
            base,
            canonical_message_v2("cpersona", "1.2.3", "deadbeef", "cafebabf", 4096)
        );
        // Length alone must matter too — a same-digest claim at a
        // different declared size is a different assertion.
        assert_ne!(
            base,
            canonical_message_v2("cpersona", "1.2.3", "deadbeef", "cafebabe", 4097)
        );
    }

    #[test]
    fn v2_fields_cannot_be_smeared_across_lines() {
        // Field values are not delimiter-escaped, so confirm that moving
        // content between fields does not collide onto one message.
        let a = canonical_message_v2("a", "1", "b", "c", 1);
        let b = canonical_message_v2("a", "1", "b", "c\narchive_length=1\nx=", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn validate_archive_sha256_rules() {
        assert!(validate_archive_sha256(&"a".repeat(64)).is_ok());
        assert!(validate_archive_sha256("short").is_err());
        assert!(validate_archive_sha256(&"z".repeat(64)).is_err());
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

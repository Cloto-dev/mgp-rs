//! v1 manifest validator.

use super::ValidationError;
use crate::adapters::SourceSpec;
use crate::types::ConnectorManifest;
use crate::{CONNECTOR_TYPE_MGP_SERVER, PACKAGE_MANAGER_UV, SPEC_VERSION};

const TRUST_LEVELS: &[&str] = &["core", "standard", "experimental", "untrusted"];
const RUNTIMES: &[&str] = &["python", "rust", "node"];

/// Validate a `cloto-connector.json` v1 manifest. Pure logic — no IO.
///
/// # Errors
///
/// Returns the first [`ValidationError`] encountered. Validation
/// short-circuits; full-detail diagnostics belong to ClotoHub.dev's
/// admin tooling, which can call the underlying check helpers
/// directly.
pub fn validate_v1(manifest: &ConnectorManifest) -> Result<(), ValidationError> {
    if manifest.spec_version != SPEC_VERSION {
        return Err(ValidationError::UnsupportedSpecVersion(
            manifest.spec_version,
        ));
    }
    if manifest.connector_type != CONNECTOR_TYPE_MGP_SERVER {
        return Err(ValidationError::UnsupportedConnectorType(
            manifest.connector_type.clone(),
        ));
    }
    if !is_well_formed_id(&manifest.id) {
        return Err(ValidationError::InvalidId);
    }
    if !TRUST_LEVELS.contains(&manifest.trust_level.as_str()) {
        return Err(ValidationError::UnsupportedTrustLevel(
            manifest.trust_level.clone(),
        ));
    }
    if !is_well_formed_seal(&manifest.magic_seal) {
        return Err(ValidationError::MalformedMagicSeal);
    }
    if manifest.install.package_manager != PACKAGE_MANAGER_UV {
        return Err(ValidationError::UnsupportedPackageManager(
            manifest.install.package_manager.clone(),
        ));
    }
    if !RUNTIMES.contains(&manifest.install.runtime.as_str()) {
        return Err(ValidationError::UnsupportedRuntime(
            manifest.install.runtime.clone(),
        ));
    }
    validate_source(&manifest.install.source)?;
    Ok(())
}

fn validate_source(source: &SourceSpec) -> Result<(), ValidationError> {
    let kind = source.kind();
    let reason = match source {
        SourceSpec::Git(s) => s.check_url().err(),
        SourceSpec::RawUrl(s) => s.check().err(),
        SourceSpec::Pypi(s) => s.check().err(),
        SourceSpec::Docker(s) => s.check().err(),
    };
    if let Some(reason) = reason {
        return Err(ValidationError::InvalidSource { kind, reason });
    }
    Ok(())
}

/// Connector id charset per MGP_CONNECTOR.md §3.3:
/// `[a-z0-9]([a-z0-9_-]*[a-z0-9])?`. kebab-case is the RECOMMENDED style;
/// underscores are equally legal so host-side server ids (snake_case on
/// Python-centric hosts) flow through unchanged. First and last characters
/// must be alphanumeric — no leading/trailing separator of either kind.
fn is_well_formed_id(id: &str) -> bool {
    if id.is_empty() {
        return false;
    }
    id.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        && id.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && id.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn is_well_formed_seal(seal: &str) -> bool {
    // Lowercase hex only — `mgp_seal::compute_seal` emits `hex::encode(...)`
    // which is lowercase, and `verify_seal` does a byte-exact comparison.
    // An uppercase or mixed-case seal can never verify, so accepting it at
    // the validator layer would only let a latent bug propagate.
    let Some(hex) = seal.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.chars().all(is_lowercase_hex_digit)
}

fn is_lowercase_hex_digit(c: char) -> bool {
    c.is_ascii_digit() || matches!(c, 'a'..='f')
}

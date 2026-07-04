//! `cloto-connector.json` v1 validation.

mod connector_v1;

pub use connector_v1::validate_v1;

use thiserror::Error;

/// Validation failure modes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    /// Wrong `spec_version`.
    #[error("unsupported spec_version: expected 1, got {0}")]
    UnsupportedSpecVersion(u32),
    /// Wrong `connector_type`.
    #[error("unsupported connector_type: expected `mgp_server`, got `{0}`")]
    UnsupportedConnectorType(String),
    /// `magic_seal` missing or malformed.
    #[error("magic_seal must be `sha256:<hex>` with 64 lowercase hex chars")]
    MalformedMagicSeal,
    /// `package_manager` not `uv`.
    #[error("package_manager must be `uv`, got `{0}`")]
    UnsupportedPackageManager(String),
    /// `runtime` not in {python, rust, node}.
    #[error("runtime must be one of python|rust|node, got `{0}`")]
    UnsupportedRuntime(String),
    /// `trust_level` not in MGP §2.3 4-tier set.
    #[error("trust_level must be one of core|standard|experimental|untrusted, got `{0}`")]
    UnsupportedTrustLevel(String),
    /// `id` empty or outside the MGP_CONNECTOR.md §3.3 charset
    /// (`[a-z0-9]([a-z0-9_-]*[a-z0-9])?`).
    #[error(
        "connector id must be non-empty lowercase alphanumeric with interior hyphens/underscores"
    )]
    InvalidId,
    /// Source-spec sub-validation failed.
    #[error("invalid source ({kind}): {reason}")]
    InvalidSource {
        /// Adapter discriminant (`git | raw_url | pypi | docker`).
        kind: &'static str,
        /// Adapter-supplied reason.
        reason: &'static str,
    },
}

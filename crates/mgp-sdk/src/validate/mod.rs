//! `cloto-connector.json` v1 validation.

mod connector_v1;

pub use connector_v1::validate_v1;

use thiserror::Error;

/// Validation failure modes.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// Wrong `spec_version`.
    #[error("unsupported spec_version: expected 1, got {0}")]
    UnsupportedSpecVersion(u32),
    /// `connector_type` outside the set v1 defines.
    #[error("unsupported connector_type: expected `mgp_server` or `ui_module`, got `{0}`")]
    UnsupportedConnectorType(String),
    /// `magic_seal` missing or malformed.
    #[error("magic_seal must be `sha256:<hex>` with 64 lowercase hex chars")]
    MalformedMagicSeal,
    /// `package_manager` not `uv`.
    #[error("package_manager must be `uv`, got `{0}`")]
    UnsupportedPackageManager(String),
    /// `runtime` not in {python, rust, node, static}.
    #[error("runtime must be one of python|rust|node|static, got `{0}`")]
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
    /// `install.package_manager` / `install.runtime` disagree with what the
    /// `connector_type` says the host does (MGP_CONNECTOR.md §5).
    ///
    /// Both directions are errors. A connector the host launches claiming it
    /// needs no build is one the host cannot build; a connector the host never
    /// launches claiming a runtime is one whose declared runtime can never run,
    /// which leaves `connector_type` unreadable as an answer to "does this
    /// start a process".
    #[error(
        "connector_type `{connector_type}` requires package_manager `{expected_package_manager}` \
         and runtime `{expected_runtime}`, got `{package_manager}` / `{runtime}`"
    )]
    InstallDisagreesWithType {
        /// The declared type.
        connector_type: String,
        /// The declared package manager.
        package_manager: String,
        /// The declared runtime.
        runtime: String,
        /// What this type requires (`uv` for a launching type, else `none`).
        expected_package_manager: &'static str,
        /// What this type requires (a real runtime, or `static`).
        expected_runtime: &'static str,
    },
    /// A panel id is empty or outside the §3.3 charset.
    #[error("panel id must be non-empty lowercase alphanumeric with interior hyphens/underscores, got `{0}`")]
    InvalidPanelId(String),
    /// A panel has an empty `name`.
    #[error("panel `{0}` has an empty name")]
    EmptyPanelName(String),
    /// Two panels in one connector claim the same id.
    ///
    /// Hosts address a panel by connector plus id, so a duplicate is not a
    /// naming preference: one of the two would be unreachable, and which one
    /// depends on the order the host happened to read them in.
    #[error("panel id `{0}` is declared twice in one connector")]
    DuplicatePanelId(String),
}

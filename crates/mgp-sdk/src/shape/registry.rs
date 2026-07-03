//! Conversion of [`ConnectorManifest`] into the `registry.json` entry
//! shape that ClotoCore consumes.
//!
//! Post Phase 5c cutover (ClotoCore PR #121 — `refactor(marketplace):
//! cut RegistryEntry/EnvVarDef over to mgp-sdk v0.2.0`), ClotoCore
//! imports [`RegistryEntry`] / [`InstallShape`] from this module
//! directly (`pub use mgp_sdk::shape::{RegistryEntry, InstallShape}`).
//! There is no longer a parallel definition to keep in lock-step —
//! this module is the single source of truth for the catalog entry
//! wire shape, and future schema changes land here.

use crate::adapters::SourceSpec;
use crate::types::{ConnectorManifest, EnvVarDef, ProviderMeta};
use serde::{Deserialize, Serialize};

/// Install descriptor carried by [`RegistryEntry`].
///
/// Mirrors the shape of `ConnectorManifest.install` for the two fields that
/// the catalog must surface to install consumers (`source` and
/// `package_manager`) without duplicating the install fields that already
/// have flat top-level homes on `RegistryEntry` (`directory`, `runtime`,
/// `bin_name`, `dependencies`).
///
/// `RegistryEntry.install` is `Option<InstallShape>` because:
///
/// - Pre-v0.2 registry.json files (notably `Cloto-dev/cloto-mcp-servers/
///   registry.json`) do not carry an `install` block — they predate the
///   `cloto-connector.json` v1 schema and let the consumer infer a single
///   global tarball source. `None` triggers that legacy behavior on the
///   consumer side (= ClotoCore's `run_install` falls back to its existing
///   monorepo tarball path).
/// - New registries (catalog feeds emitted by `clotohub-web` from
///   `cloto-connector.json` manifests) include `install` with the source
///   honored from the manifest. Consumers branch on
///   `entry.install.as_ref().map(|i| &i.source)` to pick `git` / `raw_url`
///   / `pypi` / `docker`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallShape {
    /// Source descriptor for materializing the connector — see
    /// [`crate::adapters::SourceSpec`].
    pub source: SourceSpec,
    /// Package manager used to materialize the connector. v1 only accepts
    /// `"uv"`; carried as `Option<String>` so registries that omit the
    /// field (or future versions that broaden the vocabulary) can still
    /// round-trip.
    #[serde(default)]
    pub package_manager: Option<String>,
}

/// Single entry in the catalog `registry.json` file.
///
/// Field order, names, and `#[serde(default)]` annotations are
/// load-bearing — they must match `cloto_core::handlers::marketplace::
/// RegistryEntry` exactly so the same JSON parses both sides.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryEntry {
    /// Stable connector id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Short description.
    pub description: String,
    /// Marketplace category.
    pub category: String,
    /// SemVer.
    pub version: String,
    /// Source-tree subdirectory.
    #[serde(default)]
    pub directory: String,
    /// Extra dependency hints.
    #[serde(default)]
    pub dependencies: Vec<String>,
    /// Required env vars.
    #[serde(default)]
    pub env_vars: Vec<EnvVarDef>,
    /// Optional env vars.
    #[serde(default)]
    pub optional_env_vars: Vec<EnvVarDef>,
    /// Marketplace tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// MGP §2.3 trust tier.
    #[serde(default = "default_trust_level")]
    pub trust_level: String,
    /// Host auto-restart policy.
    #[serde(default)]
    pub auto_restart: bool,
    /// Optional icon.
    #[serde(default)]
    pub icon: Option<String>,
    /// Runtime kind.
    #[serde(default = "default_runtime")]
    pub runtime: String,
    /// Optional binary name (for `runtime = rust`).
    #[serde(default)]
    pub bin_name: Option<String>,
    /// Optional changelog.
    #[serde(default)]
    pub changelog: Option<String>,
    /// MGP §8 L0 Magic Seal in `sha256:HEX` form.
    #[serde(default)]
    pub seal: Option<String>,
    /// Plain SHA-256 (64 lowercase hex chars) of the connector's
    /// entry-point file bytes, as recorded by the catalog when the
    /// seal was minted. Lets a consumer verify the integrity of the
    /// fetched entry point without holding the catalog's signing key
    /// (keyless check); `seal` remains the cryptographic counterpart
    /// that the catalog side verifies. New for `mgp-sdk` v0.4.0.
    #[serde(default)]
    pub entry_point_sha256: Option<String>,
    /// The catalog's dual-signature record for the seal, passed through
    /// verbatim from the issuer:
    /// `{"hmac": "<hex>", "ed25519": {"sig": "<base64>", "key_id": "..."}}`.
    ///
    /// A consumer holding the issuer's Ed25519 public key (from its JWKS
    /// endpoint, parsed via `mgp_seal::ed25519::public_key_from_jwk`) can
    /// reconstruct `mgp_seal::canonical_message(id, version,
    /// entry_point_sha256)` and verify the `ed25519.sig` offline — without
    /// trusting the transport the catalog arrived over. Kept as opaque JSON
    /// rather than typed fields so future signature tiers (e.g. a Rekor
    /// inclusion proof) ride along without another schema change. New for
    /// `mgp-sdk` v0.5.0.
    #[serde(default)]
    pub signature_payload: Option<serde_json::Value>,
    /// Optional install descriptor carrying `source` and `package_manager`
    /// from the originating `cloto-connector.json` manifest. `None` (or
    /// absent in JSON) signals that the catalog has no per-entry source
    /// information, and consumers SHOULD fall back to whatever default
    /// install path they previously used (e.g. ClotoCore's hard-coded
    /// monorepo tarball). New for `mgp-sdk` v0.2.0; see [`InstallShape`].
    #[serde(default)]
    pub install: Option<InstallShape>,
    /// LLM-provider metadata for reasoning-engine entries (`category =
    /// "mind"`), carried through from the connector manifest so the host can
    /// seed its provider registry from the catalog rather than a hard-coded
    /// table. `None` for non-engine entries. New for `mgp-sdk` v0.6.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderMeta>,
}

fn default_trust_level() -> String {
    "standard".to_string()
}

fn default_runtime() -> String {
    "python".to_string()
}

/// Convert a [`ConnectorManifest`] into a [`RegistryEntry`].
///
/// The Magic Seal is preserved as-is; it is the responsibility of the
/// emitter (ClotoHub.dev sync worker) to persist a `seals.revoked_at
/// IS NULL` row before serializing the entry. ClotoCore's runtime
/// re-checks the seal independently, so a stale seal here is caught
/// by §10 inv 3 force-untrusted at connect time.
#[must_use]
pub fn manifest_to_registry_entry(m: &ConnectorManifest) -> RegistryEntry {
    RegistryEntry {
        id: m.id.clone(),
        name: m.name.clone(),
        description: m.description.clone(),
        category: m.category.clone(),
        version: m.version.clone(),
        directory: m.install.directory.clone(),
        dependencies: m.install.dependencies.clone(),
        env_vars: m.env_vars.clone(),
        optional_env_vars: m.optional_env_vars.clone(),
        tags: m.tags.clone(),
        trust_level: m.trust_level.clone(),
        auto_restart: m.auto_restart,
        icon: m.icon.clone(),
        runtime: m.install.runtime.clone(),
        bin_name: m.install.bin_name.clone(),
        changelog: m.changelog.clone(),
        seal: Some(m.magic_seal.clone()),
        // The manifest carries neither the entry-point hash nor the
        // dual-signature record; the catalog emitter overrides both from
        // its seal records when available.
        entry_point_sha256: None,
        signature_payload: None,
        // New in v0.2.0: carry through the install source + package_manager.
        // The flat `directory` / `runtime` / `bin_name` / `dependencies`
        // fields above stay populated for backward compatibility with
        // consumers that have not yet migrated to reading `install.source`.
        install: Some(InstallShape {
            source: m.install.source.clone(),
            package_manager: Some(m.install.package_manager.clone()),
        }),
        // Carry engine provider metadata through to the catalog wire so the
        // host can seed its provider registry from the entry (v0.6.0).
        provider: m.provider.clone(),
    }
}

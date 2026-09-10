//! v1 manifest validator.

use super::ValidationError;
use crate::adapters::SourceSpec;
use crate::types::ConnectorManifest;
use crate::{
    CONNECTOR_TYPE_MGP_SERVER, CONNECTOR_TYPE_UI_MODULE, PACKAGE_MANAGER_NONE, PACKAGE_MANAGER_UV,
    RUNTIME_STATIC, SPEC_VERSION,
};

const TRUST_LEVELS: &[&str] = &["core", "standard", "experimental", "untrusted"];
/// Runtimes a host launches, plus `static` for the connectors it does not.
const RUNTIMES: &[&str] = &["python", "rust", "node", RUNTIME_STATIC];
/// Types v1 defines (MGP_CONNECTOR.md §3.4).
const CONNECTOR_TYPES: &[&str] = &[CONNECTOR_TYPE_MGP_SERVER, CONNECTOR_TYPE_UI_MODULE];
/// Package managers v1 defines.
const PACKAGE_MANAGERS: &[&str] = &[PACKAGE_MANAGER_UV, PACKAGE_MANAGER_NONE];

/// Whether a type is one the host starts a process for.
///
/// Separate from "is this type known" on purpose: the two questions had the
/// same answer for every type v1 shipped with, and a `ui_module` is the first
/// one where they differ (§3.4).
fn launches_a_process(connector_type: &str) -> bool {
    connector_type == CONNECTOR_TYPE_MGP_SERVER
}

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
    if !CONNECTOR_TYPES.contains(&manifest.connector_type.as_str()) {
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
    if !PACKAGE_MANAGERS.contains(&manifest.install.package_manager.as_str()) {
        return Err(ValidationError::UnsupportedPackageManager(
            manifest.install.package_manager.clone(),
        ));
    }
    if !RUNTIMES.contains(&manifest.install.runtime.as_str()) {
        return Err(ValidationError::UnsupportedRuntime(
            manifest.install.runtime.clone(),
        ));
    }
    validate_install_matches_type(manifest)?;
    validate_source(&manifest.install.source)?;
    validate_panels(manifest)?;
    Ok(())
}

/// The §5 pairing: what the host does with the connector decides what the
/// install block may say.
///
/// Checked after the two value checks above so a nonsense value reports itself
/// rather than being read as the wrong half of a pair.
fn validate_install_matches_type(manifest: &ConnectorManifest) -> Result<(), ValidationError> {
    let launches = launches_a_process(&manifest.connector_type);
    let pm = manifest.install.package_manager.as_str();
    let runtime = manifest.install.runtime.as_str();

    let agrees = if launches {
        pm != PACKAGE_MANAGER_NONE && runtime != RUNTIME_STATIC
    } else {
        pm == PACKAGE_MANAGER_NONE && runtime == RUNTIME_STATIC
    };
    if agrees {
        return Ok(());
    }
    Err(ValidationError::InstallDisagreesWithType {
        connector_type: manifest.connector_type.clone(),
        package_manager: manifest.install.package_manager.clone(),
        runtime: manifest.install.runtime.clone(),
        expected_package_manager: if launches {
            PACKAGE_MANAGER_UV
        } else {
            PACKAGE_MANAGER_NONE
        },
        expected_runtime: if launches {
            "python|rust|node"
        } else {
            RUNTIME_STATIC
        },
    })
}

/// Panels are addressed by connector plus id, so the ids have to be usable in
/// that address and distinct within the connector.
fn validate_panels(manifest: &ConnectorManifest) -> Result<(), ValidationError> {
    let Some(ui) = manifest.ui.as_ref() else {
        return Ok(());
    };
    let mut seen: Vec<&str> = Vec::with_capacity(ui.panels.len());
    for panel in &ui.panels {
        if !is_well_formed_id(&panel.id) {
            return Err(ValidationError::InvalidPanelId(panel.id.clone()));
        }
        if panel.name.trim().is_empty() {
            return Err(ValidationError::EmptyPanelName(panel.id.clone()));
        }
        if seen.contains(&panel.id.as_str()) {
            return Err(ValidationError::DuplicatePanelId(panel.id.clone()));
        }
        seen.push(&panel.id);
    }
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

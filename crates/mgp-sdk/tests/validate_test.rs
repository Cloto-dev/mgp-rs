//! Validation tests for `cloto-connector.json` v1.

use mgp_sdk::adapters::{GitSpec, SourceSpec};
use mgp_sdk::types::{ConnectorManifest, InstallSpec};
use mgp_sdk::validate::{validate_v1, ValidationError};

fn good_manifest() -> ConnectorManifest {
    ConnectorManifest {
        spec_version: 1,
        connector_type: "mgp_server".to_string(),
        id: "demo-server".to_string(),
        name: "Demo".to_string(),
        description: "demo".to_string(),
        version: "0.1.0".to_string(),
        category: "test".to_string(),
        trust_level: "standard".to_string(),
        magic_seal: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        install: InstallSpec {
            source: SourceSpec::Git(GitSpec {
                url: "https://github.com/Cloto-dev/demo.git".to_string(),
                reference: String::new(),
                subdir: None,
            }),
            package_manager: "uv".to_string(),
            runtime: "python".to_string(),
            dependencies: vec![],
            directory: "demo".to_string(),
            bin_name: None,
        },
        icon: None,
        tags: vec![],
        host_compatibility: vec![],
        env_vars: vec![],
        optional_env_vars: vec![],
        auto_restart: false,
        changelog: None,
        provider: None,
    }
}

#[test]
fn valid_v1_manifest_passes() {
    assert!(validate_v1(&good_manifest()).is_ok());
}

#[test]
fn rejects_wrong_spec_version() {
    let mut m = good_manifest();
    m.spec_version = 2;
    assert_eq!(
        validate_v1(&m),
        Err(ValidationError::UnsupportedSpecVersion(2))
    );
}

#[test]
fn rejects_wrong_connector_type() {
    let mut m = good_manifest();
    m.connector_type = "skill".to_string();
    assert_eq!(
        validate_v1(&m),
        Err(ValidationError::UnsupportedConnectorType(
            "skill".to_string()
        ))
    );
}

#[test]
fn rejects_malformed_magic_seal() {
    let mut m = good_manifest();
    m.magic_seal = "not-a-seal".to_string();
    assert_eq!(validate_v1(&m), Err(ValidationError::MalformedMagicSeal));
    m.magic_seal = "sha256:tooshort".to_string();
    assert_eq!(validate_v1(&m), Err(ValidationError::MalformedMagicSeal));
}

#[test]
fn rejects_uppercase_and_mixed_case_magic_seal() {
    // `mgp_seal::compute_seal` emits lowercase hex; `verify_seal` does a
    // byte-exact comparison. Uppercase or mixed-case seals can never verify,
    // so the validator MUST reject them at format-check time.
    let mut m = good_manifest();
    m.magic_seal = format!("sha256:{}", "A".repeat(64));
    assert_eq!(validate_v1(&m), Err(ValidationError::MalformedMagicSeal));
    m.magic_seal = format!("sha256:aA{}", "0".repeat(62));
    assert_eq!(validate_v1(&m), Err(ValidationError::MalformedMagicSeal));
    m.magic_seal = format!("sha256:{}F", "0".repeat(63));
    assert_eq!(validate_v1(&m), Err(ValidationError::MalformedMagicSeal));
}

#[test]
fn rejects_non_uv_package_manager() {
    let mut m = good_manifest();
    m.install.package_manager = "pip".to_string();
    assert_eq!(
        validate_v1(&m),
        Err(ValidationError::UnsupportedPackageManager(
            "pip".to_string()
        ))
    );
}

#[test]
fn rejects_unknown_runtime() {
    let mut m = good_manifest();
    m.install.runtime = "ruby".to_string();
    assert_eq!(
        validate_v1(&m),
        Err(ValidationError::UnsupportedRuntime("ruby".to_string()))
    );
}

#[test]
fn rejects_unknown_trust_level() {
    let mut m = good_manifest();
    m.trust_level = "elite".to_string();
    assert_eq!(
        validate_v1(&m),
        Err(ValidationError::UnsupportedTrustLevel("elite".to_string()))
    );
}

#[test]
fn rejects_ids_outside_charset() {
    let mut m = good_manifest();
    m.id = "Demo_Server".to_string(); // uppercase
    assert_eq!(validate_v1(&m), Err(ValidationError::InvalidId));
    m.id = String::new();
    assert_eq!(validate_v1(&m), Err(ValidationError::InvalidId));
    m.id = "-leading".to_string();
    assert_eq!(validate_v1(&m), Err(ValidationError::InvalidId));
    m.id = "_leading".to_string();
    assert_eq!(validate_v1(&m), Err(ValidationError::InvalidId));
    m.id = "trailing_".to_string();
    assert_eq!(validate_v1(&m), Err(ValidationError::InvalidId));
    m.id = "dotted.id".to_string();
    assert_eq!(validate_v1(&m), Err(ValidationError::InvalidId));
}

#[test]
fn accepts_snake_and_kebab_ids() {
    // MGP_CONNECTOR.md §3.3: underscores joined hyphens in the id charset
    // (2026-07-05 additive change) so host-side snake_case server ids flow
    // through unchanged.
    for id in ["agent_utils", "agent-utils", "a", "a2", "mixed_style-id"] {
        let mut m = good_manifest();
        m.id = id.to_string();
        assert_eq!(validate_v1(&m), Ok(()), "id `{id}` must validate");
    }
}

#[test]
fn rejects_invalid_git_source() {
    let mut m = good_manifest();
    m.install.source = SourceSpec::Git(GitSpec {
        url: String::new(),
        reference: String::new(),
        subdir: None,
    });
    assert!(matches!(
        validate_v1(&m),
        Err(ValidationError::InvalidSource { kind: "git", .. })
    ));
}

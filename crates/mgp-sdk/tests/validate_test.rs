//! Validation tests for `cloto-connector.json` v1.

use mgp_sdk::adapters::{GitSpec, SourceSpec};
use mgp_sdk::types::{ConnectorManifest, InstallSpec, PanelDeclaration, UiBlock};
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
        ui: None,
    }
}

/// A connector that ships a panel and no server (MGP_CONNECTOR.md §3.4).
fn panel_manifest() -> ConnectorManifest {
    let mut m = good_manifest();
    m.connector_type = "ui_module".to_string();
    m.id = "published-viewer".to_string();
    m.install.package_manager = "none".to_string();
    m.install.runtime = "static".to_string();
    m.ui = Some(UiBlock {
        panels: vec![panel("console")],
    });
    m
}

fn panel(id: &str) -> PanelDeclaration {
    PanelDeclaration {
        id: id.to_string(),
        name: "Console".to_string(),
        description: String::new(),
        version: String::new(),
        entry: "index.html".to_string(),
        icon: None,
        requires: vec!["GET /api/published".to_string()],
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

// ── ui_module (MGP_CONNECTOR.md §3.4, §4.1, §5) ──────────────────────────────

#[test]
fn panel_only_connector_passes() {
    assert_eq!(validate_v1(&panel_manifest()), Ok(()));
}

/// The half that stops a panel from claiming a runtime that would never run.
/// Without it `connector_type` stops answering "does this start a process",
/// because a `ui_module` could declare python and nothing would object.
#[test]
fn rejects_a_panel_connector_that_claims_a_runtime() {
    let mut m = panel_manifest();
    m.install.package_manager = "uv".to_string();
    m.install.runtime = "python".to_string();
    assert_eq!(
        validate_v1(&m),
        Err(ValidationError::InstallDisagreesWithType {
            connector_type: "ui_module".to_string(),
            package_manager: "uv".to_string(),
            runtime: "python".to_string(),
            expected_package_manager: "none",
            expected_runtime: "static",
        })
    );
}

/// And the other half: a server that says it needs no build is a server the
/// host cannot build.
#[test]
fn rejects_a_server_that_declares_nothing_to_build() {
    let mut m = good_manifest();
    m.install.package_manager = "none".to_string();
    m.install.runtime = "static".to_string();
    assert_eq!(
        validate_v1(&m),
        Err(ValidationError::InstallDisagreesWithType {
            connector_type: "mgp_server".to_string(),
            package_manager: "none".to_string(),
            runtime: "static".to_string(),
            expected_package_manager: "uv",
            expected_runtime: "python|rust|node",
        })
    );
}

/// A mixed pair is still a disagreement — the check is on both fields, not on
/// whichever one happens to be read first.
#[test]
fn rejects_a_panel_connector_that_agrees_only_halfway() {
    let mut m = panel_manifest();
    m.install.package_manager = "uv".to_string();
    assert!(matches!(
        validate_v1(&m),
        Err(ValidationError::InstallDisagreesWithType { .. })
    ));
}

#[test]
fn a_server_may_also_ship_a_panel() {
    let mut m = good_manifest();
    m.ui = Some(UiBlock {
        panels: vec![panel("dashboard")],
    });
    assert_eq!(validate_v1(&m), Ok(()));
}

#[test]
fn rejects_two_panels_with_one_id() {
    let mut m = panel_manifest();
    m.ui = Some(UiBlock {
        panels: vec![panel("console"), panel("console")],
    });
    assert_eq!(
        validate_v1(&m),
        Err(ValidationError::DuplicatePanelId("console".to_string()))
    );
}

#[test]
fn rejects_a_panel_id_outside_the_charset() {
    let mut m = panel_manifest();
    m.ui = Some(UiBlock {
        panels: vec![panel("Console")],
    });
    assert_eq!(
        validate_v1(&m),
        Err(ValidationError::InvalidPanelId("Console".to_string()))
    );
}

#[test]
fn rejects_a_panel_with_no_name() {
    let mut m = panel_manifest();
    let mut p = panel("console");
    p.name = "  ".to_string();
    m.ui = Some(UiBlock { panels: vec![p] });
    assert_eq!(
        validate_v1(&m),
        Err(ValidationError::EmptyPanelName("console".to_string()))
    );
}

/// The block has to survive a round trip: a manifest read through this SDK and
/// written back out must still carry its panels, or a consumer that edits a
/// manifest would drop the face off every connector it touches.
#[test]
fn the_ui_block_round_trips() {
    let json = serde_json::to_string(&panel_manifest()).expect("serialize");
    assert!(json.contains("\"panels\""), "panels dropped on serialize");
    let back: ConnectorManifest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, panel_manifest());
    // And a manifest without the block stays without it, rather than gaining
    // an empty one that a diff would show as a change.
    let plain = serde_json::to_string(&good_manifest()).expect("serialize");
    assert!(
        !plain.contains("\"ui\""),
        "absent block should not be emitted"
    );
}

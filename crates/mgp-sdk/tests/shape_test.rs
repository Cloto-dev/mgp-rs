//! Shape conversion tests: `ConnectorManifest` → `RegistryEntry`.

use mgp_sdk::adapters::{GitSpec, SourceSpec};
use mgp_sdk::shape::{manifest_to_registry_entry, InstallShape, RegistryEntry};
use mgp_sdk::types::{ConnectorManifest, EnvVarDef, InstallSpec};

fn manifest_with_full_optional_fields() -> ConnectorManifest {
    ConnectorManifest {
        spec_version: 1,
        connector_type: "mgp_server".to_string(),
        id: "shape-demo".to_string(),
        name: "Shape Demo".to_string(),
        description: "shape conversion exhibit".to_string(),
        version: "1.2.3".to_string(),
        category: "demo".to_string(),
        trust_level: "experimental".to_string(),
        magic_seal: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            .to_string(),
        install: InstallSpec {
            source: SourceSpec::Git(GitSpec {
                url: "https://github.com/Cloto-dev/x.git".to_string(),
                reference: "v1.2.3".to_string(),
                subdir: None,
            }),
            package_manager: "uv".to_string(),
            runtime: "rust".to_string(),
            dependencies: vec!["dep-a".to_string(), "dep-b".to_string()],
            directory: "x".to_string(),
            bin_name: Some("xbin".to_string()),
        },
        icon: Some("icon.svg".to_string()),
        tags: vec!["t1".to_string()],
        host_compatibility: vec!["clotocore".to_string()],
        env_vars: vec![EnvVarDef {
            name: "X_API_KEY".to_string(),
            default: None,
            description: Some("API key".to_string()),
        }],
        optional_env_vars: vec![EnvVarDef {
            name: "X_DEBUG".to_string(),
            default: Some("0".to_string()),
            description: None,
        }],
        auto_restart: true,
        changelog: Some("v1.2.3 release".to_string()),
    }
}

#[test]
fn manifest_to_registry_entry_preserves_all_fields() {
    let m = manifest_with_full_optional_fields();
    let entry = manifest_to_registry_entry(&m);

    assert_eq!(entry.id, m.id);
    assert_eq!(entry.name, m.name);
    assert_eq!(entry.description, m.description);
    assert_eq!(entry.category, m.category);
    assert_eq!(entry.version, m.version);
    assert_eq!(entry.directory, m.install.directory);
    assert_eq!(entry.dependencies, m.install.dependencies);
    assert_eq!(entry.env_vars, m.env_vars);
    assert_eq!(entry.optional_env_vars, m.optional_env_vars);
    assert_eq!(entry.tags, m.tags);
    assert_eq!(entry.trust_level, m.trust_level);
    assert_eq!(entry.auto_restart, m.auto_restart);
    assert_eq!(entry.icon, m.icon);
    assert_eq!(entry.runtime, m.install.runtime);
    assert_eq!(entry.bin_name, m.install.bin_name);
    assert_eq!(entry.changelog, m.changelog);
    assert_eq!(entry.seal.as_deref(), Some(m.magic_seal.as_str()));

    // v0.2.0: install descriptor carries source + package_manager.
    let install = entry.install.as_ref().expect("install populated");
    assert_eq!(install.source, m.install.source);
    assert_eq!(install.package_manager.as_deref(), Some("uv"));
}

#[test]
fn registry_entry_install_round_trips_through_json() {
    let entry = manifest_to_registry_entry(&manifest_with_full_optional_fields());
    let json = serde_json::to_string(&entry).expect("serialize");
    // Re-parse and confirm the install block survives the round-trip.
    let again: RegistryEntry = serde_json::from_str(&json).expect("parse");
    let install = again.install.expect("install present after re-parse");
    assert!(matches!(install.source, SourceSpec::Git(_)));
    assert_eq!(install.package_manager.as_deref(), Some("uv"));
}

#[test]
fn registry_entry_without_install_block_parses_as_none() {
    // Pre-v0.2 registry.json shape: no `install` field at all.
    let pre_v02 = r#"{
        "id": "legacy",
        "name": "Legacy",
        "description": "predates install field",
        "category": "test",
        "version": "0.1.0",
        "directory": "legacy",
        "runtime": "python"
    }"#;
    let entry: RegistryEntry = serde_json::from_str(pre_v02).expect("parse pre-v0.2");
    assert!(
        entry.install.is_none(),
        "missing install must deserialize as None so consumers fall back to legacy install path"
    );
    // Flat fields stay populated for backward-compatible consumers.
    assert_eq!(entry.directory, "legacy");
    assert_eq!(entry.runtime, "python");
}

#[test]
fn registry_entry_with_explicit_install_pypi_round_trips() {
    // Forward-compatible shape: a registry that emits an install block with
    // a pypi source (a connector that ships from PyPI rather than the
    // monorepo tarball).
    let with_pypi = r#"{
        "id": "pypi-demo",
        "name": "PyPI Demo",
        "description": "from pypi",
        "category": "test",
        "version": "0.1.0",
        "install": {
            "source": { "type": "pypi", "package": "demo-mcp", "version": "1.2.3" },
            "package_manager": "uv"
        }
    }"#;
    let entry: RegistryEntry = serde_json::from_str(with_pypi).expect("parse pypi install");
    let install = entry.install.expect("install present");
    match install.source {
        SourceSpec::Pypi(p) => {
            assert_eq!(p.package, "demo-mcp");
            assert_eq!(p.version.as_deref(), Some("1.2.3"));
        }
        other => panic!("expected pypi source, got {other:?}"),
    }
}

#[test]
fn install_shape_can_be_constructed_directly() {
    // Construct InstallShape without going through manifest_to_registry_entry,
    // mirroring how downstream consumers (e.g. ClotoCore tests) might
    // synthesize entries.
    let shape = InstallShape {
        source: SourceSpec::Git(GitSpec {
            url: "https://example.com/x.git".to_string(),
            reference: String::new(),
            subdir: None,
        }),
        package_manager: None,
    };
    let json = serde_json::to_string(&shape).expect("serialize");
    let again: InstallShape = serde_json::from_str(&json).expect("parse");
    assert_eq!(shape, again);
}

#[test]
fn registry_entry_round_trips_through_json() {
    let entry = manifest_to_registry_entry(&manifest_with_full_optional_fields());
    let json = serde_json::to_string(&entry).expect("serialize");
    let again: RegistryEntry = serde_json::from_str(&json).expect("parse");
    assert_eq!(entry, again);
}

#[test]
fn env_var_def_accepts_legacy_key_alias() {
    // Pre-v1 registries (notably cloto-mcp-servers/registry.json) emit
    // `key` instead of `name` and carry a `default` value. The SDK MUST
    // deserialize this shape unchanged so ClotoCore can adopt the SDK
    // type without a parallel wire migration. See MGP_CONNECTOR §2 and the
    // 2026-05-15 v1 schema additive amendment in mgp-spec.
    let legacy = r#"{ "key": "CLOTO_API_URL", "default": "http://127.0.0.1:8081", "description": "Kernel API URL" }"#;
    let envvar: EnvVarDef = serde_json::from_str(legacy).expect("alias parse");
    assert_eq!(envvar.name, "CLOTO_API_URL");
    assert_eq!(envvar.default.as_deref(), Some("http://127.0.0.1:8081"));
    assert_eq!(envvar.description.as_deref(), Some("Kernel API URL"));

    // Spec-canonical shape: emits `name`. Both forms must reach the same
    // logical value.
    let canonical = r#"{ "name": "CLOTO_API_URL", "default": "http://127.0.0.1:8081", "description": "Kernel API URL" }"#;
    let envvar2: EnvVarDef = serde_json::from_str(canonical).expect("canonical parse");
    assert_eq!(envvar, envvar2);
}

#[test]
fn env_var_def_serializes_canonical_name_field() {
    // The alias is for input only — the SDK emits `name`, never `key`.
    let envvar = EnvVarDef {
        name: "FOO".to_string(),
        default: Some("bar".to_string()),
        description: None,
    };
    let json = serde_json::to_string(&envvar).expect("serialize");
    assert!(
        json.contains("\"name\":\"FOO\""),
        "must serialize canonical `name` field, got: {json}"
    );
    assert!(
        !json.contains("\"key\""),
        "must not echo the legacy `key` alias on serialize, got: {json}"
    );
}

#[test]
fn registry_entry_omitted_optional_fields_use_defaults_on_parse() {
    // ClotoCore historically tolerates missing optional fields.
    // Confirm the shape stays compatible.
    let minimal = r#"{
        "id": "x",
        "name": "X",
        "description": "x",
        "category": "c",
        "version": "0.1.0"
    }"#;
    let entry: RegistryEntry = serde_json::from_str(minimal).expect("parse minimal");
    assert_eq!(entry.id, "x");
    assert_eq!(entry.trust_level, "standard"); // default
    assert_eq!(entry.runtime, "python"); // default
    assert!(entry.seal.is_none());
}

#[test]
fn registry_entry_signature_payload_defaults_to_none() {
    // The manifest never carries the dual-signature record — only the
    // catalog emitter (reading its seals table) populates it.
    let entry = manifest_to_registry_entry(&manifest_with_full_optional_fields());
    assert!(entry.signature_payload.is_none());

    // Pre-v0.5 registry.json shape: no `signature_payload` field at all.
    let pre_v05 = r#"{
        "id": "legacy",
        "name": "Legacy",
        "description": "predates signature_payload field",
        "category": "test",
        "version": "0.1.0",
        "directory": "legacy",
        "runtime": "python"
    }"#;
    let entry: RegistryEntry = serde_json::from_str(pre_v05).expect("parse pre-v0.5");
    assert!(entry.signature_payload.is_none());
}

#[test]
fn registry_entry_signature_payload_round_trips_verbatim() {
    // The catalog passes the issuer's dual-signature record through as
    // opaque JSON; the consumer must receive it byte-equivalent so the
    // Ed25519 sub-object verifies against the reconstructed canonical
    // message. Unknown future tiers (e.g. "rekor") must survive too.
    let payload = serde_json::json!({
        "hmac": "ab".repeat(32),
        "ed25519": {
            "sig": "c2lnbmF0dXJlLWJ5dGVz",
            "key_id": "clotohub-master-v1"
        },
        "rekor": { "log_index": 42 }
    });

    let mut entry = manifest_to_registry_entry(&manifest_with_full_optional_fields());
    entry.signature_payload = Some(payload.clone());

    let json = serde_json::to_string(&entry).expect("serialize");
    let again: RegistryEntry = serde_json::from_str(&json).expect("parse");
    assert_eq!(again.signature_payload, Some(payload));
}

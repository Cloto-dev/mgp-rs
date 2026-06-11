//! Adapter validation tests.

use mgp_sdk::adapters::{DockerSpec, GitSpec, PypiSpec, RawUrlSpec};

#[test]
fn git_url_validation() {
    let ok = GitSpec {
        url: "https://github.com/Cloto-dev/x.git".to_string(),
        reference: String::new(),
        subdir: None,
    };
    assert!(ok.check_url().is_ok());
    let scp = GitSpec {
        url: "git@github.com:Cloto-dev/x.git".to_string(),
        reference: String::new(),
        subdir: None,
    };
    assert!(scp.check_url().is_ok());
    let empty = GitSpec {
        url: String::new(),
        reference: String::new(),
        subdir: None,
    };
    assert!(empty.check_url().is_err());
    let bogus = GitSpec {
        url: "not a url".to_string(),
        reference: String::new(),
        subdir: None,
    };
    assert!(bogus.check_url().is_err());
}

#[test]
fn raw_url_validation() {
    let ok = RawUrlSpec {
        url: "https://example.com/x.tar.gz".to_string(),
        sha256: Some("a".repeat(64)),
        subdir: None,
    };
    assert!(ok.check().is_ok());
    let wrong_scheme = RawUrlSpec {
        url: "ftp://example.com/x".to_string(),
        sha256: None,
        subdir: None,
    };
    assert!(wrong_scheme.check().is_err());
    let bad_hash = RawUrlSpec {
        url: "https://example.com/x".to_string(),
        sha256: Some("not-hex".to_string()),
        subdir: None,
    };
    assert!(bad_hash.check().is_err());
}

#[test]
fn raw_url_subdir_roundtrip_and_default() {
    // Pre-0.3.0 JSON without `subdir` must deserialize (None).
    let legacy: RawUrlSpec =
        serde_json::from_str(r#"{"url":"https://example.com/x.tar.gz"}"#).unwrap();
    assert_eq!(legacy.subdir, None);

    // Round-trip preserves a set subdir.
    let spec = RawUrlSpec {
        url: "https://example.com/x.tar.gz".to_string(),
        sha256: Some("a".repeat(64)),
        subdir: Some("servers/cscheduler".to_string()),
    };
    assert!(spec.check().is_ok());
    let json = serde_json::to_string(&spec).unwrap();
    let back: RawUrlSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back, spec);
}

#[test]
fn pypi_install_argument_format() {
    let pinned = PypiSpec {
        package: "demo".to_string(),
        version: Some("1.2.3".to_string()),
    };
    assert_eq!(pinned.install_argument(), "demo==1.2.3");
    let unpinned = PypiSpec {
        package: "demo".to_string(),
        version: None,
    };
    assert_eq!(unpinned.install_argument(), "demo");
    let empty_version = PypiSpec {
        package: "demo".to_string(),
        version: Some(String::new()),
    };
    assert_eq!(empty_version.install_argument(), "demo");
}

#[test]
fn pypi_validation() {
    let ok = PypiSpec {
        package: "demo".to_string(),
        version: None,
    };
    assert!(ok.check().is_ok());
    let empty = PypiSpec {
        package: String::new(),
        version: None,
    };
    assert!(empty.check().is_err());
    let whitespace = PypiSpec {
        package: "demo with space".to_string(),
        version: None,
    };
    assert!(whitespace.check().is_err());
}

#[test]
fn docker_canonical_reference() {
    let pinned = DockerSpec {
        image: "ghcr.io/cloto-dev/foo".to_string(),
        tag: Some("1.0.0".to_string()),
    };
    assert_eq!(pinned.canonical_reference(), "ghcr.io/cloto-dev/foo:1.0.0");
    assert!(!pinned.is_unpinned());

    let no_tag = DockerSpec {
        image: "nginx".to_string(),
        tag: None,
    };
    assert_eq!(no_tag.canonical_reference(), "nginx:latest");
    assert!(no_tag.is_unpinned());

    let latest = DockerSpec {
        image: "nginx".to_string(),
        tag: Some("latest".to_string()),
    };
    assert!(latest.is_unpinned());
}

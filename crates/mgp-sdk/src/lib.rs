//! Pure-logic SDK for MGP connectors.
//!
//! `mgp-sdk` provides the shared logic that ClotoHub.dev's catalog
//! sync worker and ClotoCore's install path both need to handle a
//! `cloto-connector.json` manifest:
//!
//! - [`types`] — Rust definitions for the v1 manifest schema.
//! - [`validate`] — declarative validation against the v1 contract.
//! - [`adapters`] — typed wrappers over the four v1 source kinds
//!   (`git`, `raw_url`, `pypi`, `docker`); pure logic only — actual
//!   network IO is the consumer's concern.
//! - [`shape`] — conversion from a manifest into the `registry.json`
//!   entry shape that ClotoCore consumes today.
//!
//! The crate is intentionally `no_std`-compatible-spirited (no `tokio`,
//! no `reqwest`) so it can be reused from both axum-based ClotoHub.dev
//! and the embedded ClotoCore install path without forcing either to
//! adopt unwanted dependencies.
//!
//! See `project_clotohub_phase_5_design.md` §4-B for the design
//! rationale (mgp-rs workspace consolidation, language-as-strong-axis,
//! direct fallback fairness).

#![deny(missing_docs)]

pub mod adapters;
pub mod shape;
pub mod types;
pub mod validate;

pub use types::{ConnectorManifest, PanelDeclaration, ProviderMeta, ProviderQuirks, UiBlock};
pub use validate::ValidationError;

/// Spec version this SDK targets.
pub const SPEC_VERSION: u32 = 1;

/// `connector_type` for a connector the host starts a process from.
pub const CONNECTOR_TYPE_MGP_SERVER: &str = "mgp_server";

/// `connector_type` for a connector whose files the host serves and whose
/// processes the host never starts (MGP_CONNECTOR.md §3.4).
pub const CONNECTOR_TYPE_UI_MODULE: &str = "ui_module";

/// Package manager for a connector the host builds.
pub const PACKAGE_MANAGER_UV: &str = "uv";

/// `package_manager` for a connector there is nothing to build.
pub const PACKAGE_MANAGER_NONE: &str = "none";

/// `runtime` for a connector there is nothing to launch.
pub const RUNTIME_STATIC: &str = "static";

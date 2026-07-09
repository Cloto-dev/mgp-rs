//! Rust types for the `cloto-connector.json` v1 manifest schema.
//!
//! These mirror the schema declared in `project_clotohub_design.md` §
//! cloto-connector.json. Unknown fields are ignored on deserialize to
//! preserve forward-compat (v1 → v2 additive evolution); known fields
//! are preserved on serialize.

use crate::adapters::SourceSpec;
use serde::{Deserialize, Serialize};

/// Top-level cloto-connector.json document (v1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectorManifest {
    /// Manifest schema version. Must equal `1` for v1.
    pub spec_version: u32,
    /// Connector kind. v1 only accepts `"mgp_server"`.
    pub connector_type: String,
    /// Stable connector identifier (`[a-z0-9]([a-z0-9_-]*[a-z0-9])?`,
    /// MGP_CONNECTOR.md §3.3 — kebab-case recommended, underscores legal).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Short description.
    pub description: String,
    /// Connector version (SemVer).
    pub version: String,
    /// Marketplace category.
    pub category: String,
    /// MGP §2.3 trust tier: `core | standard | experimental | untrusted`.
    pub trust_level: String,
    /// MGP §8 L0 Magic Seal in `sha256:<hex>` form (64 lowercase hex chars).
    /// Required at registration.
    pub magic_seal: String,
    /// Install/runtime declaration.
    pub install: InstallSpec,
    /// Optional UI metadata.
    #[serde(default)]
    pub icon: Option<String>,
    /// Tag set for marketplace filtering.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Hosts that can run this connector
    /// (`clotocore | claude-code | claude-desktop | ...`).
    #[serde(default)]
    pub host_compatibility: Vec<String>,
    /// Required environment variables.
    #[serde(default)]
    pub env_vars: Vec<EnvVarDef>,
    /// Optional environment variables.
    #[serde(default)]
    pub optional_env_vars: Vec<EnvVarDef>,
    /// Auto-restart policy for the host.
    #[serde(default)]
    pub auto_restart: bool,
    /// Optional CHANGELOG content.
    #[serde(default)]
    pub changelog: Option<String>,
    /// Optional LLM-provider metadata for reasoning-engine connectors
    /// (`category = "mind"`). When present, the host seeds/refreshes its
    /// per-provider credential row (upstream API URL, auth style, default
    /// model, quirks) from this block instead of a hard-coded table — so a
    /// new engine needs only a catalog entry, no host change. `None` for
    /// non-engine connectors. New for `mgp-sdk` v0.6.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderMeta>,
}

/// LLM-provider metadata declared by a reasoning-engine connector.
///
/// Carries only *metadata* (upstream endpoint, auth style, default model,
/// example model id, quirks) — never user secrets. The host merges this into
/// its provider registry without overwriting user-set fields (API key, chosen
/// model, context length, thinking mode).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderMeta {
    /// Upstream provider API URL
    /// (e.g. `https://api.deepseek.com/chat/completions`).
    pub api_url: String,
    /// Auth header style: `"bearer"` (default) or `"x-api-key"` (Anthropic-style).
    #[serde(default = "default_auth_type")]
    pub auth_type: String,
    /// Default model id seeded when the provider row is first created. The host
    /// MUST NOT overwrite an existing user-chosen model with this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_default: Option<String>,
    /// Request timeout (seconds) for calls to this provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u32>,
    /// Example model id for the host's model-input placeholder
    /// (e.g. LM Studio's `org/name` vs Ollama's `name:tag`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_placeholder: Option<String>,
    /// Provider-specific quirks the host needs to talk to this backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quirks: Option<ProviderQuirks>,
}

/// Provider quirks declared as data so the host needs no provider-specific
/// branches (mirrors ClotoCore's `ProviderQuirks`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderQuirks {
    /// Provider does not require an API key (Ollama, local LM Studio).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_api_key: bool,
    /// Native models-list path (absolute URL path, e.g. `/api/tags`) that
    /// overrides the OpenAI-compatible `.../models` derivation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub models_endpoint_path: Option<String>,
    /// MCP tool name on the engine server to relay a live model switch, for
    /// providers whose engine binds the model at startup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switch_model_tool: Option<String>,
}

fn default_auth_type() -> String {
    "bearer".to_string()
}

/// Install / runtime declaration block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallSpec {
    /// Source descriptor — see [`SourceSpec`].
    pub source: SourceSpec,
    /// Package manager used to materialize the connector. v1: `"uv"`.
    pub package_manager: String,
    /// Runtime: `python | rust | node`.
    pub runtime: String,
    /// Optional list of extra dependencies the host should resolve.
    #[serde(default)]
    pub dependencies: Vec<String>,
    /// Subdirectory inside the source tree where the connector lives.
    #[serde(default)]
    pub directory: String,
    /// Binary name produced by the build (relevant for `runtime = rust`).
    #[serde(default)]
    pub bin_name: Option<String>,
}

/// Environment variable contract entry.
///
/// `name` deserialization accepts the legacy field name `key` as an alias to
/// preserve compatibility with pre-v1 registry shapes (notably the legacy
/// `cloto-mcp-servers/registry.json` wire which emits `key` rather than
/// `name`). The alias is implementation-side leniency only — see MGP_CONNECTOR
/// §2 (Authority and Drift Policy); the (α) implementation-cost-leniency
/// taxonomy applies. Producers MUST emit `name`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvVarDef {
    /// Variable name. Spec-level canonical key.
    #[serde(alias = "key")]
    pub name: String,
    /// Default value the host SHOULD inject when the operator has not
    /// supplied one. Hosts MUST still treat the variable as set for
    /// downstream contracts when defaulted. `None` means no default.
    #[serde(default)]
    pub default: Option<String>,
    /// Human description.
    #[serde(default)]
    pub description: Option<String>,
}

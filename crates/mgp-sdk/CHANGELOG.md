# Changelog

All notable changes to `mgp-sdk` are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-06-11

### Added

- `RegistryEntry.entry_point_sha256: Option<String>` — plain SHA-256
  of the connector's entry-point file bytes, recorded by the catalog
  when the seal was minted. Lets a consumer verify entry-point
  integrity without holding the catalog's signing key (keyless
  check); `seal` remains the cryptographic counterpart verified
  catalog-side. Serde-defaulted; existing registries deserialize
  unchanged. `manifest_to_registry_entry` emits `None` (the manifest
  does not carry the hash — catalog emitters override it from their
  seal records).

  Minor bump: adding a public field breaks downstream struct-literal
  construction of `RegistryEntry`.

## [0.3.0] - 2026-06-11

### Added

- `RawUrlSpec.subdir: Option<String>` — optional subdirectory inside
  the extracted archive tree where the connector lives (after the
  consumer strips a single shared top-level prefix,
  GitHub-archive-style). Lets one monorepo tarball serve multiple
  connectors through a `raw_url` source; mirrors `GitSpec::subdir`.
  Serde-defaulted, so existing manifests deserialize unchanged.

  Minor (not patch) bump: adding a public field is a breaking change
  for downstream code constructing `RawUrlSpec` with a struct
  literal.

## [0.2.0] - 2026-05-17

### Added

- (Backfilled entry — released as tag `mgp-sdk-v0.2.0`, PR #6.)
  `InstallShape` on `RegistryEntry`, and `EnvVarDef` alias / default
  support for registry shape conversion.

## [0.1.2] - 2026-05-11

### Changed

- `validate::validate_v1` now rejects `magic_seal` values containing
  uppercase hex characters. `mgp_seal::compute_seal` emits lowercase
  hex (via `hex::encode`) and `verify_seal` does a byte-exact
  comparison, so an uppercase or mixed-case seal can never verify.
  Previously the format check used `is_ascii_hexdigit` and accepted
  inputs that would silently fail at verify time, masking the bug
  until the connector was actually loaded. This tightens the
  format-check layer to match the operational truth and aligns the
  SDK with the `cloto-connector.json` v1 JSON Schema
  (`mgp-spec/schemas/connector/v1.json`).

  No behavior change for inputs that any consumer was correctly
  using: every seal that `mgp_seal::compute_seal` ever produced is
  lowercase, every example in `MGP_ISOLATION_DESIGN.md` is
  lowercase, and every catalog fixture in `clotohub-web` is
  lowercase. Treated as a bug fix; downstream pins MAY stay on
  `0.1` (no API change).

## [0.1.1] - 2026-05-09

### Removed

- Dropped the `mgp-seal` dependency that v0.1.0 carried in
  anticipation of Magic Seal verification helpers — those helpers
  did not land in v0.1.0, and the unused dep caused downstream
  consumers (e.g. `clotohub-web`) that also depend on `mgp-seal`
  directly to compile two source-distinct copies of `mgp-seal` at
  the same commit because cargo treats `?tag=mgp-sdk-vX.Y.Z` and
  `?tag=mgp-seal-vX.Y.Z` as separate sources. The dep will return
  in v0.2.0 alongside the helpers.

## [0.1.0] - 2026-05-08

### Added

- Initial release. Pure-logic SDK for the `cloto-connector.json` v1
  manifest, intentionally no `tokio` / no `reqwest` so the same crate
  is reusable from both ClotoHub.dev's catalog sync worker and
  ClotoCore's install path.
- `types::ConnectorManifest` — Rust definitions for the v1 schema
  with forward-compat `#[serde(default)]` and unknown-field tolerance.
- `validate::validate_v1` — declarative checks for `spec_version`,
  `connector_type`, kebab-case `id`, MGP §2.3 `trust_level`,
  Magic Seal format (`sha256:HEX`), `package_manager == "uv"`,
  `runtime ∈ {python, rust, node}`, and source sub-spec.
- `adapters::{GitSpec, RawUrlSpec, PypiSpec, DockerSpec}` — typed
  wrappers over the four v1 source kinds, each with a pure
  `check()` validator. `SourceSpec::kind()` exposes the JSON tag.
- `shape::manifest_to_registry_entry` — conversion from a manifest
  into a `registry.json` entry that ClotoCore consumes today, plus
  a [`RegistryEntry`] type with field layout mirroring
  `cloto_core::handlers::marketplace::RegistryEntry` byte-for-byte.

### Out of scope (Phase 6+ candidates)

- `hf_hub`, `npm`, `ipfs`, `custom` source adapters.
- A formal JSON Schema document for `cloto-connector.json` (lives
  in `mgp-spec`; this crate is a consumer).
- Network IO (delegated to consumers — see `project_clotohub_phase_5_design.md`
  §4-B on the pure-logic decision).

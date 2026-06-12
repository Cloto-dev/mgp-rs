//! Integration tests for the Ed25519 public API.
//!
//! Unit tests in `src/ed25519.rs` exercise the internals; these tests pin the
//! end-to-end contract a downstream consumer (ClotoCore, ClotoHub) sees:
//!
//! - keypair generation, sign / verify, and on-the-wire base64 / JWK formats
//!   round-trip across module boundaries
//! - ClotoHub's "issue once, verify offline" workflow works as advertised
//! - the HMAC API from v0.1.x is untouched and still imports cleanly alongside
//!   the new Ed25519 surface

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use mgp_seal::ed25519::{
    generate_keypair, private_key_from_base64, public_key_to_jwk, sign, verify, KeyId, PublicKey,
    Signature, PUBLIC_KEY_LENGTH,
};
use mgp_seal::{compute_seal, verify_seal};
use rand::rngs::OsRng;

const SEAL_HMAC_KEY: &[u8] = b"hmac-key-for-tier1-coexistence-test!";

#[test]
fn issue_once_verify_offline_workflow() {
    // Issuer side (ClotoHub): generate a master keypair, publish the public
    // key out-of-band, sign a canonical seal payload.
    let (issuer_priv, issuer_pub) = generate_keypair(&mut OsRng);
    let kid = KeyId::new("clotohub-master-v1").unwrap();
    let canonical = b"connector=cpersona\nversion=2.4.12\nentry_point_sha256=deadbeef\n";
    let sig = sign(&issuer_priv, &kid, canonical);

    // Verifier side (ClotoCore): receives only the issuer's published public
    // key (via base64 from a checked-in `.pub` file or DNS TXT) and the seal's
    // base64 signature payload + key_id. No private key, no oracle.
    let pub_b64 = issuer_pub.to_base64();
    let sig_b64 = sig.to_base64();

    let received_pub = PublicKey::from_base64(&pub_b64).unwrap();
    let received_sig = Signature::from_base64(&sig_b64).unwrap();

    assert!(verify(&received_pub, &kid, canonical, &received_sig));
}

#[test]
fn jwks_x_field_decodes_to_public_key() {
    // A real JWKS consumer reads the `x` field, base64url-no-pad decodes it,
    // and reconstructs a usable verifying key. This test enforces that
    // round-trip end-to-end.
    let (_, pk) = generate_keypair(&mut OsRng);
    let kid = KeyId::new("clotohub-master-v1").unwrap();
    let jwk = public_key_to_jwk(&pk, &kid);

    let x = jwk["x"].as_str().expect("`x` must be a string");
    let raw = URL_SAFE_NO_PAD
        .decode(x)
        .expect("`x` decodes as base64url-no-pad");
    let arr: [u8; PUBLIC_KEY_LENGTH] = raw.try_into().expect("`x` decodes to exactly 32 bytes");
    assert_eq!(arr, pk.to_bytes());
}

#[test]
fn private_key_env_var_roundtrip() {
    // Models the production deployment path where ClotoHub reads its master
    // private key from CLOTO_SEAL_ED25519_PRIVATE_KEY (base64) at boot.
    let (sk, pk) = generate_keypair(&mut OsRng);
    let kid = KeyId::new("clotohub-master-v1").unwrap();
    let env_value = sk.to_base64();

    let restored_sk = private_key_from_base64(&env_value).unwrap();
    let sig = sign(&restored_sk, &kid, b"deployment payload");
    assert!(verify(&pk, &kid, b"deployment payload", &sig));
}

#[test]
fn rebinding_signature_to_different_kid_fails() {
    // Defence-in-depth: even if an attacker controls JWKS and relabels a
    // signature with a different `kid`, verification with the new kid must
    // fail because kid is mixed into the signing input.
    let (sk, pk) = generate_keypair(&mut OsRng);
    let kid_real = KeyId::new("clotohub-master-v1").unwrap();
    let kid_attacker = KeyId::new("clotohub-master-evil").unwrap();
    let payload = b"important seal";

    let sig = sign(&sk, &kid_real, payload);
    assert!(verify(&pk, &kid_real, payload, &sig));
    assert!(!verify(&pk, &kid_attacker, payload, &sig));
}

#[test]
fn hmac_api_still_works_alongside_ed25519() {
    // Tier 1 (HMAC) and Tier 2 (Ed25519) co-exist in the same crate; this
    // test exercises both via the public API to catch any accidental
    // breakage when bumping consumer Cargo.toml from 0.1.x to 0.2.0.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), b"tier1+tier2 coexistence").unwrap();

    let hmac_seal = compute_seal(tmp.path(), SEAL_HMAC_KEY).unwrap();
    assert!(verify_seal(tmp.path(), &hmac_seal, SEAL_HMAC_KEY).unwrap());

    let (sk, pk) = generate_keypair(&mut OsRng);
    let kid = KeyId::new("clotohub-master-v1").unwrap();
    let ed_sig = sign(&sk, &kid, hmac_seal.as_bytes());
    assert!(verify(&pk, &kid, hmac_seal.as_bytes(), &ed_sig));
}

#[test]
fn jwk_round_trip_through_public_key_from_jwk() {
    // Full JWKS consumer workflow: serve a JWK, parse it back, verify a
    // signature with the reconstructed key. This is the exact path ClotoCore
    // takes against ClotoHub's /api/seal/keys.
    use mgp_seal::ed25519::public_key_from_jwk;

    let (sk, pk) = generate_keypair(&mut OsRng);
    let kid = KeyId::new("clotohub-master-v1").unwrap();
    let jwk = public_key_to_jwk(&pk, &kid);

    let (parsed_pk, parsed_kid) = public_key_from_jwk(&jwk).unwrap();
    assert_eq!(parsed_pk.to_bytes(), pk.to_bytes());
    assert_eq!(parsed_kid.as_str(), kid.as_str());

    let canonical = mgp_seal::canonical_message("cpersona", "2.4.21", &"ab".repeat(32));
    let sig = sign(&sk, &kid, &canonical);
    assert!(verify(&parsed_pk, &parsed_kid, &canonical, &sig));
}

#[test]
fn public_key_from_jwk_ignores_annotation_fields() {
    // ClotoHub annotates retired keys with `revoked_at`; parsing must not
    // reject the extra field (trust policy for rotated keys is the caller's).
    use mgp_seal::ed25519::public_key_from_jwk;

    let (_, pk) = generate_keypair(&mut OsRng);
    let kid = KeyId::new("clotohub-master-v0").unwrap();
    let mut jwk = public_key_to_jwk(&pk, &kid);
    jwk.as_object_mut()
        .unwrap()
        .insert("revoked_at".into(), "2026-06-01T00:00:00Z".into());

    let (parsed_pk, parsed_kid) = public_key_from_jwk(&jwk).unwrap();
    assert_eq!(parsed_pk.to_bytes(), pk.to_bytes());
    assert_eq!(parsed_kid.as_str(), "clotohub-master-v0");
}

#[test]
fn public_key_from_jwk_rejects_malformed_inputs() {
    use mgp_seal::ed25519::public_key_from_jwk;
    use serde_json::json;

    let (_, pk) = generate_keypair(&mut OsRng);
    let kid = KeyId::new("clotohub-master-v1").unwrap();
    let good = public_key_to_jwk(&pk, &kid);

    let mutate = |f: &str, v: serde_json::Value| {
        let mut j = good.clone();
        j.as_object_mut().unwrap().insert(f.into(), v);
        j
    };
    let drop_field = |f: &str| {
        let mut j = good.clone();
        j.as_object_mut().unwrap().remove(f);
        j
    };

    // Wrong key type / curve / algorithm / use.
    assert!(public_key_from_jwk(&mutate("kty", json!("RSA"))).is_err());
    assert!(public_key_from_jwk(&mutate("crv", json!("P-256"))).is_err());
    assert!(public_key_from_jwk(&mutate("alg", json!("RS256"))).is_err());
    assert!(public_key_from_jwk(&mutate("use", json!("enc"))).is_err());

    // Missing mandatory fields. `alg` / `use` are optional and may be absent.
    assert!(public_key_from_jwk(&drop_field("kty")).is_err());
    assert!(public_key_from_jwk(&drop_field("crv")).is_err());
    assert!(public_key_from_jwk(&drop_field("kid")).is_err());
    assert!(public_key_from_jwk(&drop_field("x")).is_err());
    assert!(public_key_from_jwk(&drop_field("alg")).is_ok());
    assert!(public_key_from_jwk(&drop_field("use")).is_ok());

    // `x` must be base64url-no-pad of exactly 32 valid key bytes. The
    // STANDARD-alphabet padded form (what PublicKey::to_base64 emits) must
    // be rejected here — the two wire formats are deliberately distinct.
    assert!(public_key_from_jwk(&mutate("x", json!("!!!not-base64!!!"))).is_err());
    assert!(public_key_from_jwk(&mutate("x", json!(URL_SAFE_NO_PAD.encode([0u8; 16])))).is_err());
    let padded_standard = pk.to_base64();
    if padded_standard.contains('=')
        || padded_standard.contains('+')
        || padded_standard.contains('/')
    {
        assert!(public_key_from_jwk(&mutate("x", json!(padded_standard))).is_err());
    }
}

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::AuthPolicyLevel;
use crate::error::Result;
use crate::hash::{sha256_hex, sha3_256, sha3_512_hex};
use crate::manifest::jcs::{canonicalize_json_to_bytes, MANIFEST_CANONICALIZATION_LABEL};

use super::validation::{exact_keys, hex_string, safe_integer, string, value_object, value_string};

pub const SHA3_512_ALG: &str = "SHA3-512";
pub const SHA3_256_ALG: &str = "SHA3-256";
pub const SHA256_ALG: &str = "SHA-256";
pub const AUTH_POLICY_COMMITMENT_ALG: &str = SHA3_512_ALG;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestObject {
    pub alg: String,
    pub value: String,
}

pub type Sha3_512Digest = DigestObject;
pub type Sha3_256Digest = DigestObject;
pub type Sha256Digest = DigestObject;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPolicyCommitment {
    pub alg: String,
    pub canonicalization: String,
    pub value: String,
}

pub fn digest_object(alg: &str, value: String) -> DigestObject {
    DigestObject {
        alg: alg.to_string(),
        value,
    }
}

pub fn sha3_512_digest(bytes: &[u8]) -> Sha3_512Digest {
    digest_object(SHA3_512_ALG, sha3_512_hex(bytes))
}

pub fn sha3_256_digest(bytes: &[u8]) -> Sha3_256Digest {
    digest_object(SHA3_256_ALG, hex::encode(sha3_256(bytes)))
}

pub fn sha256_digest(bytes: &[u8]) -> Sha256Digest {
    digest_object(SHA256_ALG, sha256_hex(bytes))
}

pub fn normalize_digest_object(
    value: &Value,
    field: &str,
    expected_alg: Option<&str>,
    expected_len: Option<usize>,
) -> Result<DigestObject> {
    let source = value_object(value, field)?;
    exact_keys(source, &["alg", "value"], &[], field)?;
    let alg = string(source.get("alg"), &format!("{field}.alg"))?;
    if let Some(expected) = expected_alg {
        if alg != expected {
            return Err(crate::error::err(format!("Invalid {field}.alg")));
        }
    }
    let value = hex_string(source.get("value"), &format!("{field}.value"), expected_len)?;
    Ok(DigestObject { alg, value })
}

pub fn digest_to_value(digest: &DigestObject) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("alg".to_string(), Value::String(digest.alg.clone()));
    map.insert("value".to_string(), Value::String(digest.value.clone()));
    Value::Object(map)
}

pub fn normalize_auth_policy(value: &Value) -> Result<Value> {
    let source = value_object(value, "authPolicy")?;
    exact_keys(source, &["level", "minValidSignatures"], &[], "authPolicy")?;
    let level = string(source.get("level"), "authPolicy.level")?;
    match level.as_str() {
        "integrity-only" | "any-signature" | "strong-pq-signature" => {}
        _ => {
            return Err(crate::error::err(format!(
                "Unsupported authPolicy.level: {level}"
            )))
        }
    }
    let min_valid = safe_integer(
        source.get("minValidSignatures"),
        "authPolicy.minValidSignatures",
        1,
    )?;
    let mut map = serde_json::Map::new();
    map.insert("level".to_string(), Value::String(level));
    map.insert(
        "minValidSignatures".to_string(),
        Value::Number(serde_json::Number::from(min_valid)),
    );
    Ok(Value::Object(map))
}

pub fn compute_auth_policy_commitment(auth_policy: &Value) -> Result<AuthPolicyCommitment> {
    let normalized = normalize_auth_policy(auth_policy)?;
    let bytes = canonicalize_json_to_bytes(&normalized)?;
    Ok(AuthPolicyCommitment {
        alg: AUTH_POLICY_COMMITMENT_ALG.to_string(),
        canonicalization: MANIFEST_CANONICALIZATION_LABEL.to_string(),
        value: sha3_512_hex(&bytes),
    })
}

pub fn validate_auth_policy_commitment_shape(value: &Value) -> Result<AuthPolicyCommitment> {
    let source = value_object(value, "authPolicyCommitment")?;
    exact_keys(
        source,
        &["alg", "canonicalization", "value"],
        &[],
        "authPolicyCommitment",
    )?;
    let alg = value_string(source.get("alg"), "authPolicyCommitment.alg")?;
    if alg != AUTH_POLICY_COMMITMENT_ALG {
        return Err(crate::error::err("Unsupported authPolicyCommitment.alg"));
    }
    let canonicalization = value_string(
        source.get("canonicalization"),
        "authPolicyCommitment.canonicalization",
    )?;
    if canonicalization != MANIFEST_CANONICALIZATION_LABEL {
        return Err(crate::error::err(
            "Unsupported authPolicyCommitment.canonicalization",
        ));
    }
    let value = hex_string(source.get("value"), "authPolicyCommitment.value", Some(128))?;
    Ok(AuthPolicyCommitment {
        alg,
        canonicalization,
        value,
    })
}

pub fn auth_policy_level_to_value(level: AuthPolicyLevel, min_valid_signatures: u64) -> Value {
    let mut map = serde_json::Map::new();
    map.insert(
        "level".to_string(),
        Value::String(level.as_str().to_string()),
    );
    map.insert(
        "minValidSignatures".to_string(),
        Value::Number(serde_json::Number::from(min_valid_signatures)),
    );
    Value::Object(map)
}

use serde_json::Value;

use crate::error::{coded, QvCode, Result};
use crate::hash::sha3_256;
use crate::manifest::jcs::{canonicalize_json, canonicalize_json_to_bytes};
use crate::rng::fill_random;

use super::digests::{normalize_digest_object, DigestObject, SHA3_512_ALG};
use super::validation::{hex_string, object_from_pairs};

pub const COHORT_ID_PREIMAGE_TYPE: &str = "quantum-vault-cohort-id-preimage/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CohortIdPreimage {
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalCohortIdPreimage {
    pub preimage: CohortIdPreimage,
    pub canonical: String,
    pub bytes: Vec<u8>,
}

pub fn canonicalize_cohort_id_preimage(
    archive_id: &str,
    state_id: &str,
    cohort_binding_digest: &DigestObject,
) -> Result<CanonicalCohortIdPreimage> {
    let digest_value = serde_json::to_value(cohort_binding_digest)?;
    let digest = normalize_digest_object(
        &digest_value,
        "cohortIdPreimage.cohortBindingDigest",
        Some(SHA3_512_ALG),
        Some(128),
    )?;
    let preimage = CohortIdPreimage {
        value: object_from_pairs(vec![
            ("type", Value::String(COHORT_ID_PREIMAGE_TYPE.to_string())),
            (
                "archiveId",
                Value::String(hex_string(
                    Some(&Value::String(archive_id.to_string())),
                    "cohortIdPreimage.archiveId",
                    Some(64),
                )?),
            ),
            (
                "stateId",
                Value::String(hex_string(
                    Some(&Value::String(state_id.to_string())),
                    "cohortIdPreimage.stateId",
                    Some(128),
                )?),
            ),
            ("cohortBindingDigest", serde_json::to_value(digest)?),
        ]),
    };
    Ok(CanonicalCohortIdPreimage {
        canonical: canonicalize_json(&preimage.value)?,
        bytes: canonicalize_json_to_bytes(&preimage.value)?,
        preimage,
    })
}

pub fn derive_cohort_id(
    archive_id: &str,
    state_id: &str,
    cohort_binding_digest: &DigestObject,
) -> Result<String> {
    let canonical = canonicalize_cohort_id_preimage(archive_id, state_id, cohort_binding_digest)?;
    Ok(hex::encode(sha3_256(&canonical.bytes)))
}

pub fn generate_archive_id() -> Result<String> {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes).map_err(|error| {
        coded(
            QvCode::EntropyFailed,
            format!("archiveId RNG failed: {error}"),
        )
    })?;
    Ok(hex::encode(bytes))
}

#[cfg(feature = "deterministic-test-vectors")]
pub fn generate_archive_id_deterministic(bytes: [u8; 32]) -> String {
    hex::encode(bytes)
}

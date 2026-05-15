use serde_json::Value;

use crate::error::{err, Result};
use crate::manifest::jcs::{
    canonicalize_json, canonicalize_json_to_bytes, MANIFEST_CANONICALIZATION_LABEL,
};
use crate::manifest::strict_json::{assert_canonical_bytes, parse_json_bytes_strict};

use super::digests::{sha3_512_digest, DigestObject, SHA3_512_ALG};
use super::validation::{
    exact_keys, exact_string, exact_string_array, hash_list, hex_string, integer, number,
    object_from_pairs, safe_integer, string, value_object,
};

pub const COHORT_BINDING_SCHEMA: &str = "quantum-vault-cohort-binding/v1";
pub const COHORT_BINDING_VERSION: u64 = 1;
pub const COHORT_BINDING_CANONICALIZATION: &str = MANIFEST_CANONICALIZATION_LABEL;
pub const COHORT_TYPE_DEFAULT: &str = "shard-cohort";
pub const REED_SOLOMON_CODEC_ID: &str = "QV-RS-ErasureCodes-v1";
pub const SHARD_BODY_DEFINITION_ID: &str = "QV-QCONT-SHARDBODY-v1";
pub const SHARE_COMMITMENT_INPUT: &str = "raw-shamir-share-bytes";
pub const BODY_DEFINITION_INCLUDES: &[&str] = &["fragment-len32-stream"];
pub const BODY_DEFINITION_EXCLUDES: &[&str] = &[
    "qcont-header",
    "embedded-archive-state",
    "embedded-archive-state-digest",
    "embedded-cohort-binding",
    "embedded-cohort-binding-digest",
    "embedded-lifecycle-bundle",
    "embedded-lifecycle-bundle-digest",
    "external-signatures",
];
const BODY_DEFINITION_EXCLUDES_ERROR: &str =
    "cohortBinding.bodyDefinition.excludes MUST equal canonical QV-QCONT-SHARDBODY-v1 excludes";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildCohortBindingParams {
    pub archive_id: String,
    pub state_id: String,
    pub shamir_threshold: u64,
    pub shamir_share_count: u64,
    pub rs_n: u64,
    pub rs_k: u64,
    pub rs_parity: u64,
    pub shard_body_hashes: Vec<String>,
    pub share_commitments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CohortBinding {
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalCohortBinding {
    pub cohort_binding: CohortBinding,
    pub canonical: String,
    pub bytes: Vec<u8>,
    pub digest: DigestObject,
    pub canonicalization_label: String,
}

pub fn build_cohort_binding(params: &BuildCohortBindingParams) -> Result<CohortBinding> {
    let shard_body_hashes = params
        .shard_body_hashes
        .iter()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    let share_commitments = params
        .share_commitments
        .iter()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    let value = object_from_pairs(vec![
        ("schema", Value::String(COHORT_BINDING_SCHEMA.to_string())),
        ("version", number(COHORT_BINDING_VERSION)),
        ("cohortType", Value::String(COHORT_TYPE_DEFAULT.to_string())),
        (
            "canonicalization",
            Value::String(COHORT_BINDING_CANONICALIZATION.to_string()),
        ),
        ("archiveId", Value::String(params.archive_id.clone())),
        ("stateId", Value::String(params.state_id.clone())),
        (
            "sharding",
            object_from_pairs(vec![
                (
                    "shamir",
                    object_from_pairs(vec![
                        ("threshold", number(params.shamir_threshold)),
                        ("shareCount", number(params.shamir_share_count)),
                    ]),
                ),
                (
                    "reedSolomon",
                    object_from_pairs(vec![
                        ("n", number(params.rs_n)),
                        ("k", number(params.rs_k)),
                        ("parity", number(params.rs_parity)),
                        ("codecId", Value::String(REED_SOLOMON_CODEC_ID.to_string())),
                    ]),
                ),
            ]),
        ),
        (
            "bodyDefinitionId",
            Value::String(SHARD_BODY_DEFINITION_ID.to_string()),
        ),
        (
            "bodyDefinition",
            object_from_pairs(vec![
                (
                    "includes",
                    Value::Array(
                        BODY_DEFINITION_INCLUDES
                            .iter()
                            .map(|value| Value::String((*value).to_string()))
                            .collect(),
                    ),
                ),
                (
                    "excludes",
                    Value::Array(
                        BODY_DEFINITION_EXCLUDES
                            .iter()
                            .map(|value| Value::String((*value).to_string()))
                            .collect(),
                    ),
                ),
            ]),
        ),
        ("shardBodyHashAlg", Value::String(SHA3_512_ALG.to_string())),
        ("shardBodyHashes", Value::Array(shard_body_hashes)),
        (
            "shareCommitment",
            object_from_pairs(vec![
                ("hashAlg", Value::String(SHA3_512_ALG.to_string())),
                ("input", Value::String(SHARE_COMMITMENT_INPUT.to_string())),
            ]),
        ),
        ("shareCommitments", Value::Array(share_commitments)),
    ]);
    validate_cohort_binding_value(&value)
}

pub fn validate_cohort_binding_value(value: &Value) -> Result<CohortBinding> {
    let source = value_object(value, "cohortBinding")?;
    if source.contains_key("cohortId") {
        return Err(err("cohortBinding.cohortId MUST NOT be present"));
    }
    exact_keys(
        source,
        &[
            "schema",
            "version",
            "cohortType",
            "canonicalization",
            "archiveId",
            "stateId",
            "sharding",
            "bodyDefinitionId",
            "bodyDefinition",
            "shardBodyHashAlg",
            "shardBodyHashes",
            "shareCommitment",
            "shareCommitments",
        ],
        &[],
        "cohortBinding",
    )?;

    let sharding = value_object(
        source
            .get("sharding")
            .ok_or_else(|| err("Missing cohortBinding.sharding"))?,
        "cohortBinding.sharding",
    )?;
    exact_keys(
        sharding,
        &["shamir", "reedSolomon"],
        &[],
        "cohortBinding.sharding",
    )?;
    let shamir = value_object(
        sharding
            .get("shamir")
            .ok_or_else(|| err("Missing cohortBinding.sharding.shamir"))?,
        "cohortBinding.sharding.shamir",
    )?;
    exact_keys(
        shamir,
        &["threshold", "shareCount"],
        &[],
        "cohortBinding.sharding.shamir",
    )?;
    let rs = value_object(
        sharding
            .get("reedSolomon")
            .ok_or_else(|| err("Missing cohortBinding.sharding.reedSolomon"))?,
        "cohortBinding.sharding.reedSolomon",
    )?;
    exact_keys(
        rs,
        &["n", "k", "parity", "codecId"],
        &[],
        "cohortBinding.sharding.reedSolomon",
    )?;

    let threshold = safe_integer(
        shamir.get("threshold"),
        "cohortBinding.sharding.shamir.threshold",
        2,
    )?;
    let share_count = safe_integer(
        shamir.get("shareCount"),
        "cohortBinding.sharding.shamir.shareCount",
        2,
    )?;
    let n = safe_integer(rs.get("n"), "cohortBinding.sharding.reedSolomon.n", 2)?;
    let k = safe_integer(rs.get("k"), "cohortBinding.sharding.reedSolomon.k", 2)?;
    let parity = integer(
        rs.get("parity"),
        "cohortBinding.sharding.reedSolomon.parity",
        0,
        0xffff_ffff,
    )?;
    let codec_id = exact_string(
        rs.get("codecId"),
        "cohortBinding.sharding.reedSolomon.codecId",
        REED_SOLOMON_CODEC_ID,
    )?;
    if threshold > share_count {
        return Err(err("Invalid cohortBinding.sharding.shamir.threshold"));
    }
    if share_count != n {
        return Err(err("Invalid cohortBinding.sharding.shamir.shareCount"));
    }
    if k >= n {
        return Err(err("Invalid cohortBinding.sharding.reedSolomon.k"));
    }
    if parity != n - k {
        return Err(err("Invalid cohortBinding.sharding.reedSolomon.parity"));
    }
    if parity % 2 != 0 {
        return Err(err(format!(
            "Unsupported cohort parameters: parity must be even under {REED_SOLOMON_CODEC_ID}"
        )));
    }
    if threshold != k + (parity / 2) {
        return Err(err(format!(
            "Unsupported cohort parameters: t must equal k + (parity/2) under {REED_SOLOMON_CODEC_ID}"
        )));
    }

    let body_definition = value_object(
        source
            .get("bodyDefinition")
            .ok_or_else(|| err("Missing cohortBinding.bodyDefinition"))?,
        "cohortBinding.bodyDefinition",
    )?;
    exact_keys(
        body_definition,
        &["includes", "excludes"],
        &[],
        "cohortBinding.bodyDefinition",
    )?;
    let body_definition_excludes = canonical_body_definition_excludes(body_definition)?;
    let share_commitment = value_object(
        source
            .get("shareCommitment")
            .ok_or_else(|| err("Missing cohortBinding.shareCommitment"))?,
        "cohortBinding.shareCommitment",
    )?;
    exact_keys(
        share_commitment,
        &["hashAlg", "input"],
        &[],
        "cohortBinding.shareCommitment",
    )?;

    let shard_body_hashes = hash_list(
        source.get("shardBodyHashes"),
        "cohortBinding.shardBodyHashes",
        128,
    )?;
    let share_commitments = hash_list(
        source.get("shareCommitments"),
        "cohortBinding.shareCommitments",
        128,
    )?;
    if shard_body_hashes.len() != n as usize {
        return Err(err("cohortBinding.shardBodyHashes length mismatch"));
    }
    if share_commitments.len() != n as usize {
        return Err(err("cohortBinding.shareCommitments length mismatch"));
    }

    let sharding_value = object_from_pairs(vec![
        (
            "shamir",
            object_from_pairs(vec![
                ("threshold", number(threshold)),
                ("shareCount", number(share_count)),
            ]),
        ),
        (
            "reedSolomon",
            object_from_pairs(vec![
                ("n", number(n)),
                ("k", number(k)),
                ("parity", number(parity)),
                ("codecId", Value::String(codec_id)),
            ]),
        ),
    ]);

    Ok(CohortBinding {
        value: object_from_pairs(vec![
            (
                "schema",
                Value::String(exact_string(
                    source.get("schema"),
                    "cohortBinding.schema",
                    COHORT_BINDING_SCHEMA,
                )?),
            ),
            (
                "version",
                number(integer(
                    source.get("version"),
                    "cohortBinding.version",
                    1,
                    u64::MAX,
                )?),
            ),
            (
                "cohortType",
                Value::String(string(
                    source.get("cohortType"),
                    "cohortBinding.cohortType",
                )?),
            ),
            (
                "canonicalization",
                Value::String(exact_string(
                    source.get("canonicalization"),
                    "cohortBinding.canonicalization",
                    COHORT_BINDING_CANONICALIZATION,
                )?),
            ),
            (
                "archiveId",
                Value::String(hex_string(
                    source.get("archiveId"),
                    "cohortBinding.archiveId",
                    Some(64),
                )?),
            ),
            (
                "stateId",
                Value::String(hex_string(
                    source.get("stateId"),
                    "cohortBinding.stateId",
                    Some(128),
                )?),
            ),
            ("sharding", sharding_value),
            (
                "bodyDefinitionId",
                Value::String(exact_string(
                    source.get("bodyDefinitionId"),
                    "cohortBinding.bodyDefinitionId",
                    SHARD_BODY_DEFINITION_ID,
                )?),
            ),
            (
                "bodyDefinition",
                object_from_pairs(vec![
                    (
                        "includes",
                        exact_string_array(
                            body_definition.get("includes"),
                            BODY_DEFINITION_INCLUDES,
                            "cohortBinding.bodyDefinition.includes",
                        )?,
                    ),
                    (
                        "excludes",
                        body_definition_excludes,
                    ),
                ]),
            ),
            (
                "shardBodyHashAlg",
                Value::String(exact_string(
                    source.get("shardBodyHashAlg"),
                    "cohortBinding.shardBodyHashAlg",
                    SHA3_512_ALG,
                )?),
            ),
            ("shardBodyHashes", Value::Array(shard_body_hashes)),
            (
                "shareCommitment",
                object_from_pairs(vec![
                    (
                        "hashAlg",
                        Value::String(exact_string(
                            share_commitment.get("hashAlg"),
                            "cohortBinding.shareCommitment.hashAlg",
                            SHA3_512_ALG,
                        )?),
                    ),
                    (
                        "input",
                        Value::String(exact_string(
                            share_commitment.get("input"),
                            "cohortBinding.shareCommitment.input",
                            SHARE_COMMITMENT_INPUT,
                        )?),
                    ),
                ]),
            ),
            ("shareCommitments", Value::Array(share_commitments)),
        ]),
    })
}

fn canonical_body_definition_excludes(
    body_definition: &serde_json::Map<String, Value>,
) -> Result<Value> {
    exact_string_array(
        body_definition.get("excludes"),
        BODY_DEFINITION_EXCLUDES,
        "cohortBinding.bodyDefinition.excludes",
    )
    .map_err(|_| err(BODY_DEFINITION_EXCLUDES_ERROR))
}

pub fn canonicalize_cohort_binding(value: &Value) -> Result<CanonicalCohortBinding> {
    let cohort_binding = validate_cohort_binding_value(value)?;
    let canonical = canonicalize_json(&cohort_binding.value)?;
    let bytes = canonicalize_json_to_bytes(&cohort_binding.value)?;
    let digest = sha3_512_digest(&bytes);
    Ok(CanonicalCohortBinding {
        cohort_binding,
        canonical,
        bytes,
        digest,
        canonicalization_label: COHORT_BINDING_CANONICALIZATION.to_string(),
    })
}

pub fn parse_cohort_binding_bytes(bytes: &[u8]) -> Result<CanonicalCohortBinding> {
    let parsed = parse_json_bytes_strict(bytes)?;
    let canonicalized = canonicalize_cohort_binding(&parsed)?;
    assert_canonical_bytes(bytes, &canonicalized.bytes, "Cohort binding")?;
    Ok(canonicalized)
}

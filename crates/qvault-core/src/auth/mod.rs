pub mod opentimestamps;
pub mod qsig;
pub mod signature_suites;
pub mod stellar_sig;
pub mod verify;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthPolicyLevel {
    #[serde(rename = "integrity-only")]
    IntegrityOnly,
    #[serde(rename = "any-signature")]
    AnySignature,
    #[serde(rename = "strong-pq-signature")]
    StrongPqSignature,
}

impl AuthPolicyLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IntegrityOnly => "integrity-only",
            Self::AnySignature => "any-signature",
            Self::StrongPqSignature => "strong-pq-signature",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPolicy {
    pub level: AuthPolicyLevel,
    #[serde(rename = "minValidSignatures")]
    pub min_valid_signatures: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedBinaryArtifact {
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerificationInputs {
    pub signatures: Vec<NamedBinaryArtifact>,
    pub pinned_pq_public_key_file_bytes: Option<Vec<u8>>,
    pub timestamps: Vec<NamedBinaryArtifact>,
    pub expected_ed25519_signer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureVerificationCounts {
    #[serde(rename = "validTotal")]
    pub valid_total: u64,
    #[serde(rename = "validStrongPq")]
    pub valid_strong_pq: u64,
    #[serde(rename = "pinnedValidTotal")]
    pub pinned_valid_total: u64,
    #[serde(rename = "pinnedValidStrongPq")]
    pub pinned_valid_strong_pq: u64,
    #[serde(rename = "bundlePinnedValidTotal")]
    pub bundle_pinned_valid_total: u64,
    #[serde(rename = "userPinnedValidTotal")]
    pub user_pinned_valid_total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureArtifact {
    pub id: String,
    pub name: String,
    pub source: String,
    pub format: String,
    #[serde(
        rename = "signatureContentDigestHex",
        skip_serializing_if = "Option::is_none"
    )]
    pub signature_content_digest_hex: Option<String>,
    #[serde(
        rename = "otsStampedDigestHex",
        skip_serializing_if = "Option::is_none"
    )]
    pub ots_stamped_digest_hex: Option<String>,
    #[serde(skip)]
    pub bytes: Vec<u8>,
    pub ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureVerificationStatus {
    #[serde(rename = "signatureVerified")]
    pub signature_verified: bool,
    #[serde(rename = "strongPqSignatureVerified")]
    pub strong_pq_signature_verified: bool,
    #[serde(rename = "signerPinned")]
    pub signer_pinned: bool,
    #[serde(rename = "signerIdentityPinned")]
    pub signer_identity_pinned: bool,
    #[serde(rename = "bundlePinned")]
    pub bundle_pinned: bool,
    #[serde(rename = "userPinned")]
    pub user_pinned: bool,
    #[serde(rename = "userPinProvided")]
    pub user_pin_provided: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureCheckResult {
    pub ok: bool,
    #[serde(rename = "bundlePinned")]
    pub bundle_pinned: bool,
    #[serde(rename = "userPinned")]
    pub user_pinned: bool,
    #[serde(rename = "signerPinned")]
    pub signer_pinned: bool,
    pub name: String,
    pub source: String,
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suite: Option<String>,
    #[serde(rename = "suiteDisplay", skip_serializing_if = "Option::is_none")]
    pub suite_display: Option<String>,
    #[serde(rename = "strongPq")]
    pub strong_pq: bool,
    #[serde(rename = "keySource", skip_serializing_if = "Option::is_none")]
    pub key_source: Option<String>,
    #[serde(
        rename = "signerFingerprintHex",
        skip_serializing_if = "Option::is_none"
    )]
    pub signer_fingerprint_hex: Option<String>,
    #[serde(rename = "signerLabel", skip_serializing_if = "Option::is_none")]
    pub signer_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub warnings: Vec<String>,
    #[serde(rename = "artifactId")]
    pub artifact_id: String,
    #[serde(
        rename = "signatureContentDigestAlg",
        skip_serializing_if = "Option::is_none"
    )]
    pub signature_content_digest_alg: Option<String>,
    #[serde(
        rename = "signatureContentDigestHex",
        skip_serializing_if = "Option::is_none"
    )]
    pub signature_content_digest_hex: Option<String>,
    #[serde(
        rename = "otsStampedDigestAlg",
        skip_serializing_if = "Option::is_none"
    )]
    pub ots_stamped_digest_alg: Option<String>,
    #[serde(
        rename = "otsStampedDigestHex",
        skip_serializing_if = "Option::is_none"
    )]
    pub ots_stamped_digest_hex: Option<String>,
    #[serde(rename = "countedForPolicy", default)]
    pub counted_for_policy: bool,
    #[serde(skip)]
    pub signature_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureVerificationReport {
    pub provided: bool,
    pub results: Vec<SignatureCheckResult>,
    pub warnings: Vec<String>,
    pub counts: SignatureVerificationCounts,
    #[serde(rename = "signatureArtifacts")]
    pub signature_artifacts: Vec<SignatureArtifact>,
    pub status: SignatureVerificationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivePolicyEvaluation {
    pub level: AuthPolicyLevel,
    #[serde(rename = "minValidSignatures")]
    pub min_valid_signatures: u64,
    pub satisfied: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampEvidence {
    pub id: String,
    #[serde(rename = "targetRef")]
    pub target_ref: String,
    #[serde(rename = "targetName")]
    pub target_name: String,
    #[serde(rename = "targetSource")]
    pub target_source: String,
    #[serde(rename = "targetVerified")]
    pub target_verified: bool,
    pub linked: bool,
    #[serde(rename = "apparentlyComplete")]
    pub apparently_complete: bool,
    #[serde(rename = "completeProof")]
    pub complete_proof: bool,
    #[serde(rename = "linkLabel")]
    pub link_label: String,
    #[serde(rename = "completionLabel")]
    pub completion_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticityStatus {
    #[serde(rename = "integrityVerified")]
    pub integrity_verified: bool,
    #[serde(rename = "signatureVerified")]
    pub signature_verified: bool,
    #[serde(rename = "strongPqSignatureVerified")]
    pub strong_pq_signature_verified: bool,
    #[serde(rename = "signerPinned")]
    pub signer_pinned: bool,
    #[serde(rename = "signerIdentityPinned")]
    pub signer_identity_pinned: bool,
    #[serde(rename = "bundlePinned")]
    pub bundle_pinned: bool,
    #[serde(rename = "userPinned")]
    pub user_pinned: bool,
    #[serde(rename = "userPinProvided")]
    pub user_pin_provided: bool,
    #[serde(rename = "policySatisfied")]
    pub policy_satisfied: bool,
    #[serde(rename = "archivePolicySatisfied")]
    pub archive_policy_satisfied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticityReport {
    pub policy: ArchivePolicyEvaluation,
    pub verification: SignatureVerificationReport,
    pub warnings: Vec<String>,
    pub status: AuthenticityStatus,
    #[serde(rename = "timestampEvidence")]
    pub timestamp_evidence: Vec<TimestampEvidence>,
}

pub use opentimestamps::{
    assert_manifest_bundle_timestamps, inspect_timestamp_evidence, parse_open_timestamp_proof,
    resolve_open_timestamp_target,
};
pub use qsig::{unpack_pqpk, unpack_qsig, verify_qsig_against_bytes, ParsedPqpk, ParsedQsig};
pub use signature_suites::{
    get_signature_suite_info, is_strong_pq_suite, list_supported_signature_suites,
    normalize_signature_suite, SignatureSuiteInfo,
};
pub use stellar_sig::verify_stellar_sig_against_bytes;
pub use verify::verify_manifest_signatures;

pub mod detached_archive_approval_format;
pub mod opentimestamps;
pub mod qsig;
pub mod signature_identity;
pub mod signature_suites;
pub mod stellar_sig;
pub(crate) mod successor_policy;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
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
    /// Successor archive-approval family only (oracle `validArchiveApproval`).
    #[serde(rename = "validArchiveApproval", default)]
    pub valid_archive_approval: u64,
    #[serde(rename = "validArchiveApprovalStrongPq", default)]
    pub valid_archive_approval_strong_pq: u64,
    #[serde(rename = "archiveApprovalPinnedValidTotal", default)]
    pub archive_approval_pinned_valid_total: u64,
    #[serde(rename = "archiveApprovalBundlePinnedValidTotal", default)]
    pub archive_approval_bundle_pinned_valid_total: u64,
    #[serde(rename = "archiveApprovalUserPinnedValidTotal", default)]
    pub archive_approval_user_pinned_valid_total: u64,
    #[serde(rename = "validMaintenance", default)]
    pub valid_maintenance: u64,
    #[serde(rename = "validSourceEvidence", default)]
    pub valid_source_evidence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureArtifact {
    pub id: String,
    pub name: String,
    pub source: String,
    #[serde(default = "default_archive_approval_family")]
    pub family: String,
    pub format: String,
    #[serde(rename = "targetType", skip_serializing_if = "Option::is_none")]
    pub target_type: Option<String>,
    #[serde(rename = "targetRef", skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
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
    #[serde(rename = "archiveApprovalSignatureVerified")]
    pub archive_approval_signature_verified: bool,
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
    #[serde(rename = "transitionRecordPresent")]
    pub transition_record_present: bool,
    #[serde(rename = "transitionChainValid")]
    pub transition_chain_valid: bool,
    #[serde(rename = "sourceEvidencePresent")]
    pub source_evidence_present: bool,
    #[serde(rename = "maintenanceSignatureVerified")]
    pub maintenance_signature_verified: bool,
    #[serde(rename = "sourceEvidenceSignatureVerified")]
    pub source_evidence_signature_verified: bool,
    #[serde(rename = "otsEvidenceLinked")]
    pub ots_evidence_linked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureCheckResult {
    pub ok: bool,
    #[serde(default = "default_archive_approval_family")]
    pub family: String,
    #[serde(default, rename = "selfSigned")]
    pub self_signed: bool,
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
    #[serde(rename = "targetType", skip_serializing_if = "Option::is_none")]
    pub target_type: Option<String>,
    #[serde(rename = "targetRef", skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
    #[serde(rename = "targetDigest", skip_serializing_if = "Option::is_none")]
    pub target_digest: Option<SignatureTargetDigest>,
    #[serde(rename = "transitionIndex", skip_serializing_if = "Option::is_none")]
    pub transition_index: Option<usize>,
    #[serde(rename = "maintenancePurposeLabels", default)]
    pub maintenance_purpose_labels: Vec<String>,
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
    /// `null` in JSON when absent (oracle verify / restore JSON surfaces).
    #[serde(rename = "proofIdentityDigestAlg", default)]
    pub proof_identity_digest_alg: Option<String>,
    #[serde(rename = "proofIdentityDigestHex", default)]
    pub proof_identity_digest_hex: Option<String>,
    #[serde(rename = "countedForPolicy", default)]
    pub counted_for_policy: bool,
    #[serde(skip)]
    pub signature_bytes: Option<Vec<u8>>,
}

fn default_archive_approval_family() -> String {
    "archive-approval".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureTargetDigest {
    pub alg: String,
    pub value: String,
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
pub struct TransitionReportRecord {
    pub index: usize,
    #[serde(rename = "digestHex")]
    pub digest_hex: String,
    #[serde(rename = "transitionType")]
    pub transition_type: String,
    #[serde(rename = "archiveId")]
    pub archive_id: String,
    #[serde(rename = "fromStateId")]
    pub from_state_id: String,
    #[serde(rename = "toStateId")]
    pub to_state_id: String,
    #[serde(rename = "fromCohortId")]
    pub from_cohort_id: String,
    #[serde(rename = "toCohortId")]
    pub to_cohort_id: String,
    #[serde(rename = "fromCohortBindingDigest")]
    pub from_cohort_binding_digest: SignatureTargetDigest,
    #[serde(rename = "toCohortBindingDigest")]
    pub to_cohort_binding_digest: SignatureTargetDigest,
    #[serde(rename = "maintenanceSignatureIds")]
    pub maintenance_signature_ids: Vec<String>,
    #[serde(rename = "verifiedMaintenanceSignatureIds")]
    pub verified_maintenance_signature_ids: Vec<String>,
    #[serde(rename = "maintenanceSignatureCount")]
    pub maintenance_signature_count: usize,
    #[serde(rename = "verifiedMaintenanceSignatureCount")]
    pub verified_maintenance_signature_count: usize,
    #[serde(rename = "maintenancePurposeLabels")]
    pub maintenance_purpose_labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionReport {
    pub present: bool,
    #[serde(rename = "chainValid")]
    pub chain_valid: bool,
    #[serde(rename = "validationScope")]
    pub validation_scope: String,
    pub count: usize,
    pub signed: bool,
    #[serde(rename = "maintenanceSignatureVerified")]
    pub maintenance_signature_verified: bool,
    #[serde(rename = "maintenancePurposeLabels")]
    pub maintenance_purpose_labels: Vec<String>,
    #[serde(rename = "currentArchiveId")]
    pub current_archive_id: String,
    #[serde(rename = "currentStateId")]
    pub current_state_id: String,
    #[serde(rename = "currentCohortId")]
    pub current_cohort_id: String,
    #[serde(rename = "currentCohortBindingDigestHex")]
    pub current_cohort_binding_digest_hex: String,
    pub records: Vec<TransitionReportRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceEvidenceReportRecord {
    pub index: usize,
    #[serde(rename = "digestHex")]
    pub digest_hex: String,
    #[serde(rename = "targetRef")]
    pub target_ref: String,
    #[serde(rename = "relationType")]
    pub relation_type: String,
    #[serde(rename = "sourceObjectType")]
    pub source_object_type: String,
    #[serde(rename = "sourceDigests")]
    pub source_digests: Vec<SignatureTargetDigest>,
    #[serde(rename = "externalSourceSignatureRefs")]
    pub external_source_signature_refs: Vec<String>,
    #[serde(rename = "externalSourceSignatureRefCount")]
    pub external_source_signature_ref_count: usize,
    #[serde(rename = "descriptiveFieldNames")]
    pub descriptive_field_names: Vec<String>,
    #[serde(rename = "mediaType")]
    pub media_type: Option<String>,
    #[serde(rename = "sourceEvidenceSignatureIds")]
    pub source_evidence_signature_ids: Vec<String>,
    #[serde(rename = "verifiedSourceEvidenceSignatureIds")]
    pub verified_source_evidence_signature_ids: Vec<String>,
    #[serde(rename = "sourceEvidenceSignatureCount")]
    pub source_evidence_signature_count: usize,
    #[serde(rename = "verifiedSourceEvidenceSignatureCount")]
    pub verified_source_evidence_signature_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceEvidenceReport {
    pub present: bool,
    pub count: usize,
    pub signed: bool,
    #[serde(rename = "signatureVerified")]
    pub signature_verified: bool,
    #[serde(rename = "sourceEvidenceSignatureCount")]
    pub source_evidence_signature_count: usize,
    #[serde(rename = "verifiedSourceEvidenceSignatureCount")]
    pub verified_source_evidence_signature_count: usize,
    #[serde(rename = "externalSourceSignatureRefCount")]
    pub external_source_signature_ref_count: usize,
    #[serde(rename = "externalSourceSignatureRefsPresent")]
    pub external_source_signature_refs_present: bool,
    #[serde(rename = "descriptiveFieldNames")]
    pub descriptive_field_names: Vec<String>,
    pub records: Vec<SourceEvidenceReportRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticityStatus {
    #[serde(rename = "integrityVerified")]
    pub integrity_verified: bool,
    #[serde(rename = "archiveApprovalSignatureVerified")]
    pub archive_approval_signature_verified: bool,
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
    #[serde(rename = "transitionRecordPresent")]
    pub transition_record_present: bool,
    #[serde(rename = "transitionChainValid")]
    pub transition_chain_valid: bool,
    #[serde(rename = "sourceEvidencePresent")]
    pub source_evidence_present: bool,
    #[serde(rename = "maintenanceSignatureVerified")]
    pub maintenance_signature_verified: bool,
    #[serde(rename = "sourceEvidenceSignatureVerified")]
    pub source_evidence_signature_verified: bool,
    #[serde(rename = "otsEvidenceLinked")]
    pub ots_evidence_linked: bool,
    #[serde(rename = "policySatisfied")]
    pub policy_satisfied: bool,
    #[serde(rename = "archivePolicySatisfied")]
    pub archive_policy_satisfied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticityReport {
    pub policy: ArchivePolicyEvaluation,
    pub verification: SignatureVerificationReport,
    #[serde(rename = "transitionReport")]
    pub transition_report: TransitionReport,
    #[serde(rename = "sourceEvidenceReport")]
    pub source_evidence_report: SourceEvidenceReport,
    pub warnings: Vec<String>,
    pub status: AuthenticityStatus,
    #[serde(rename = "timestampEvidence")]
    pub timestamp_evidence: Vec<TimestampEvidence>,
}

pub use detached_archive_approval_format::{
    classify_detached_archive_approval_bytes, is_supported_stellar_signature_document_bytes,
    DetachedArchiveApprovalKind,
};
pub use opentimestamps::{parse_open_timestamp_proof, resolve_open_timestamp_target};
pub use qsig::{unpack_pqpk, unpack_qsig, verify_qsig_against_bytes, ParsedPqpk, ParsedQsig};
pub use signature_identity::compute_detached_signature_identity_digest_hex;
pub use signature_suites::{
    get_signature_suite_info, is_strong_pq_suite, list_supported_signature_suites,
    normalize_signature_suite, SignatureSuiteInfo,
};
pub use stellar_sig::verify_stellar_sig_against_bytes;

use qvault_core::error::QvCode;

#[test]
fn qv_code_strings_match_oracle_cli_exit_js() {
    assert_eq!(QvCode::EntropyFailed.as_str(), "ENTROPY_FAILED");
    assert_eq!(QvCode::KeyRejected.as_str(), "KEY_REJECTED");
    assert_eq!(QvCode::AeadFailed.as_str(), "AEAD_FAILED");
    assert_eq!(
        QvCode::SignatureImportFailed.as_str(),
        "SIGNATURE_IMPORT_FAILED"
    );
    assert_eq!(QvCode::PolicyNotSatisfied.as_str(), "POLICY_NOT_SATISFIED");
    assert_eq!(QvCode::AmbiguousInputs.as_str(), "AMBIGUOUS_INPUTS");
    assert_eq!(QvCode::InvalidSelection.as_str(), "AMBIGUOUS_INPUTS");
    assert_eq!(QvCode::NotEnoughShards.as_str(), "QUORUM_UNREACHABLE");
    assert_eq!(QvCode::IntegrityMismatch.as_str(), "QUORUM_UNREACHABLE");
    assert_eq!(
        QvCode::ReshareContractViolation.as_str(),
        "RESHARE_CONTRACT_VIOLATION"
    );
    assert_eq!(
        QvCode::RestoredIntegrityFailed.as_str(),
        "RESTORED_INTEGRITY_FAILED"
    );
    assert_eq!(
        QvCode::RestoreLifecycleVariantAckRequired.as_str(),
        "RESTORE_LIFECYCLE_VARIANT_ACK_REQUIRED"
    );
    assert_eq!(QvCode::InvalidFormat.as_str(), "FORMAT_POLICY_REJECT");
    assert_eq!(QvCode::UnsupportedFormat.as_str(), "FORMAT_POLICY_REJECT");
    assert_eq!(QvCode::VerificationFailed.as_str(), "UNEXPECTED");
    assert_eq!(QvCode::RestoreFailed.as_str(), "UNEXPECTED");
}

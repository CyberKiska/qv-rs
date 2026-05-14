//! Stage C: detached archive-approval classification (no filename / non-schema heuristics).

use qvault_core::auth::{
    classify_detached_archive_approval_bytes, is_supported_stellar_signature_document_bytes,
    DetachedArchiveApprovalKind,
};

#[test]
fn pqsg_prefix_classifies_as_qsig_even_when_short() {
    assert_eq!(
        classify_detached_archive_approval_bytes(b"PQSG").unwrap(),
        DetachedArchiveApprovalKind::Qsig
    );
}

#[test]
fn random_bytes_are_rejected_not_treated_as_stellar() {
    let err = classify_detached_archive_approval_bytes(&[0xff, 0xfe, 0xfd])
        .expect_err("opaque bytes must not be routed to the Stellar verifier");
    assert!(
        err.to_string().contains("Unsupported"),
        "unexpected message: {err}"
    );
}

#[test]
fn stellar_file_v1_json_is_not_oracle_supported_external_shape() {
    let v1 = br#"{"schema":"stellar-file-signature/v1","mode":"sep53","hashes":[]}"#;
    assert!(!is_supported_stellar_signature_document_bytes(v1));
    assert!(classify_detached_archive_approval_bytes(v1).is_err());
}

#[test]
fn empty_stellar_v2_shell_without_hashes_is_not_supported() {
    let body = br#"{"schema":"stellar-signature/v2","proofType":"sep53-message-signature","payloadType":"raw-bytes","signatureScheme":"sep53-sha256-ed25519","signer":"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF","signatureB64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#;
    assert!(!is_supported_stellar_signature_document_bytes(body));
}

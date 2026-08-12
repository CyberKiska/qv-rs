use qvault_core::{
    build_bundle_payload, decrypt_qenc, encrypt_qenc, generate_key_pair, is_bundle_payload,
    parse_bundle_payload, BundleEntryRef, EncryptQencOptions,
};

#[test]
fn encrypt_and_decrypt_multi_file_bundle_round_trip() {
    let (public_key, secret_key) = generate_key_pair().expect("key pair");
    let bundle_name = "bundle-2026-03-07T09-08-07.qvpack".to_string();
    let bundle_payload = build_bundle_payload(&[
        BundleEntryRef {
            name: "a.txt",
            bytes: b"alpha payload",
        },
        BundleEntryRef {
            name: "b.bin",
            bytes: &[1, 2, 3, 4, 5, 6],
        },
    ])
    .expect("build bundle");

    let container = encrypt_qenc(
        &bundle_payload,
        &public_key,
        &EncryptQencOptions {
            original_filename: Some(bundle_name.clone()),
            timestamp: Some("2026-03-07T09:08:07.000Z".to_string()),
        },
    )
    .expect("encrypt bundle");

    let decrypted = decrypt_qenc(&container, &secret_key).expect("decrypt bundle");
    assert_eq!(
        decrypted.private_metadata.original_filename.as_deref(),
        Some(bundle_name.as_str())
    );
    assert!(is_bundle_payload(&decrypted.file_bytes));

    let entries = parse_bundle_payload(&decrypted.file_bytes).expect("parse decrypted bundle");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "a.txt");
    assert_eq!(entries[0].bytes, b"alpha payload");
    assert_eq!(entries[1].name, "b.bin");
    assert_eq!(entries[1].bytes, [1, 2, 3, 4, 5, 6]);
}

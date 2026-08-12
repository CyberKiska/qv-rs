#![forbid(unsafe_code)]

pub mod aead;
pub mod auth;
pub mod bundle;
pub mod bytes;
pub mod erasure;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod lifecycle;
pub mod manifest;
pub mod mlkem;
pub mod policy;
pub mod qcont;
pub mod qenc;
mod rng;
pub mod sss;

pub use auth::{
    AuthPolicy, AuthPolicyLevel, AuthenticityReport, NamedBinaryArtifact, VerificationInputs,
};
pub use bundle::{
    build_bundle_payload, bundle_entry_output_path, bundle_filename_for_time,
    current_bundle_filename, is_bundle_payload, parse_bundle_payload, BundleEntryRef,
    ParsedBundleEntry,
};
pub use error::{QvError, Result};
pub use mlkem::{decapsulate, encapsulate, generate_key_pair};
pub use qcont::verify_successor_lifecycle_authenticity;
pub use qenc::{
    build_qenc_header, current_iso8601_utc_millis, decrypt_qenc, encrypt_qenc, parse_qenc_header,
    DecryptedQenc, EncryptQencOptions, QencHeader, QencMetadata,
};

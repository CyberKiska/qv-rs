pub mod aead;
pub mod auth;
pub mod bundle;
pub mod bytes;
pub mod erasure;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod manifest;
pub mod mlkem;
pub mod policy;
pub mod qcont;
pub mod qenc;
pub mod sss;
pub mod test_support;

pub use auth::{
    AuthPolicy, AuthPolicyLevel, AuthenticityReport, NamedBinaryArtifact, VerificationInputs,
};
pub use bundle::{
    build_bundle_payload, bundle_filename_for_time, current_bundle_filename, is_bundle_payload,
    parse_bundle_payload, BundleEntryRef, ParsedBundleEntry,
};
pub use error::{QvError, Result};
pub use manifest::{
    canonicalize_archive_manifest, canonicalize_manifest_bundle, parse_archive_manifest_bytes,
    parse_manifest_bundle_bytes, ArchiveManifest, ManifestBundle,
};
pub use mlkem::{decapsulate, encapsulate, generate_key_pair};
pub use qcont::{
    attach_manifest_bundle_to_shards, build_qcont_shards, parse_qcont_shard,
    parse_qcont_shard_non_strict, restore_from_shards, AttachManifestBundleOptions,
    AttachedManifestBundle, BuiltQcontShard, BuiltQcontShards, QcontBuildOptions, QcontBuildParams,
    QcontShard, QcontShardParseReport, RestoreQcontOptions, RestoredQcont,
};
pub use qenc::{
    build_qenc_header, current_iso8601_utc_millis, decrypt_qenc, encrypt_qenc, parse_qenc_header,
    DecryptedQenc, EncryptQencOptions, QencHeader, QencMetadata,
};

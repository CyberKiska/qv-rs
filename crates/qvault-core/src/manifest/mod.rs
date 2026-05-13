#[cfg(feature = "legacy-mvp")]
pub mod archive;
#[cfg(feature = "legacy-mvp")]
pub mod bundle;
pub mod jcs;
pub mod strict_json;

#[cfg(feature = "legacy-mvp")]
pub use archive::{
    build_archive_manifest, canonicalize_archive_manifest, parse_archive_manifest_bytes,
    ArchiveManifest, ArchiveManifestCanonicalized, ArchiveManifestQenc, ArchiveManifestReedSolomon,
    ArchiveManifestShamir, ArchiveManifestShardBinding, ArchiveManifestShardBodyDefinition,
    ArchiveManifestSharding, ArchiveManifestShareCommitment, AuthPolicyCommitment,
    BuildArchiveManifestParams, ParsedArchiveManifest, ARCHIVE_MANIFEST_SCHEMA,
    ARCHIVE_MANIFEST_VERSION, LEGACY_ARCHIVE_MANIFEST_SCHEMA, LEGACY_ARCHIVE_MANIFEST_VERSION,
    QV_CANONICALIZATION_LABEL,
};
#[cfg(feature = "legacy-mvp")]
pub use bundle::{
    assert_auth_policy_commitment, build_initial_manifest_bundle, canonicalize_manifest_bundle,
    compute_auth_policy_commitment, compute_manifest_digest, normalize_auth_policy,
    normalize_manifest_bundle, parse_manifest_bundle_bytes, recover_committed_auth_policy,
    validate_auth_policy_commitment_shape, ManifestBundle, ManifestBundleAttachments,
    ManifestBundleCanonicalized, ManifestBundlePublicKeyAttachment,
    ManifestBundleSignatureAttachment, ManifestBundleSignatureTarget,
    ManifestBundleTimestampAttachment, ManifestDigestObject, ParsedManifestBundle,
    AUTH_POLICY_COMMITMENT_ALG, MANIFEST_BUNDLE_TYPE, MANIFEST_BUNDLE_VERSION, MANIFEST_DIGEST_ALG,
};

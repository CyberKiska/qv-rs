//! Pre-successor Quantum Vault compatibility surface.
//!
//! This module is available only with `--features legacy-mvp`. It keeps the
//! retired manifest-v2 / manifest-bundle-v1 / QVqcont-6 implementation reachable
//! for migration fixtures and compatibility investigations without linking it
//! into the default successor build.

pub mod predecessor {
    pub use crate::manifest::{
        build_archive_manifest, canonicalize_archive_manifest, canonicalize_manifest_bundle,
        parse_archive_manifest_bytes, parse_manifest_bundle_bytes, ArchiveManifest,
        ArchiveManifestCanonicalized, ArchiveManifestQenc, ArchiveManifestReedSolomon,
        ArchiveManifestShamir, ArchiveManifestShardBinding, ArchiveManifestShardBodyDefinition,
        ArchiveManifestSharding, ArchiveManifestShareCommitment, AuthPolicyCommitment,
        BuildArchiveManifestParams, ManifestBundle, ManifestBundleAttachments,
        ManifestBundleCanonicalized, ManifestBundlePublicKeyAttachment,
        ManifestBundleSignatureAttachment, ManifestBundleSignatureTarget,
        ManifestBundleTimestampAttachment, ManifestDigestObject, ParsedArchiveManifest,
        ParsedManifestBundle,
    };
    pub use crate::qcont::{
        attach_manifest_bundle_to_shards, build_qcont_shards, parse_qcont_shard,
        parse_qcont_shard_non_strict, restore_from_shards, AttachManifestBundleOptions,
        AttachedManifestBundle, BuiltQcontShard, BuiltQcontShards, QcontBuildOptions,
        QcontBuildParams, QcontShard, QcontShardParseReport, RestoreQcontOptions, RestoredQcont,
    };
}

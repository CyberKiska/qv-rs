#[cfg(feature = "legacy-mvp")]
pub mod attach;
pub mod attach_v7;
pub mod reshare_v7;
#[cfg(feature = "legacy-mvp")]
pub mod restore;
pub mod restore_v7;
#[cfg(feature = "legacy-mvp")]
pub mod shard;
pub mod shard_v7;
#[cfg(feature = "legacy-mvp")]
pub mod split;
pub mod split_v7;

#[cfg(feature = "legacy-mvp")]
pub use attach::{
    attach_manifest_bundle_to_shards, AttachManifestBundleOptions, AttachedManifestBundle,
};
pub use attach_v7::{
    attach_lifecycle_bundle_to_shards, AttachLifecycleOptions, AttachedLifecycleBundle,
    AttachedLifecycleShard, LifecycleSignatureFamily, LifecycleSignatureImport,
    LifecycleSourceEvidenceImport,
};
pub use reshare_v7::{
    reshare_same_state, ReshareMaintenanceArtifacts, ReshareSameStateOptions,
    ReshareSameStateParams, ReshareTransitionOptions, ReshareVerificationReport, ResharedSameState,
};
#[cfg(feature = "legacy-mvp")]
pub use restore::{restore_from_shards, RestoreQcontOptions, RestoredQcont};
pub use restore_v7::{
    restore_qvqcont7_from_shards, RestoreQvqcont7Options, RestoreQvqcont7Selection,
    RestoredQvqcont7,
};
#[cfg(feature = "legacy-mvp")]
pub use shard::{
    parse_qcont_shard, parse_qcont_shard_non_strict, QcontShard, QcontShardAlgorithmMetadata,
    QcontShardDomainStrings, QcontShardMetadata, QcontShardParseReport,
    LEGACY_QCONT_FORMAT_VERSION, QCONT_FORMAT_VERSION,
};
pub use shard_v7::{
    build_qvqcont7_shard, parse_qvqcont7_shard, Qvqcont7Shard, LIFECYCLE_ARTIFACT_FAMILY,
    LIFECYCLE_QCONT_FORMAT_VERSION, LIFECYCLE_QCONT_MAGIC, LIFECYCLE_QCONT_MIN_HEADER_BYTES,
};
#[cfg(feature = "legacy-mvp")]
pub use split::{
    build_qcont_shards, BuiltQcontShard, BuiltQcontShards, QcontBuildOptions, QcontBuildParams,
};
pub use split_v7::{
    build_qvqcont7_shards, BuiltQvqcont7Shard, BuiltQvqcont7Shards, Qvqcont7BuildOptions,
    Qvqcont7BuildParams,
};

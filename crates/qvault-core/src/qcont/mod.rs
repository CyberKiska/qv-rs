//! Successor threshold shards (`QVqcont-7`, `artifactFamily = successor-lifecycle-v1`).

pub mod attach_v7;
pub mod reshare_v7;
pub mod restore_v7;
pub mod shard_v7;
pub mod split_v7;

pub use attach_v7::{
    attach_lifecycle_bundle_to_shards, AttachLifecycleOptions, AttachedLifecycleBundle,
    AttachedLifecycleShard, LifecycleSignatureFamily, LifecycleSignatureImport,
    LifecycleSourceEvidenceImport,
};
pub use reshare_v7::{
    reshare_same_state, ReshareMaintenanceArtifacts, ReshareSameStateOptions,
    ReshareSameStateParams, ReshareTransitionOptions, ReshareVerificationReport, ResharedSameState,
};
pub use restore_v7::{
    restore_qvqcont7_from_shards, verify_successor_lifecycle_authenticity, RestoreQvqcont7Options,
    RestoreQvqcont7Selection, RestoredQvqcont7,
};
pub use shard_v7::{
    build_qvqcont7_shard, parse_qvqcont7_shard, Qvqcont7Shard, LIFECYCLE_ARTIFACT_FAMILY,
    LIFECYCLE_QCONT_FORMAT_VERSION, LIFECYCLE_QCONT_MAGIC, LIFECYCLE_QCONT_MIN_HEADER_BYTES,
    MAX_QVQCONT7_SHARD_BYTES,
};
pub use split_v7::{
    build_qvqcont7_shards, BuiltQvqcont7Shard, BuiltQvqcont7Shards, Qvqcont7BuildOptions,
    Qvqcont7BuildParams,
};

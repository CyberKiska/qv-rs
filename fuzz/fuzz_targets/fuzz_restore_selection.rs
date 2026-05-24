#![no_main]

use libfuzzer_sys::fuzz_target;
use qvault_core::qcont::{
    parse_qvqcont7_shard, restore_qvqcont7_from_shards, RestoreQvqcont7Options,
    RestoreQvqcont7Selection,
};

mod common;

const SINGLE_EXAMPLE_SHARD: &[u8] = include_bytes!(
    "../../crates/qvault-core/tests/data/examples/single/file_500kb.part1-of-5.qcont"
);
const BUNDLE_EXAMPLE_SHARD: &[u8] = include_bytes!(
    "../../crates/qvault-core/tests/data/examples/bundle/bundle-2026-04-25T20-47-18.qvpack.part1-of-6.qcont"
);

fuzz_target!(|data: &[u8]| {
    if !common::input_is_reasonable(data) {
        return;
    }

    let mut shards = Vec::new();
    for bytes in [SINGLE_EXAMPLE_SHARD, BUNDLE_EXAMPLE_SHARD] {
        if data.first().copied().unwrap_or(0) & 0x40 != 0 {
            if let Ok(shard) = parse_qvqcont7_shard(bytes) {
                shards.push(shard);
            }
        }
    }

    if let Ok(shard) = parse_qvqcont7_shard(data) {
        shards.push(shard);
    }
    if let Some(bytes) = common::base64_fixture_bytes(data) {
        if let Ok(shard) = parse_qvqcont7_shard(&bytes) {
            shards.push(shard);
        }
    }
    if shards.is_empty() {
        return;
    }

    let selector = data.first().copied().unwrap_or(0);
    let first = &shards[0];
    let archive_id = first
        .archive_state
        .archive_state
        .value
        .get("archiveId")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let selection = RestoreQvqcont7Selection {
        selected_archive_id: (selector & 0x01 != 0).then(|| archive_id.clone()).flatten(),
        selected_state_id: (selector & 0x02 != 0).then(|| first.state_id.clone()),
        selected_cohort_id: (selector & 0x04 != 0).then(|| first.cohort_id.clone()),
        selected_lifecycle_bundle_digest_hex: (selector & 0x08 != 0)
            .then(|| first.lifecycle_bundle_digest_hex.clone()),
        archive_state_bytes: None,
        lifecycle_bundle_bytes: None,
    };

    let options = RestoreQvqcont7Options {
        selection,
        enforce_policy: selector & 0x10 == 0,
        ..RestoreQvqcont7Options::default()
    };
    let _ = restore_qvqcont7_from_shards(&shards, &options);
});

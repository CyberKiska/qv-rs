#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use qvault_core::qcont::{
    build_qvqcont7_shards, parse_qvqcont7_shard, restore_qvqcont7_from_shards,
    Qvqcont7BuildOptions, Qvqcont7BuildParams, Qvqcont7Shard, RestoreQvqcont7Options,
    RestoreQvqcont7Selection,
};

#[path = "common/attachment.rs"]
mod attachment;
#[path = "common/fixture.rs"]
mod fixture;
#[path = "common/input.rs"]
mod input;

const SPLIT_V7_QENC: &[u8] =
    include_bytes!("../../crates/qvault-core/tests/data/split_v7/single-small.qenc");
const SPLIT_V7_SECRET_QKEY: &[u8] =
    include_bytes!("../../crates/qvault-core/tests/data/split_v7/single-small.secret.qkey");
const SINGLE_EXAMPLE_SHARD: &[u8] = include_bytes!(
    "../../crates/qvault-core/tests/data/examples/single/file_500kb.part1-of-5.qcont"
);
const BUNDLE_EXAMPLE_SHARD: &[u8] = include_bytes!(
    "../../crates/qvault-core/tests/data/examples/bundle/bundle-2026-04-25T20-47-18.qvpack.part1-of-6.qcont"
);

static SPLIT_V7_SHARDS: OnceLock<Vec<Qvqcont7Shard>> = OnceLock::new();

fn split_v7_shards() -> &'static [Qvqcont7Shard] {
    SPLIT_V7_SHARDS.get_or_init(|| {
        let built = build_qvqcont7_shards(
            SPLIT_V7_QENC,
            SPLIT_V7_SECRET_QKEY,
            Qvqcont7BuildParams { n: 5, k: 3 },
            &Qvqcont7BuildOptions::default(),
        )
        .expect("split_v7 fuzz fixture must build");
        built
            .shards
            .iter()
            .map(|shard| {
                parse_qvqcont7_shard(&shard.bytes).expect("split_v7 fuzz fixture shard must parse")
            })
            .collect()
    })
}

fn push_parsed_shard(shards: &mut Vec<Qvqcont7Shard>, bytes: &[u8]) {
    if let Ok(shard) = parse_qvqcont7_shard(bytes) {
        shards.push(shard);
    }
}

fuzz_target!(|data: &[u8]| {
    if !input::input_is_reasonable(data) {
        return;
    }

    let selector = data.first().copied().unwrap_or(0);
    let shard_mask = data.get(1).copied().unwrap_or(0);
    let attach_flags = data.get(2).copied().unwrap_or(0);

    let mut shards = Vec::new();
    if selector & 0x80 != 0 {
        for (index, shard) in split_v7_shards().iter().enumerate() {
            if shard_mask & (1 << index) != 0 {
                shards.push(shard.clone());
            }
        }
    } else {
        let example_bytes = if selector & 0x40 != 0 {
            BUNDLE_EXAMPLE_SHARD
        } else {
            SINGLE_EXAMPLE_SHARD
        };
        push_parsed_shard(&mut shards, example_bytes);
    }

    push_parsed_shard(&mut shards, data);
    if let Some(bytes) = fixture::base64_fixture_bytes(data) {
        push_parsed_shard(&mut shards, &bytes);
    }

    if shards.is_empty() {
        return;
    }

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
        archive_state_bytes: attachment::optional_attachment_bytes(data, attach_flags, true),
        lifecycle_bundle_bytes: attachment::optional_attachment_bytes(data, attach_flags, false),
    };

    let options = RestoreQvqcont7Options {
        selection,
        enforce_policy: selector & 0x10 == 0,
        ..RestoreQvqcont7Options::default()
    };
    let _ = restore_qvqcont7_from_shards(&shards, &options);
});

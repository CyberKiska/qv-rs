use proptest::prelude::*;
use qvault_core::erasure;
#[cfg(feature = "deterministic-test-vectors")]
use qvault_core::sss::split_secret_deterministic;
use qvault_core::sss::{combine_shares, split_secret};

const CASES: u32 = 128;
const RS_MAX_CODEWORD: usize = 255;
const U64_BITS: usize = u64::BITS as usize;

#[cfg(feature = "deterministic-test-vectors")]
#[test]
fn deterministic_shamir_stream_is_explicit_and_reproducible() {
    let random = vec![0x42; 255 + (8 * 2)];
    let first = split_secret_deterministic(b"12345678", 5, 3, &random).expect("first split");
    let second = split_secret_deterministic(b"12345678", 5, 3, &random).expect("second split");
    assert_eq!(first, second);
    assert!(split_secret_deterministic(b"12345678", 5, 3, &random[..random.len() - 1]).is_err());
}

// `combine_shares` has no threshold parameter, so fewer-than-threshold
// distinct shares are not an error invariant for the low-level SSS API.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: CASES,
        ..ProptestConfig::default()
    })]

    #[test]
    fn shamir_recovers_with_threshold_or_more_distinct_shares(
        (secret, shares, threshold, extra_shares, offset) in shamir_cases()
    ) {
        let split = split_secret(&secret, shares, threshold)?;
        let selected = rotated_selection(&split, threshold + extra_shares, offset);

        let recovered = combine_shares(&selected)?;

        prop_assert_eq!(recovered, secret);
    }

    #[test]
    fn shamir_rejects_duplicate_share_coordinates(
        (secret, shares, threshold, _, _) in shamir_cases()
    ) {
        let split = split_secret(&secret, shares, threshold)?;
        let duplicate = vec![split[0].clone(), split[0].clone()];

        prop_assert!(combine_shares(&duplicate).is_err());
    }

    #[test]
    fn reed_solomon_recovers_with_all_fragments(
        (payload, original_blobs, allowed_failures) in reed_solomon_cases()
    ) {
        let padded = padded_rs_input(&payload, original_blobs, allowed_failures);
        let fragments = erasure::split(
            &padded,
            original_blobs,
            allowed_failures,
            RS_MAX_CODEWORD,
        )?;

        let recovered = erasure::recombine(
            &fragments,
            payload.len(),
            original_blobs,
            allowed_failures,
            RS_MAX_CODEWORD,
        )?;

        prop_assert_eq!(fragments.len(), original_blobs + (allowed_failures * 2));
        prop_assert_eq!(recovered, payload);
    }

    #[test]
    fn reed_solomon_recovers_with_up_to_allowed_failures_corrupt_fragments(
        (payload, original_blobs, allowed_failures, corrupt_count, offset, seed) in reed_solomon_corruption_cases()
    ) {
        let padded = padded_rs_input(&payload, original_blobs, allowed_failures);
        let mut fragments = erasure::split(
            &padded,
            original_blobs,
            allowed_failures,
            RS_MAX_CODEWORD,
        )?;

        let n = original_blobs + (allowed_failures * 2);
        for index in rotated_indices(n, corrupt_count, offset) {
            if ((seed >> (index % U64_BITS)) & 1) == 0 {
                fragments[index].fill(0);
            } else {
                corrupt_fragment(&mut fragments[index], seed, index);
            }
        }

        let recovered = erasure::recombine(
            &fragments,
            payload.len(),
            original_blobs,
            allowed_failures,
            RS_MAX_CODEWORD,
        )?;

        prop_assert_eq!(recovered, payload);
    }
}

prop_compose! {
    fn shamir_cases()
        (
            secret in prop::collection::vec(any::<u8>(), 1..=128),
            shares in 2usize..=16,
            offset in any::<usize>(),
            threshold_offset in any::<usize>(),
            extra_offset in any::<usize>(),
        )
        -> (Vec<u8>, usize, usize, usize, usize)
    {
        let threshold = 2 + (threshold_offset % (shares - 1));
        let extra_shares = extra_offset % (shares - threshold + 1);
        (secret, shares, threshold, extra_shares, offset)
    }
}

prop_compose! {
    fn reed_solomon_cases()
        (
            payload in prop::collection::vec(any::<u8>(), 0..=512),
            original_blobs in 2usize..=8,
            allowed_failures in 0usize..=4,
        )
        -> (Vec<u8>, usize, usize)
    {
        (payload, original_blobs, allowed_failures)
    }
}

prop_compose! {
    fn reed_solomon_corruption_cases()
        (
            (payload, original_blobs, allowed_failures) in reed_solomon_cases(),
            offset in any::<usize>(),
            seed in any::<u64>(),
        )
        (
            corrupt_count in 0usize..=allowed_failures,
            payload in Just(payload),
            original_blobs in Just(original_blobs),
            allowed_failures in Just(allowed_failures),
            offset in Just(offset),
            seed in Just(seed),
        )
        -> (Vec<u8>, usize, usize, usize, usize, u64)
    {
        (
            payload,
            original_blobs,
            allowed_failures,
            corrupt_count,
            offset,
            seed,
        )
    }
}

fn rotated_selection<T: Clone>(values: &[T], count: usize, offset: usize) -> Vec<T> {
    debug_assert!(count <= values.len());
    let start = offset % values.len();
    (0..count)
        .map(|index| values[(start + index) % values.len()].clone())
        .collect()
}

fn rotated_indices(len: usize, count: usize, offset: usize) -> Vec<usize> {
    debug_assert!(count <= len);
    let start = offset % len;
    (0..count).map(|index| (start + index) % len).collect()
}

fn padded_rs_input(payload: &[u8], original_blobs: usize, allowed_failures: usize) -> Vec<u8> {
    let input_size = rs_input_size(original_blobs, allowed_failures);
    let padded_len = payload.len().div_ceil(input_size) * input_size;
    let mut padded = vec![0u8; padded_len];
    padded[..payload.len()].copy_from_slice(payload);
    padded
}

fn rs_input_size(original_blobs: usize, allowed_failures: usize) -> usize {
    let n = original_blobs + (allowed_failures * 2);
    let encode_size = (RS_MAX_CODEWORD / n) * n;
    (encode_size * original_blobs) / n
}

fn corrupt_fragment(fragment: &mut [u8], seed: u64, fragment_index: usize) {
    for (byte_index, byte) in fragment.iter_mut().enumerate() {
        let shift = ((byte_index + fragment_index) % U64_BITS) as u32;
        let mask = (((seed.rotate_left(shift) as u8) ^ fragment_index as u8) | 1)
            .wrapping_add(byte_index as u8);
        *byte ^= mask.max(1);
    }
}

use qvault_core::erasure::{recombine, split};
use qvault_core::hash::sha3_512_hex;

use proptest::prelude::*;

#[test]
fn reed_solomon_rejects_invalid_layouts_without_panicking() {
    for (original, failures, max) in [
        (0, 1, 255),
        (3, 1, 0),
        (256, 0, 255),
        (usize::MAX, 1, 255),
        (3, usize::MAX, 255),
    ] {
        assert!(split(b"input", original, failures, max).is_err());
        assert!(recombine(&[], 0, original, failures, max).is_err());
    }
}

#[test]
fn reed_solomon_zero_pads_a_short_final_block_like_the_js_codec() {
    // The 5-of-3 layout consumes 153 source bytes per block. Exercise one
    // complete block plus a deliberately short final block.
    let input = (0..154).map(|value| value as u8).collect::<Vec<_>>();
    let fragments = split(&input, 3, 1, 255).expect("split non-aligned input");
    let fragment_hashes = fragments
        .iter()
        .map(|fragment| sha3_512_hex(fragment))
        .collect::<Vec<_>>();
    assert_eq!(
        fragment_hashes,
        [
            "832f1bdd46161c635ee2ad8e0468901725e94908a2685291fb70743016fe2c507567576d84bcf694a33fe8af1d821bdee7360e6be9f20ed855fe6d6db4a87a19",
            "e5ca23a4e11816df7492af58f2f782f1dc88a056e935e56f8e50b8bedb4e59fe1f55c4c5a9ab9b3994eeb71eacc4f76f19e5395a1945bc2ed6f5c5292958cbce",
            "4b954fb5c201d18e8434cf039cc788f204321ce510e5c6d27598a04f00ba889a4cdff04c2de645070b3094108b87d3e4bcaaa05f0fd154990b96610292268791",
            "1ebaebeaa992695ede5f709e5ce44abf953a10d54afec7286ff6eb53df58d6d7e5d07295b6e8cb9b14f0f7621353982270fbaa01d810838ac6dde927389771b4",
            "9fbf8a9798f06cf6bc5a8c3c55de9ac5bdefd693b5737b8bbef14ec396632e2ea8a61c63800fcf3965befa9dca5e7bbaafe11c0e401bff76ea0486e68c7ff57b",
        ]
    );
    let restored = recombine(&fragments, input.len(), 3, 1, 255).expect("recombine");
    assert_eq!(restored, input);
}

#[test]
fn reed_solomon_rejects_truncated_or_overlong_fragment_geometry() {
    let input = vec![0x5a; 154];
    let mut fragments = split(&input, 3, 1, 255).expect("split");
    for fragment in &mut fragments {
        fragment.pop();
    }
    assert!(recombine(&fragments, input.len(), 3, 1, 255).is_err());

    let fragments = split(&input, 3, 1, 255).expect("split");
    assert!(recombine(&fragments, 10_000, 3, 1, 255).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn reed_solomon_public_api_is_panic_free_and_round_trips_supported_layouts(
        input in proptest::collection::vec(any::<u8>(), 0..600),
        original in 0usize..300,
        failures in 0usize..300,
        max_codeword in 0usize..300,
    ) {
        let outcome = std::panic::catch_unwind(|| {
            let fragments = split(&input, original, failures, max_codeword)?;
            recombine(&fragments, input.len(), original, failures, max_codeword)
        });
        prop_assert!(outcome.is_ok(), "public erasure API panicked");
        if let Ok(Ok(restored)) = outcome {
            prop_assert_eq!(restored, input);
        }
    }
}

use qvault_core::manifest::jcs::canonicalize_json;

fn canon(n: f64) -> String {
    canonicalize_json(&n).unwrap()
}

#[test]
fn compare_vectors() {
    let cases: Vec<(f64, &str)> = vec![
        (0.0, "0"),
        (-0.0, "0"),
        (1.0, "1"),
        (-1.0, "-1"),
        (0.5, "0.5"),
        (-0.5, "-0.5"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (1e-7, "1e-7"),
        (1e-6, "0.000001"),
        (0.1_f64 + 0.2_f64, "0.30000000000000004"),
        (9007199254740991.0, "9007199254740991"),
        (-9007199254740991.0, "-9007199254740991"),
        (f64::from_bits(1), "5e-324"),
        (-f64::from_bits(1), "-5e-324"),
        (f64::MAX, "1.7976931348623157e+308"),
        (-f64::MAX, "-1.7976931348623157e+308"),
    ];
    for (v, exp) in cases {
        let got = canon(v);
        assert_eq!(got, exp, "mismatch for {:?}", v);
    }
}

use crate::error::{err, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureSuiteInfo {
    pub canonical: &'static str,
    pub display_name: &'static str,
    pub family: &'static str,
    pub strong_pq: bool,
    pub legacy: bool,
    pub public_key_type: &'static str,
}

const MLDSA_44: SignatureSuiteInfo = SignatureSuiteInfo {
    canonical: "mldsa-44",
    display_name: "ML-DSA-44",
    family: "mldsa",
    strong_pq: false,
    legacy: false,
    public_key_type: "ml-dsa-public-key",
};

const MLDSA_65: SignatureSuiteInfo = SignatureSuiteInfo {
    canonical: "mldsa-65",
    display_name: "ML-DSA-65",
    family: "mldsa",
    strong_pq: false,
    legacy: false,
    public_key_type: "ml-dsa-public-key",
};

const MLDSA_87: SignatureSuiteInfo = SignatureSuiteInfo {
    canonical: "mldsa-87",
    display_name: "ML-DSA-87",
    family: "mldsa",
    strong_pq: true,
    legacy: false,
    public_key_type: "ml-dsa-public-key",
};

const SLHDSA_SHAKE_128S: SignatureSuiteInfo = SignatureSuiteInfo {
    canonical: "slhdsa-shake-128s",
    display_name: "SLH-DSA-SHAKE-128s",
    family: "slhdsa-shake",
    strong_pq: false,
    legacy: false,
    public_key_type: "slh-dsa-public-key",
};

const SLHDSA_SHAKE_192S: SignatureSuiteInfo = SignatureSuiteInfo {
    canonical: "slhdsa-shake-192s",
    display_name: "SLH-DSA-SHAKE-192s",
    family: "slhdsa-shake",
    strong_pq: false,
    legacy: false,
    public_key_type: "slh-dsa-public-key",
};

const SLHDSA_SHAKE_256S: SignatureSuiteInfo = SignatureSuiteInfo {
    canonical: "slhdsa-shake-256s",
    display_name: "SLH-DSA-SHAKE-256s",
    family: "slhdsa-shake",
    strong_pq: true,
    legacy: false,
    public_key_type: "slh-dsa-public-key",
};

const SLHDSA_SHAKE_256F: SignatureSuiteInfo = SignatureSuiteInfo {
    canonical: "slhdsa-shake-256f",
    display_name: "SLH-DSA-SHAKE-256f",
    family: "slhdsa-shake",
    strong_pq: true,
    legacy: false,
    public_key_type: "slh-dsa-public-key",
};

const ED25519: SignatureSuiteInfo = SignatureSuiteInfo {
    canonical: "ed25519",
    display_name: "Ed25519",
    family: "ed25519",
    strong_pq: false,
    legacy: true,
    public_key_type: "ed25519-public-key",
};

pub fn normalize_signature_suite(value: &str) -> Result<&'static str> {
    let normalized = value.trim().to_ascii_lowercase().replace(['_', ' '], "-");
    let canonical = match normalized.as_str() {
        "ml-dsa-44" | "mldsa44" | "mldsa-44" => MLDSA_44.canonical,
        "ml-dsa-65" | "mldsa65" | "mldsa-65" => MLDSA_65.canonical,
        "ml-dsa-87" | "mldsa87" | "mldsa-87" => MLDSA_87.canonical,
        "slh-dsa-shake-128s" | "slhdsa-shake-128s" => SLHDSA_SHAKE_128S.canonical,
        "slh-dsa-shake-192s" | "slhdsa-shake-192s" => SLHDSA_SHAKE_192S.canonical,
        "slh-dsa-shake-256s" | "slhdsa-shake-256s" => SLHDSA_SHAKE_256S.canonical,
        "slh-dsa-shake-256f" | "slhdsa-shake-256f" => SLHDSA_SHAKE_256F.canonical,
        "ed25519" => ED25519.canonical,
        _ => return Err(err(format!("Unsupported signature suite: {value}"))),
    };
    Ok(canonical)
}

pub fn get_signature_suite_info(value: &str) -> Result<SignatureSuiteInfo> {
    Ok(match normalize_signature_suite(value)? {
        "mldsa-44" => MLDSA_44,
        "mldsa-65" => MLDSA_65,
        "mldsa-87" => MLDSA_87,
        "slhdsa-shake-128s" => SLHDSA_SHAKE_128S,
        "slhdsa-shake-192s" => SLHDSA_SHAKE_192S,
        "slhdsa-shake-256s" => SLHDSA_SHAKE_256S,
        "slhdsa-shake-256f" => SLHDSA_SHAKE_256F,
        "ed25519" => ED25519,
        _ => unreachable!(),
    })
}

pub fn is_strong_pq_suite(value: &str) -> Result<bool> {
    Ok(get_signature_suite_info(value)?.strong_pq)
}

pub fn list_supported_signature_suites() -> &'static [&'static str] {
    &[
        MLDSA_44.canonical,
        MLDSA_65.canonical,
        MLDSA_87.canonical,
        SLHDSA_SHAKE_128S.canonical,
        SLHDSA_SHAKE_192S.canonical,
        SLHDSA_SHAKE_256S.canonical,
        SLHDSA_SHAKE_256F.canonical,
        ED25519.canonical,
    ]
}

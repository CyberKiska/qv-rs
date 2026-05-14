use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QvCode {
    InvalidFormat,
    InvalidSelection,
    AmbiguousInputs,
    NotEnoughShards,
    IntegrityMismatch,
    VerificationFailed,
    PolicyNotSatisfied,
    ReshareContractViolation,
    UnsupportedFormat,
    RestoreFailed,
    /// Reconstructed `.qenc` / private key material failed hash or header binding checks.
    RestoredIntegrityFailed,
    /// Selected cohort embeds multiple lifecycle-bundle digests; operator must pass explicit acknowledgement.
    RestoreLifecycleVariantAckRequired,
}

impl QvCode {
    /// Stable `qvCode` strings aligned with `quantum-vault` `src/core/cli/lib/exit.js` (`QV_CODE`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidFormat | Self::UnsupportedFormat => "FORMAT_POLICY_REJECT",
            Self::InvalidSelection | Self::AmbiguousInputs => "AMBIGUOUS_INPUTS",
            Self::NotEnoughShards => "QUORUM_UNREACHABLE",
            Self::IntegrityMismatch => "QUORUM_UNREACHABLE",
            Self::VerificationFailed => "UNEXPECTED",
            Self::PolicyNotSatisfied => "POLICY_NOT_SATISFIED",
            Self::ReshareContractViolation => "RESHARE_CONTRACT_VIOLATION",
            Self::RestoreFailed => "UNEXPECTED",
            Self::RestoredIntegrityFailed => "RESTORED_INTEGRITY_FAILED",
            Self::RestoreLifecycleVariantAckRequired => "RESTORE_LIFECYCLE_VARIANT_ACK_REQUIRED",
        }
    }
}

#[derive(Debug, Error)]
pub enum QvError {
    #[error("{0}")]
    Message(String),
    #[error("{message}")]
    Coded { code: QvCode, message: String },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl QvError {
    pub fn qv_code(&self) -> Option<QvCode> {
        match self {
            Self::Coded { code, .. } => Some(*code),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, QvError>;

pub fn err(message: impl Into<String>) -> QvError {
    QvError::Message(message.into())
}

pub fn coded(code: QvCode, message: impl Into<String>) -> QvError {
    QvError::Coded {
        code,
        message: message.into(),
    }
}

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
    UnsupportedFormat,
    RestoreFailed,
}

impl QvCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidFormat => "QV_INVALID_FORMAT",
            Self::InvalidSelection => "QV_INVALID_SELECTION",
            Self::AmbiguousInputs => "QV_AMBIGUOUS_INPUTS",
            Self::NotEnoughShards => "QV_NOT_ENOUGH_SHARDS",
            Self::IntegrityMismatch => "QV_INTEGRITY_MISMATCH",
            Self::VerificationFailed => "QV_VERIFICATION_FAILED",
            Self::PolicyNotSatisfied => "QV_POLICY_NOT_SATISFIED",
            Self::UnsupportedFormat => "QV_UNSUPPORTED_FORMAT",
            Self::RestoreFailed => "QV_RESTORE_FAILED",
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

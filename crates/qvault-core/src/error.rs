use thiserror::Error;

#[derive(Debug, Error)]
pub enum QvError {
    #[error("{0}")]
    Message(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, QvError>;

pub fn err(message: impl Into<String>) -> QvError {
    QvError::Message(message.into())
}

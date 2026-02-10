use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid magic bytes (expected VWH\\0)")]
    InvalidMagic,

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u16),

    #[error("Invalid intent value: {0}")]
    InvalidIntent(u8),

    #[error("Invalid intent string: {0}")]
    InvalidIntentString(String),

    #[error("Invalid artifact ID")]
    InvalidArtifactId,

    #[error("Invalid hex encoding")]
    InvalidHex,

    #[error("Signature verification failed")]
    SignatureInvalid,

    #[error("File too small (minimum {expected} bytes, got {actual})")]
    FileTooSmall { expected: usize, actual: usize },

    #[error("Unexpected EOF while reading {field}")]
    UnexpectedEof { field: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}


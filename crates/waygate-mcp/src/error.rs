use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("upstream not found: {0}")]
    UpstreamNotFound(String),

    #[error("tool not found: {0}")]
    ToolNotFound(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

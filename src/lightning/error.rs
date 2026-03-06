use thiserror::Error;

#[derive(Error, Debug)]
pub enum LightningError {
    #[error("LDK node error: {0}")]
    Node(String),

    #[error("LSP communication error: {0}")]
    Lsp(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("invoice error: {0}")]
    Invoice(String),

    #[error("payment error: {0}")]
    Payment(String),

    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, LightningError>;

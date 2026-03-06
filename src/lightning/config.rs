use serde::{Deserialize, Serialize};

/// Configuration for the Lightning wallet and its LSP connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningConfig {
    /// Bitcoin network (bitcoin, testnet, signet, regtest)
    pub network: bitcoin::Network,

    /// Path for LDK node persistent storage (SQLite, channel state, etc.)
    pub storage_path: String,

    /// Esplora server URL for chain data
    pub esplora_url: String,

    /// Rapid Gossip Sync URL for network graph
    pub rgs_url: String,

    /// LSP HTTP endpoint for registration and invoice upload
    pub lsp_url: String,

    /// LSP node public key (hex-encoded)
    pub lsp_pubkey: String,

    /// LSP node address (host:port) for Lightning P2P
    pub lsp_address: String,

    /// Optional listening port for incoming connections
    pub listening_port: Option<u16>,

    /// Number of static invoices to pre-generate and upload
    #[serde(default = "default_invoice_batch_size")]
    pub invoice_batch_size: usize,

    /// Invoice expiry in seconds (default: 14 days)
    #[serde(default = "default_invoice_expiry_secs")]
    pub invoice_expiry_secs: u64,
}

fn default_invoice_batch_size() -> usize {
    10
}

fn default_invoice_expiry_secs() -> u64 {
    14 * 24 * 3600 // 14 days
}

impl LightningConfig {
    /// Create a config for regtest development.
    pub fn regtest(storage_path: &str, lsp_pubkey: &str) -> Self {
        Self {
            network: bitcoin::Network::Regtest,
            storage_path: storage_path.to_string(),
            esplora_url: "http://127.0.0.1:3002".to_string(),
            rgs_url: "https://rapidsync.lightningdevkit.org/testnet/snapshot".to_string(),
            lsp_url: "http://127.0.0.1:8080".to_string(),
            lsp_pubkey: lsp_pubkey.to_string(),
            lsp_address: "127.0.0.1:9735".to_string(),
            listening_port: Some(9736),
            invoice_batch_size: default_invoice_batch_size(),
            invoice_expiry_secs: default_invoice_expiry_secs(),
        }
    }
}

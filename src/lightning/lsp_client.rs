use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::error::{LightningError, Result};

/// HTTP client for communicating with the LSP server.
#[derive(Debug, Clone)]
pub struct LspClient {
    client: Client,
    base_url: String,
}

/// Response from lsp-register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub phantom_scid: String,
    pub opening_fee_ppm: u32,
    pub min_opening_fee_msat: u64,
    pub min_channel_size_sat: u64,
    pub max_channel_size_sat: u64,
    pub lsp_pubkey: String,
}

/// Response from lsp-upload-invoice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResponse {
    pub status: String,
    pub payment_hash: String,
    pub expiry_unix: i64,
}

impl LspClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(LightningError::Network)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        })
    }

    /// Register with the LSP, returning a phantom SCID and fee schedule.
    pub async fn register(&self, node_pubkey: &str) -> Result<RegistrationResponse> {
        let resp = self
            .client
            .post(format!("{}/api/register", self.base_url))
            .json(&serde_json::json!({ "node_pubkey": node_pubkey }))
            .send()
            .await?
            .error_for_status()
            .map_err(LightningError::Network)?
            .json::<RegistrationResponse>()
            .await?;

        Ok(resp)
    }

    /// Upload a static invoice for offline receives.
    pub async fn upload_invoice(
        &self,
        node_pubkey: &str,
        bolt12_invoice_hex: &str,
        payment_hash: &str,
        expiry_unix: i64,
        amount_msat: Option<u64>,
    ) -> Result<UploadResponse> {
        let mut body = serde_json::json!({
            "node_pubkey": node_pubkey,
            "bolt12_invoice": bolt12_invoice_hex,
            "payment_hash": payment_hash,
            "expiry_unix": expiry_unix,
        });

        if let Some(amt) = amount_msat {
            body["amount_msat"] = serde_json::json!(amt);
        }

        let resp = self
            .client
            .post(format!("{}/api/upload-invoice", self.base_url))
            .json(&body)
            .send()
            .await?
            .error_for_status()
            .map_err(LightningError::Network)?
            .json::<UploadResponse>()
            .await?;

        Ok(resp)
    }
}

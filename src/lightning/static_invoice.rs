use ldk_node::lightning_invoice::Bolt11InvoiceDescription;

use super::error::{LightningError, Result};
use super::lsp_client::LspClient;

/// Manages static invoice generation and rotation.
///
/// Static invoices allow receiving payments while offline:
/// 1. Generate preimages locally (never shared with LSP)
/// 2. Build BOLT 12 invoices from the preimages
/// 3. Upload the invoices (without preimages) to the LSP
/// 4. LSP serves them to payers; only the wallet can claim with the preimage
///
/// This ensures non-custodial security: the LSP holds HTLCs but can never
/// claim payments because it doesn't know the preimages.

/// Upload a batch of static invoices to the LSP.
///
/// Uses ldk-node's `receive_via_jit_channel()` to generate invoices with
/// locally-held preimages, then uploads them via the LSP client.
pub async fn upload_static_invoices(
    node: &ldk_node::Node,
    lsp_client: &LspClient,
    node_pubkey: &str,
    batch_size: usize,
    expiry_secs: u64,
) -> Result<Vec<String>> {
    let mut uploaded_hashes = Vec::new();
    let expiry_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| LightningError::Other(e.into()))?
        .as_secs() as i64
        + expiry_secs as i64;

    let desc = ldk_node::lightning_invoice::Description::new(
        "static invoice for offline receives".to_string(),
    )
    .map_err(|e| LightningError::Invoice(format!("invalid description: {:?}", e)))?;
    let description = Bolt11InvoiceDescription::Direct(desc);

    for _ in 0..batch_size {
        // Generate a JIT channel invoice via ldk-node.
        // ldk-node generates the preimage locally and stores it in its DB.
        // We get back an invoice we can upload to the LSP.
        let invoice = node
            .bolt11_payment()
            .receive_via_jit_channel(
                100_000_000, // 100k sat minimum
                &description,
                expiry_secs as u32,
                None,
            )
            .map_err(|e| {
                LightningError::Invoice(format!("failed to create JIT invoice: {:?}", e))
            })?;

        let invoice_str = invoice.to_string();

        // Extract payment hash from the invoice
        let payment_hash = hex::encode(AsRef::<[u8]>::as_ref(invoice.payment_hash()));
        let invoice_hex = hex::encode(invoice_str.as_bytes());

        // Upload to LSP
        lsp_client
            .upload_invoice(node_pubkey, &invoice_hex, &payment_hash, expiry_unix, None)
            .await?;

        uploaded_hashes.push(payment_hash);
    }

    log::info!(
        "uploaded {} static invoices (expiry: {})",
        uploaded_hashes.len(),
        expiry_unix
    );

    Ok(uploaded_hashes)
}

/// Check if invoices need rotation (within 4-day buffer of expiry).
pub fn needs_rotation(last_upload_unix: i64, expiry_secs: u64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let buffer_secs = 4 * 24 * 3600; // 4 days
    let expiry_at = last_upload_unix + expiry_secs as i64;

    now >= expiry_at - buffer_secs
}

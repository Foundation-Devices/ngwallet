use super::error::{LightningError, Result};

/// Create a BOLT 12 offer using ldk-node's async receive support.
///
/// The offer includes blinded paths through the LSP so payments
/// can be received even when offline (the LSP serves static invoices
/// and holds HTLCs until the wallet comes online).
pub fn create_offer(node: &ldk_node::Node) -> Result<String> {
    let offer = node
        .bolt12_payment()
        .receive_variable_amount("Lightning Torrent wallet", None)
        .map_err(|e| LightningError::Invoice(format!("failed to create offer: {:?}", e)))?;

    Ok(offer.to_string())
}

/// Create a fixed-amount BOLT 12 offer.
pub fn create_offer_with_amount(node: &ldk_node::Node, amount_msat: u64) -> Result<String> {
    let offer = node
        .bolt12_payment()
        .receive(amount_msat, "Lightning Torrent wallet", None, None)
        .map_err(|e| LightningError::Invoice(format!("failed to create offer: {:?}", e)))?;

    Ok(offer.to_string())
}

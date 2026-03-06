use ldk_node::lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};

use super::error::{LightningError, Result};

/// Re-export PaymentId for public API.
pub type PaymentId = ldk_node::lightning::ln::channelmanager::PaymentId;

/// A Lightning payment record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningPayment {
    pub id: String,
    pub amount_msat: Option<u64>,
    pub direction: PaymentDirection,
    pub status: PaymentStatus,
    pub timestamp: u64,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PaymentDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PaymentStatus {
    Pending,
    Succeeded,
    Failed,
}

/// Channel balance information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningBalance {
    /// Total balance across all channels (spendable)
    pub spendable_msat: u64,
    /// Total inbound liquidity
    pub inbound_msat: u64,
    /// Total channel capacity
    pub total_channel_capacity_msat: u64,
    /// Number of open channels
    pub num_channels: usize,
}

/// Pay a BOLT 12 offer.
pub fn pay_offer(
    node: &ldk_node::Node,
    offer_str: &str,
    amount_msat: Option<u64>,
) -> Result<PaymentId> {
    let offer: ldk_node::lightning::offers::offer::Offer = offer_str
        .parse()
        .map_err(|_| LightningError::Payment("invalid BOLT 12 offer".into()))?;

    let payment_id = if let Some(amt) = amount_msat {
        node.bolt12_payment()
            .send_using_amount(&offer, amt, None, None)
            .map_err(|e| LightningError::Payment(format!("bolt12 send failed: {:?}", e)))?
    } else {
        node.bolt12_payment()
            .send(&offer, None, None)
            .map_err(|e| LightningError::Payment(format!("bolt12 send failed: {:?}", e)))?
    };

    Ok(payment_id)
}

/// Pay a BOLT 11 invoice.
pub fn pay_bolt11(node: &ldk_node::Node, invoice_str: &str) -> Result<PaymentId> {
    let invoice: Bolt11Invoice = invoice_str
        .parse()
        .map_err(|_| LightningError::Payment("invalid BOLT 11 invoice".into()))?;

    let payment_id = node
        .bolt11_payment()
        .send(&invoice, None)
        .map_err(|e| LightningError::Payment(format!("bolt11 send failed: {:?}", e)))?;

    Ok(payment_id)
}

/// Get channel balance summary.
pub fn get_balance(node: &ldk_node::Node) -> LightningBalance {
    let channels = node.list_channels();
    let mut spendable_msat = 0u64;
    let mut inbound_msat = 0u64;
    let mut total_capacity_msat = 0u64;

    for ch in &channels {
        if ch.is_usable {
            spendable_msat += ch.outbound_capacity_msat;
            inbound_msat += ch.inbound_capacity_msat;
        }
        total_capacity_msat += ch.channel_value_sats * 1000;
    }

    LightningBalance {
        spendable_msat,
        inbound_msat,
        total_channel_capacity_msat: total_capacity_msat,
        num_channels: channels.len(),
    }
}

/// Convert ldk-node payment details to our LightningPayment type.
pub fn list_payments(node: &ldk_node::Node) -> Vec<LightningPayment> {
    node.list_payments()
        .into_iter()
        .map(|p| {
            let direction = match p.direction {
                ldk_node::payment::PaymentDirection::Inbound => PaymentDirection::Inbound,
                ldk_node::payment::PaymentDirection::Outbound => PaymentDirection::Outbound,
            };
            let status = match p.status {
                ldk_node::payment::PaymentStatus::Pending => PaymentStatus::Pending,
                ldk_node::payment::PaymentStatus::Succeeded => PaymentStatus::Succeeded,
                ldk_node::payment::PaymentStatus::Failed => PaymentStatus::Failed,
            };
            LightningPayment {
                id: format!("{:?}", p.id),
                amount_msat: p.amount_msat,
                direction,
                status,
                timestamp: p.latest_update_timestamp,
                description: None,
            }
        })
        .collect()
}

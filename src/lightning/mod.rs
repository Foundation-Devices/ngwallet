//! Lightning wallet module — BOLT 12 async payments via LDK Node + LSP.
//!
//! This module provides a `LightningWallet` type that sits alongside the existing
//! BDK-based on-chain wallet. It uses `ldk-node` for channel management, routing,
//! and payments, with an LSP (Lightning Service Provider) for:
//!
//! - JIT (Just-In-Time) 0-conf channel opens on first receive
//! - Static invoice serving for offline payment receipt
//! - BOLT 12 offer/invoice_request relay
//!
//! **Key security property**: Non-custodial. Preimages are generated and held
//! locally — the LSP never learns them and cannot claim payments.

pub mod config;
pub mod error;
pub mod lsp_client;
pub mod offer;
pub mod payment;
pub mod static_invoice;

use config::LightningConfig;
use error::{LightningError, Result};
use ldk_node::lightning::ln::msgs::SocketAddress;
use lsp_client::{LspClient, RegistrationResponse};

/// Lightning wallet — manages LDK node, LSP connection, and payments.
pub struct LightningWallet {
    node: ldk_node::Node,
    lsp_client: LspClient,
    config: LightningConfig,
}

impl LightningWallet {
    /// Create a new Lightning wallet.
    ///
    /// This initializes the LDK node with the given configuration but does NOT
    /// start it. Call `start()` to begin syncing and processing events.
    pub fn new(config: LightningConfig) -> Result<Self> {
        let lsp_pubkey: ldk_node::bitcoin::secp256k1::PublicKey = config
            .lsp_pubkey
            .parse()
            .map_err(|_| LightningError::Config("invalid LSP pubkey".into()))?;

        let lsp_addr: SocketAddress = config
            .lsp_address
            .parse()
            .map_err(|_| LightningError::Config("invalid LSP address".into()))?;

        let mut builder = ldk_node::Builder::new();
        builder.set_network(to_ldk_network(config.network));
        builder.set_storage_dir_path(config.storage_path.clone());
        builder.set_chain_source_esplora(config.esplora_url.clone(), None);
        builder.set_gossip_source_rgs(config.rgs_url.clone());
        builder.set_liquidity_source_lsps2(lsp_pubkey, lsp_addr.clone(), None);

        if let Some(port) = config.listening_port {
            let addr = SocketAddress::TcpIpV4 {
                addr: [0, 0, 0, 0],
                port,
            };
            builder
                .set_listening_addresses(vec![addr])
                .map_err(|e| LightningError::Config(format!("listening address: {:?}", e)))?;
        }

        let node = builder
            .build()
            .map_err(|e| LightningError::Node(format!("failed to build node: {:?}", e)))?;

        let lsp_client = LspClient::new(&config.lsp_url)?;

        Ok(Self {
            node,
            lsp_client,
            config,
        })
    }

    /// Start the LDK node (chain sync, gossip sync, event processing).
    pub fn start(&self) -> Result<()> {
        self.node
            .start()
            .map_err(|e| LightningError::Node(format!("failed to start node: {:?}", e)))
    }

    /// Stop the LDK node gracefully.
    pub fn stop(&self) -> Result<()> {
        self.node
            .stop()
            .map_err(|e| LightningError::Node(format!("failed to stop node: {:?}", e)))
    }

    /// Get the node's public key (hex string).
    pub fn node_pubkey(&self) -> String {
        self.node.node_id().to_string()
    }

    /// Register with the LSP and get a phantom SCID + fee schedule.
    pub async fn register_with_lsp(&self) -> Result<RegistrationResponse> {
        let pubkey = self.node_pubkey();
        self.lsp_client.register(&pubkey).await
    }

    /// Create a BOLT 12 offer for receiving payments.
    pub fn create_offer(&self) -> Result<String> {
        offer::create_offer(&self.node)
    }

    /// Create a fixed-amount BOLT 12 offer.
    pub fn create_offer_with_amount(&self, amount_msat: u64) -> Result<String> {
        offer::create_offer_with_amount(&self.node, amount_msat)
    }

    /// Generate and upload static invoices to the LSP for offline receives.
    pub async fn upload_static_invoices(&self) -> Result<Vec<String>> {
        let pubkey = self.node_pubkey();
        static_invoice::upload_static_invoices(
            &self.node,
            &self.lsp_client,
            &pubkey,
            self.config.invoice_batch_size,
            self.config.invoice_expiry_secs,
        )
        .await
    }

    /// Pay a BOLT 12 offer.
    pub fn pay_offer(
        &self,
        offer_str: &str,
        amount_msat: Option<u64>,
    ) -> Result<payment::PaymentId> {
        payment::pay_offer(&self.node, offer_str, amount_msat)
    }

    /// Pay a BOLT 11 invoice.
    pub fn pay_bolt11(&self, invoice_str: &str) -> Result<payment::PaymentId> {
        payment::pay_bolt11(&self.node, invoice_str)
    }

    /// Get the current channel balance.
    pub fn balance(&self) -> payment::LightningBalance {
        payment::get_balance(&self.node)
    }

    /// List all payments.
    pub fn list_payments(&self) -> Vec<payment::LightningPayment> {
        payment::list_payments(&self.node)
    }

    /// Get the next pending event from the LDK node, if any.
    pub fn next_event(&self) -> Option<ldk_node::Event> {
        self.node.next_event()
    }

    /// Mark the current event as handled.
    pub fn event_handled(&self) {
        let _ = self.node.event_handled();
    }

    /// Access the underlying ldk_node::Node for advanced operations.
    pub fn inner_node(&self) -> &ldk_node::Node {
        &self.node
    }

    /// Access the LSP client.
    pub fn lsp_client(&self) -> &LspClient {
        &self.lsp_client
    }

    /// Access the config.
    pub fn config(&self) -> &LightningConfig {
        &self.config
    }
}

fn to_ldk_network(network: bitcoin::Network) -> ldk_node::bitcoin::Network {
    match network {
        bitcoin::Network::Bitcoin => ldk_node::bitcoin::Network::Bitcoin,
        bitcoin::Network::Testnet => ldk_node::bitcoin::Network::Testnet,
        bitcoin::Network::Signet => ldk_node::bitcoin::Network::Signet,
        bitcoin::Network::Regtest => ldk_node::bitcoin::Network::Regtest,
        _ => ldk_node::bitcoin::Network::Regtest,
    }
}

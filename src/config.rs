use bdk_wallet::bitcoin::Network;
use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AddressType {
    /// Pay to pubkey hash.
    P2pkh,
    /// Pay to script hash.
    P2sh,
    /// Pay to witness pubkey hash.
    P2wpkh,
    /// Pay to witness script hash.
    P2wsh,
    /// Pay to taproot.
    P2tr,
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NgAccountConfig {
    pub name: String,
    pub color: String,
    pub device_serial: Option<String>,
    pub date_added: Option<String>,
    pub address_type: AddressType,
    pub index: u32,
    pub internal_descriptor: String,
    pub external_descriptor: Option<String>,
    pub date_synced: Option<String>,
    pub network: Network,
    pub id: String,
}

impl NgAccountConfig {
    pub fn new(
        name: String,
        color: String,
        device_serial: Option<String>,
        date_added: Option<String>,
        index: u32,
        internal_descriptor: String,
        external_descriptor: Option<String>,
        address_type: AddressType,
        network: Network,
        id: String,
        date_synced: Option<String>,
    ) -> Self {
        Self {
            name,
            color,
            device_serial,
            date_added,
            index,
            internal_descriptor,
            external_descriptor,
            address_type,
            network,
            id,
            date_synced,
        }
    }
    pub fn serialize(&self) -> String {
        serde_json::to_string_pretty(self).unwrap()
    }

    pub fn deserialize(data: &str) -> Self {
        serde_json::from_str(data).unwrap()
    }
}
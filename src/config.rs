use bdk_electrum::bdk_core::bitcoin::Network;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug,Clone)]
pub struct NgAccountConfig {
    pub name: String,
    pub color: String,
    pub device_serial: Option<String>,
    pub date_added: Option<String>,
    pub address_type: String,
    pub index: u32,
    pub internal_descriptor: String,
    pub external_descriptor: Option<String>,
    pub network: String,
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
        address_type: String,
        network: String,
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
        }
    }
    pub fn serialize(&self) -> String {
        serde_json::to_string_pretty(self).unwrap()
    }

    pub fn deserialize(data: &str) -> Self {
        serde_json::from_str(data).unwrap()
    }
}
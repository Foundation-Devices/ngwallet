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

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum ExportMode {
    Qr,
    Ur2,
    File,
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum ExportTarget {
    Envoy,
    BitcoinCore,
    BitcoinKeeper,
    BlueWallet,
    BTCPay,
    Casa,
    Coinbits,
    Electrum,
    FullyNoded,
    Nunchuk,
    SimpleBitcoinWallet,
    Sparrow,
    Specter,
    Theya,
    Zeus,
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
    pub wallet_path: Option<String>,
    pub network: Network,
    pub id: String,
}

impl NgAccountConfig {
    pub fn serialize(&self) -> String {
        serde_json::to_string_pretty(self).unwrap()
    }

    pub fn deserialize(data: &str) -> Self {
        serde_json::from_str(data).unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NgMultisigCosigner {
    pub xfp: String,
    pub wallet_path: String,
    pub descriptor: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NgMultisigConfig {
    pub name: String,
    pub color: String,
    pub device_serial: Option<String>,
    pub date_added: Option<String>,
    pub address_type: AddressType,
    pub derivation: String,
    pub threshold_m: u32,
    pub cosigners: Vec<NgMultisigCosigner>,
    pub network: Network,
    pub id: String,
}

impl NgMultisigConfig {
    pub fn serialize(&self) -> String {
        serde_json::to_string_pretty(self).unwrap()
    }

    pub fn deserialize(data: &str) -> Self {
        serde_json::from_str(data).unwrap()
    }
}

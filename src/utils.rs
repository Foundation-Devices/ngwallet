use bdk_wallet::bitcoin::{Address, Network, ScriptBuf};
#[cfg(feature = "envoy")]
use {
    bdk_electrum::BdkElectrumClient,
    bdk_electrum::electrum_client::{Client, Config, Socks5Config},
};

use crate::config::AddressType;
use serde::Serialize;

#[derive(Serialize)]
struct Bip329Item {
    #[serde(rename = "type")]
    item_type: String,

    #[serde(rename = "ref")]
    reference: String,

    #[serde(skip_serializing_if = "String::is_empty")]
    label: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    spendable: Option<bool>,
}

#[cfg(feature = "envoy")]
pub(crate) fn build_electrum_client(
    electrum_server: &str,
    socks_proxy: Option<&str>,
) -> BdkElectrumClient<Client> {
    let socks5_config = match socks_proxy {
        Some(socks_proxy) => {
            let socks5_config = Socks5Config::new(socks_proxy);
            Some(socks5_config)
        }
        None => None,
    };
    let electrum_config = Config::builder()
        .timeout(Some(30))
        .retry(3)
        .socks5(socks5_config.clone())
        .build();
    let client = Client::from_config(electrum_server, electrum_config).unwrap();
    let bdk_client: BdkElectrumClient<Client> = BdkElectrumClient::new(client);
    bdk_client
}

//
pub fn get_address_type(descriptor: &str) -> AddressType {
    if descriptor.starts_with("pkh(") {
        AddressType::P2pkh
    } else if descriptor.starts_with("wpkh(") {
        AddressType::P2wpkh
    } else if descriptor.starts_with("sh(wsh(") {
        AddressType::P2ShWsh
    } else if descriptor.starts_with("sh(wpkh(") {
        AddressType::P2ShWpkh
    } else if descriptor.starts_with("sh(") {
        AddressType::P2sh
    } else if descriptor.starts_with("tr(") {
        AddressType::P2tr
    } else if descriptor.starts_with("wsh(") {
        AddressType::P2wsh
    } else {
        AddressType::P2pkh
    }
}

pub fn get_address_as_string(script: &ScriptBuf, network: Network) -> String {
    match Address::from_script(script, network) {
        Ok(address) => address.to_string(),
        Err(_) => {
            if script.is_op_return() {
                "OP_RETURN".to_string()
            } else {
                "Unknown script".to_string()
            } // Handle the error as needed
        }
    }
}

pub fn extract_xpub_from_descriptor(descriptor: &str) -> String {
    descriptor
        .split(']')
        .nth(1)
        .and_then(|s| s.split('/').next())
        .unwrap_or("")
        .to_string()
}

pub fn extract_descriptor_origin(desc: &str) -> String {
    desc.find(']')
        .map(|idx| &desc[..=idx])
        .map(|s| format!("{s})"))
        .unwrap_or_default()
}

pub fn build_key_json(
    item_type: &str,
    reference: &str,
    label: Option<&str>,
    origin: Option<&str>,
    spendable: Option<bool>,
) -> String {
    let item = Bip329Item {
        item_type: item_type.to_string(),
        reference: reference.to_string(),
        label: label.unwrap_or("").to_string(),
        origin: origin.map(str::to_string),
        spendable,
    };

    serde_json::to_string(&item).unwrap()
}

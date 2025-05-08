// Created by: 0xB1ue
#[cfg(feature = "envoy")]
use {
    bdk_electrum::BdkElectrumClient,
    bdk_electrum::electrum_client::{Client, Config, Socks5Config},
};

use crate::config::AddressType;

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
    let electrum_config = Config::builder().socks5(socks5_config.clone()).build();
    let client = Client::from_config(electrum_server, electrum_config).unwrap();
    let bdk_client: BdkElectrumClient<Client> = BdkElectrumClient::new(client);
    bdk_client
}

//use with bdk_wallet::descriptor::ExtendedDescriptor
// for valid descriptors
pub(crate) fn get_address_type(descriptor: &str) -> AddressType {
    if descriptor.starts_with("pkh(") {
        AddressType::P2pkh
    } else if descriptor.starts_with("wpkh(") {
        AddressType::P2wpkh
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

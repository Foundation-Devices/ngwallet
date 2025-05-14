use crate::account::{Descriptor, NgAccount};
use crate::utils::get_address_type;
use bdk_wallet::WalletPersister;
use bdk_wallet::bitcoin::Network;
use redb::StorageBackend;
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

    P2ShWpkh,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NgDescriptor {
    pub internal: String,
    pub external: Option<String>,
    pub address_type: AddressType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NgAccountConfig {
    pub name: String,
    pub color: String,
    pub seed_has_passphrase: bool,
    pub device_serial: Option<String>,
    pub date_added: Option<String>,
    pub preferred_address_type: AddressType,
    pub index: u32,
    pub descriptors: Vec<NgDescriptor>,
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

impl<P: WalletPersister> Default for NgAccountBuilder<P> {
    fn default() -> Self {
        Self {
            name: None,
            color: None,
            device_serial: None,
            date_added: None,
            network: None,
            preferred_address_type: None,
            descriptors: None,
            index: None,
            db_path: None,
            id: None,
            date_synced: None,
            seed_has_passphrase: None,
            open_in_memory: None,
        }
    }
}

pub struct NgAccountBuilder<P: WalletPersister> {
    name: Option<String>,
    color: Option<String>,
    device_serial: Option<String>,
    date_added: Option<String>,
    network: Option<Network>,
    preferred_address_type: Option<AddressType>,
    descriptors: Option<Vec<Descriptor<P>>>,
    index: Option<u32>,
    db_path: Option<String>,
    id: Option<String>,
    date_synced: Option<String>,
    seed_has_passphrase: Option<bool>,
    open_in_memory: Option<bool>,
}

impl<P: WalletPersister> NgAccountBuilder<P> {
    pub fn name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn color(mut self, color: String) -> Self {
        self.color = Some(color);
        self
    }

    pub fn device_serial(mut self, device_serial: Option<String>) -> Self {
        self.device_serial = device_serial;
        self
    }

    pub fn date_added(mut self, date_added: Option<String>) -> Self {
        self.date_added = date_added;
        self
    }

    pub fn network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    pub fn preferred_address_type(mut self, address_type: AddressType) -> Self {
        self.preferred_address_type = Some(address_type);
        self
    }

    pub fn descriptors(mut self, descriptors: Vec<Descriptor<P>>) -> Self {
        self.descriptors = Some(descriptors);
        self
    }

    pub fn index(mut self, index: u32) -> Self {
        self.index = Some(index);
        self
    }

    pub fn db_path(mut self, db_path: Option<String>) -> Self {
        self.db_path = db_path;
        self
    }

    pub fn id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }

    pub fn date_synced(mut self, date_synced: Option<String>) -> Self {
        self.date_synced = date_synced;
        self
    }

    pub fn seed_has_passphrase(mut self, seed_has_passphrase: bool) -> Self {
        self.seed_has_passphrase = Some(seed_has_passphrase);
        self
    }

    pub fn open_in_memory(mut self) -> Self {
        self.open_in_memory = Some(true);
        self
    }

    pub fn build(self, meta_storage_backend: Option<impl StorageBackend>) -> NgAccount<P> {
        let descriptors = self.descriptors.expect("Descriptors are required");

        let ng_descriptors = descriptors
            .iter()
            .map(|d| NgDescriptor {
                external: d.external.clone(),
                internal: d.internal.clone(),
                address_type: get_address_type(&d.internal),
            })
            .collect();

        let ng_account_config = NgAccountConfig {
            name: self.name.expect("Name is required"),
            color: self.color.expect("Color is required"),
            device_serial: self.device_serial,
            date_added: self.date_added,
            network: self.network.expect("Network is required"),
            preferred_address_type: self
                .preferred_address_type
                .expect("Preferred address type is required"),
            descriptors: ng_descriptors,
            index: self.index.expect("Index is required"),
            wallet_path: self.db_path,
            id: self.id.expect("id is required"),
            date_synced: self.date_synced,
            seed_has_passphrase: self.seed_has_passphrase.unwrap_or(false),
        };

        NgAccount::new_from_descriptors(
            ng_account_config,
            meta_storage_backend,
            self.open_in_memory.unwrap_or(false),
            descriptors,
        )
    }
}

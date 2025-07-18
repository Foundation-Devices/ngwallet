use anyhow::bail;
use std::collections::HashMap;
use std::sync::Arc;
use std::str::FromStr;

use crate::account::{Descriptor, NgAccount, RemoteUpdate};
use crate::db::RedbMetaStorage;
use crate::store::MetaStorage;
use crate::utils::get_address_type;
use bdk_wallet::KeychainKind;
use bdk_wallet::WalletPersister;
use bdk_wallet::bitcoin::{self, Network};
use bdk_wallet::bitcoin::bip32::{self, DerivationPath, Fingerprint, Xpub};
use redb::StorageBackend;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct MultiSigSigner {
    derivation: String,
    fingerprint: String,
    pubkey: String,
}

impl MultiSigSigner {
    pub fn new_from_strings(derivation: &str, fingerprint: &str, pubkey: &str) -> Result<Self, bip32::Error> {
        let d = DerivationPath::from_str(derivation)?;
        let f = Fingerprint::from_str(fingerprint).map_err(|e| bip32::Error::Hex(e))?;
        let p = Xpub::from_str(pubkey)?;
        Ok(Self::new(&d, &f, &p))
    }

    pub fn new(derivation: &DerivationPath, fingerprint: &Fingerprint, pubkey: &Xpub) -> Self {
        Self {
            derivation: derivation.to_string(),
            fingerprint: fingerprint.to_string().to_uppercase(),
            pubkey: pubkey.to_string(),
        }
    }

    pub fn get_derivation(&self) -> Result<DerivationPath, bip32::Error> {
        DerivationPath::from_str(&self.derivation)
    }

    pub fn get_fingerprint(&self) -> Result<Fingerprint, bip32::Error> {
        Fingerprint::from_str(&self.fingerprint).map_err(|e| bip32::Error::Hex(e))
    }

    pub fn get_pubkey(&self) -> Result<Xpub, bip32::Error> {
        Xpub::from_str(&self.pubkey)
    }

    pub fn get_derivation_str(&self) -> &str { &self.derivation }
    pub fn get_fingerprint_str(&self) -> &str { &self.fingerprint }
    pub fn get_pubkey_str(&self) -> &str { &self.pubkey }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct MultiSigDetails {
    pub policy_threshold: u32,  // aka M
    pub policy_total_keys: u32, // aka N
    pub address_type: AddressType,
    pub signers: Vec<MultiSigSigner>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
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

impl TryFrom<bitcoin::AddressType> for AddressType {
    type Error = anyhow::Error;

    fn try_from(item: bitcoin::AddressType) -> Result<Self, Self::Error> {
        let t = match item {
            bitcoin::AddressType::P2pkh => AddressType::P2pkh,
            bitcoin::AddressType::P2sh => AddressType::P2sh,
            bitcoin::AddressType::P2wpkh => AddressType::P2wpkh,
            bitcoin::AddressType::P2wsh => AddressType::P2wsh,
            bitcoin::AddressType::P2tr => AddressType::P2tr,
            other => anyhow::bail!("Unknown bitcoin::AddressType: {}", other),
        };
        Ok(t)
    }
}

impl From<AddressType> for bitcoin::AddressType {
   fn from(item: AddressType) -> Self {
        match item {
            AddressType::P2pkh => bitcoin::AddressType::P2pkh,
            AddressType::P2sh  => bitcoin::AddressType::P2sh,
            AddressType::P2wpkh => bitcoin::AddressType::P2wpkh,
            AddressType::P2wsh => bitcoin::AddressType::P2wsh,
            AddressType::P2tr => bitcoin::AddressType::P2tr,
            AddressType::P2ShWpkh => bitcoin::AddressType::P2sh,
        }
    }
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
    pub account_path: Option<String>,
    pub network: Network,
    pub id: String,
    pub multisig: Option<MultiSigDetails>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NgAccountBackup {
    pub ng_account_config: NgAccountConfig,
    pub last_used_index: Vec<(AddressType, KeychainKind, u32)>,
    pub notes: HashMap<String, String>,
    pub tags: HashMap<String, String>,
    pub do_not_spend: HashMap<String, bool>,
}

impl NgAccountConfig {
    pub fn serialize(&self) -> String {
        serde_json::to_string_pretty(self).unwrap()
    }

    pub fn deserialize(data: &str) -> Self {
        serde_json::from_str(data).unwrap()
    }

    pub fn from_remote(remote_update: Vec<u8>) -> anyhow::Result<NgAccountConfig> {
        let update: RemoteUpdate = minicbor_serde::from_slice(&remote_update)?;
        match update.metadata {
            None => {
                bail!("expected metadata")
            }
            Some(update) => Ok(update),
        }
    }
}

impl NgAccountBackup {
    pub fn serialize(&self) -> String {
        serde_json::to_string_pretty(self).unwrap()
    }

    pub fn deserialize(data: &str) -> serde_json::Result<NgAccountBackup> {
        serde_json::from_str(data)
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
            account_path: None,
            id: None,
            date_synced: None,
            seed_has_passphrase: None,
            multisig: None,
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
    account_path: Option<String>,
    id: Option<String>,
    date_synced: Option<String>,
    seed_has_passphrase: Option<bool>,
    multisig: Option<MultiSigDetails>,
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

    pub fn account_path(mut self, db_path: Option<String>) -> Self {
        self.account_path = db_path;
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

    pub fn build_in_memory(self) -> anyhow::Result<NgAccount<P>> {
        let meta_storage = crate::store::InMemoryMetaStorage::default();
        self.build_inner(meta_storage)
    }

    pub fn build_from_file(self, db_path: Option<String>) -> anyhow::Result<NgAccount<P>> {
        let meta_storage = RedbMetaStorage::from_file(db_path)?;
        self.build_inner(meta_storage)
    }

    pub fn build_from_backend(self, backend: impl StorageBackend) -> anyhow::Result<NgAccount<P>> {
        let meta_storage = RedbMetaStorage::from_backend(backend)?;
        self.build_inner(meta_storage)
    }

    fn build_inner(self, meta_storage: impl MetaStorage + 'static) -> anyhow::Result<NgAccount<P>> {
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
            index: if self.multisig.is_none() { self.index.expect("Index is required") } else { 0 },
            id: self.id.expect("id is required"),
            date_synced: self.date_synced,
            seed_has_passphrase: self.seed_has_passphrase.unwrap_or(false),
            account_path: self.account_path,
            multisig: self.multisig,
        };

        NgAccount::new_from_descriptors(ng_account_config, Arc::new(meta_storage), descriptors)
    }
}

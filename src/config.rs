use anyhow::{self, Context, bail};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use crate::account::{Descriptor, NgAccount, RemoteUpdate};
use crate::db::RedbMetaStorage;
use crate::store::MetaStorage;
use crate::utils::get_address_type;
use bdk_wallet::KeychainKind;
use bdk_wallet::WalletPersister;
use bdk_wallet::bitcoin::bip32::{self, DerivationPath, Fingerprint, Xpub};
use bdk_wallet::bitcoin::{self, Network};
use redb::StorageBackend;
use regex::Regex;
use serde::{Deserialize, Serialize};

pub const MULTI_SIG_SIGNER_LIMIT: u32 = 20;

#[derive(
    Debug,
    Serialize,
    Deserialize,
    Clone,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct MultiSigSigner {
    derivation: String,
    fingerprint: String,
    pubkey: String,
}

impl MultiSigSigner {
    pub fn new_from_strings(
        derivation: &str,
        fingerprint: &str,
        pubkey: &str,
    ) -> Result<Self, bip32::Error> {
        let d = DerivationPath::from_str(derivation)?;
        let f = Fingerprint::from_str(fingerprint).map_err(bip32::Error::Hex)?;
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
        Fingerprint::from_str(&self.fingerprint).map_err(bip32::Error::Hex)
    }

    pub fn get_pubkey(&self) -> Result<Xpub, bip32::Error> {
        Xpub::from_str(&self.pubkey)
    }

    pub fn get_derivation_str(&self) -> &str {
        &self.derivation
    }
    pub fn get_fingerprint_str(&self) -> &str {
        &self.fingerprint
    }
    pub fn get_pubkey_str(&self) -> &str {
        &self.pubkey
    }
}

#[derive(
    Debug,
    Serialize,
    Deserialize,
    Clone,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct MultiSigDetails {
    pub policy_threshold: u32,  // aka M
    pub policy_total_keys: u32, // aka N
    pub format: AddressType,
    pub signers: Vec<MultiSigSigner>,
}

impl MultiSigDetails {
    // TODO: replace anyhows with thiserrors
    // TODO: infer and return network type, create network enum compatible with rkyv serialization
    pub fn from_config(config: &str) -> Result<(Self, Option<String>), anyhow::Error> {
        let mut name: Option<String> = None;
        let mut policy_threshold: Option<u32> = None;
        let mut policy_total_keys: Option<u32> = None;
        let mut derivation: Option<DerivationPath> = None;
        let mut format: Option<AddressType> = None;
        let mut signers: Vec<MultiSigSigner> = Vec::new();
        let pattern = Regex::new(r"(\d+)\D*(\d+)")?;

        for (i, line) in config.lines().enumerate() {
            let s = String::from(line);
            let line = s.trim();

            let (key, mut value) = match line.split_once(":") {
                Some((k, v)) => {
                    let k = String::from(k);
                    let k = k.trim();
                    let v = String::from(v);
                    let v = v.trim();
                    (k.to_lowercase(), v.to_owned())
                }
                // TODO: Core allows xpubs without fingerprints and defaults to 00000000 fingerprint,
                // but a comment calls it a "pointless optimization"
                None => continue,
            };

            // Remove commented lines
            if let Some(comment_index) = key.find('#') {
                match comment_index {
                    0 => continue, // TODO: should we uncomment derivation paths here?
                    _ => anyhow::bail!(
                        "Multisig config line {} is malformed, should only include comments after values",
                        i + 1
                    ),
                }
            }

            // Allow names to include '#'
            if key == *"name" {
                name = Some(value);
                continue;
            }

            // Remove comments after values
            if let Some((v, _comment)) = value.split_once('#') {
                if v.is_empty() {
                    anyhow::bail!(
                        "Multisig config line {} is malformed, should not comment out values",
                        i + 1
                    );
                }
                value = String::from(v).trim().to_owned()
            }

            match key.as_str() {
                "policy" => {
                    let captures = pattern
                        .captures(&value)
                        .ok_or(anyhow::anyhow!("Invalid policy format"))?;
                    if captures.len() != 3 {
                        anyhow::bail!("Invalid policy format, incorrect regex capture");
                    }
                    policy_threshold = Some(captures[1].parse::<u32>()?);
                    policy_total_keys = Some(captures[2].parse::<u32>()?);
                }
                // This handles global and signer-specific derivations by just assigning the
                // latest parsed derivation to the next signer.
                "derivation" => derivation = Some(DerivationPath::from_str(&value)?),
                "format" => format = Some(AddressType::try_from(value)?),
                other => {
                    let fingerprint = Fingerprint::from_str(other).with_context(
                        || "Unnamed keys in a multisig format should be valid fingerprints",
                    )?;
                    let pubkey = Xpub::from_str(&value)?;
                    match derivation {
                        Some(ref d) => signers.push(MultiSigSigner::new(d, &fingerprint, &pubkey)),
                        None => anyhow::bail!(
                            "Multisig config does not include a derivation path for at least one signer"
                        ),
                    }
                }
            }
        }

        let res = Self {
            policy_threshold: policy_threshold.ok_or(anyhow::anyhow!(
                "Multisig config is missing policy threshold"
            ))?,
            policy_total_keys: policy_total_keys.ok_or(anyhow::anyhow!(
                "Multisig config is missing policy total keys"
            ))?,
            format: format.ok_or(anyhow::anyhow!("Multisig config is missing address format"))?,
            signers: signers.clone(),
        };

        if signers.len() != res.policy_total_keys as usize {
            anyhow::bail!(
                "Multisig config number of signers should specify the total keys (M) specified"
            );
        }

        if res.policy_total_keys >= MULTI_SIG_SIGNER_LIMIT {
            anyhow::bail!(
                "Multisig config has {} signers, limit is {}",
                signers.len(),
                MULTI_SIG_SIGNER_LIMIT
            );
        }

        if signers.len() < 2 {
            anyhow::bail!("Multisig configs require at least 2 signers");
        }

        if res.policy_threshold < 2 {
            anyhow::bail!("Multisig configs should have a threshold of at least 2");
        }

        Ok((res, name))
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
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
    /// Bip 49 script.
    P2ShWpkh,
    /// Bip48/1 script.
    P2ShWsh,
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

impl TryFrom<String> for AddressType {
    type Error = anyhow::Error;

    fn try_from(item: String) -> Result<Self, Self::Error> {
        let cleaned = item.to_lowercase().replace("_", "-");
        let t = match cleaned.as_str() {
            "p2pkh" | "pkh" => AddressType::P2pkh,
            "p2sh" | "sh" => AddressType::P2sh,
            "p2wpkh" | "wpkh" => AddressType::P2wpkh,
            "p2wsh" | "wsh" => AddressType::P2wsh,
            "p2tr" | "tr" => AddressType::P2tr,
            "p2sh-p2wpkh" | "sh-wpkh" | "p2wpkh-p2sh" | "wpkh-sh" => AddressType::P2ShWpkh,
            "p2sh-p2wsh" | "sh-wsh" | "p2wsh-p2sh" | "wsh-sh" => AddressType::P2ShWsh,
            other => anyhow::bail!("Unknown address type string: {}", other),
        };
        Ok(t)
    }
}

impl From<AddressType> for bitcoin::AddressType {
    fn from(item: AddressType) -> Self {
        match item {
            AddressType::P2pkh => bitcoin::AddressType::P2pkh,
            AddressType::P2sh => bitcoin::AddressType::P2sh,
            AddressType::P2wpkh => bitcoin::AddressType::P2wpkh,
            AddressType::P2wsh => bitcoin::AddressType::P2wsh,
            AddressType::P2tr => bitcoin::AddressType::P2tr,
            AddressType::P2ShWpkh => bitcoin::AddressType::P2sh,
            AddressType::P2ShWsh => bitcoin::AddressType::P2sh,
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
    pub multisig: Option<MultiSigDetails>,
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
            index: if self.multisig.is_none() {
                self.index.expect("Index is required")
            } else {
                0
            },
            id: self.id.expect("id is required"),
            date_synced: self.date_synced,
            seed_has_passphrase: self.seed_has_passphrase.unwrap_or(false),
            account_path: self.account_path,
            multisig: self.multisig,
        };

        NgAccount::new_from_descriptors(ng_account_config, Arc::new(meta_storage), descriptors)
    }
}

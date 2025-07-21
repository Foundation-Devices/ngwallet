use anyhow::{self, Context, bail};
use std::cmp::Ordering;
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
pub const ACCEPTED_FORMATS: &[AddressType] =
    &[AddressType::P2sh, AddressType::P2wsh, AddressType::P2ShWsh];

#[derive(
    Debug,
    Serialize,
    Deserialize,
    Clone,
    PartialEq,
    Eq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct MultiSigSigner {
    derivation: String,
    fingerprint: String,
    pubkey: String,
}

impl PartialOrd for MultiSigSigner {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.pubkey.cmp(&other.pubkey))
    }
}

impl Ord for MultiSigSigner {
    fn cmp(&self, other: &Self) -> Ordering {
        self.pubkey.cmp(&other.pubkey)
    }
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
        // This string can be parsed back into a DerivationPath,
        // and is nicer for config file formatting
        let mut deriv_str = derivation.to_string();
        deriv_str.insert_str(0, "m/");

        Self {
            derivation: deriv_str,
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
    Debug, Serialize, Deserialize, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct MultiSigDetails {
    pub policy_threshold: u32,  // aka M
    pub policy_total_keys: u32, // aka N
    pub format: AddressType,
    pub network_kind: NetworkKind,
    // Signers are sorted on creation
    signers: Vec<MultiSigSigner>,
}

impl PartialEq for MultiSigDetails {
    fn eq(&self, other: &Self) -> bool {
        let mut self_signers = self.signers.clone();
        let mut other_signers = other.signers.clone();
        self_signers.sort();
        other_signers.sort();

        self.policy_threshold == other.policy_threshold
            && self.policy_total_keys == other.policy_total_keys
            && self.format == other.format
            && self.network_kind == other.network_kind
            && self_signers == other_signers
    }
}

impl MultiSigDetails {
    pub fn new(
        policy_threshold: u32,
        policy_total_keys: u32,
        format: AddressType,
        network_kind: NetworkKind,
        mut signers: Vec<MultiSigSigner>,
    ) -> Result<Self, anyhow::Error> {
        // Sort by xpubs
        signers.sort();

        if signers.len() != policy_total_keys as usize {
            anyhow::bail!("Multisig number of signers should match the total keys (M) specified");
        }

        if policy_total_keys >= MULTI_SIG_SIGNER_LIMIT {
            anyhow::bail!(
                "Multisig has {} signers, limit is {}",
                signers.len(),
                MULTI_SIG_SIGNER_LIMIT
            );
        }

        if signers.len() < 2 {
            anyhow::bail!("Multisigs require at least 2 total signers (N)");
        }

        if policy_threshold < 2 {
            anyhow::bail!("Multisigs should have a threshold (M) of at least 2");
        }

        if policy_threshold > policy_total_keys {
            anyhow::bail!(
                "Multisigs should have a threshold (M) less than or equal too the total keys (N)"
            );
        }

        for signer in &signers {
            let signer_network: NetworkKind = signer.get_pubkey()?.network.into();
            if signer_network != network_kind {
                anyhow::bail!(
                    "Multisig signer with fingerprint {} has a mismatched network type: {:?}",
                    signer.fingerprint,
                    signer_network,
                );
            }
        }

        if !ACCEPTED_FORMATS.contains(&format) {
            anyhow::bail!(
                "Multisig has address format {:?}, while only {:?} are currently accepted",
                format,
                ACCEPTED_FORMATS
            );
        }

        Ok(Self {
            policy_threshold,
            policy_total_keys,
            format,
            network_kind,
            signers,
        })
    }

    pub fn get_signers(&self) -> &Vec<MultiSigSigner> {
        &self.signers
    }

    // TODO: replace anyhows with thiserrors
    // TODO: infer and return network type, create network enum compatible with rkyv serialization
    pub fn from_config(config: &str) -> Result<(Self, Option<String>), anyhow::Error> {
        let mut name: Option<String> = None;
        let mut policy_threshold: Option<u32> = None;
        let mut policy_total_keys: Option<u32> = None;
        let mut derivation: Option<DerivationPath> = None;
        let mut format: Option<AddressType> = None;
        let mut network_kind: Option<NetworkKind> = None;
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
                    // Ensure that strings parse correctly to a fingerprint and pubkey
                    let fingerprint = Fingerprint::from_str(other).with_context(
                        || "Unnamed keys in a multisig format should be valid fingerprints",
                    )?;
                    let pubkey = Xpub::from_str(&value)?;

                    // Ensure that all pubkeys indicate the same network kind
                    let n = network_kind.get_or_insert(pubkey.network.into());
                    if *n != pubkey.network.into() {
                        anyhow::bail!("Multisig config has pubkeys from different networks");
                    }

                    match derivation {
                        Some(ref d) => {
                            let signer = MultiSigSigner::new(d, &fingerprint, &pubkey);
                            if signers.contains(&signer) {
                                anyhow::bail!("Multisig config contains duplicate signers");
                            }
                            signers.push(signer);
                        }
                        None => anyhow::bail!(
                            "Multisig config does not include a derivation path for at least one signer"
                        ),
                    }
                }
            }
        }

        let res = Self::new(
            policy_threshold.ok_or(anyhow::anyhow!(
                "Multisig config is missing policy threshold"
            ))?,
            policy_total_keys.ok_or(anyhow::anyhow!(
                "Multisig config is missing policy total keys"
            ))?,
            format.ok_or(anyhow::anyhow!("Multisig config is missing address format"))?,
            network_kind.ok_or(anyhow::anyhow!(
                "Multisig config does not indicate a network kind"
            ))?,
            signers.clone(),
        )?;

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
pub enum NetworkKind {
    Main,
    Test,
}

impl From<bitcoin::NetworkKind> for NetworkKind {
    fn from(item: bitcoin::NetworkKind) -> NetworkKind {
        match item {
            bitcoin::NetworkKind::Main => NetworkKind::Main,
            bitcoin::NetworkKind::Test => NetworkKind::Test,
        }
    }
}

impl From<NetworkKind> for bitcoin::NetworkKind {
    fn from(item: NetworkKind) -> bitcoin::NetworkKind {
        match item {
            NetworkKind::Main => bitcoin::NetworkKind::Main,
            NetworkKind::Test => bitcoin::NetworkKind::Test,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multisig_from_config_1() {
        let config = String::from("# Passport Multisig setup file (created by Sparrow)
#
Name: Multisig 2-of-2 Test
Policy: 2 of 2
Derivation: m/48'/1'/0'/2'
Format: P2WSH

AB88DE89: tpubDFUc8ddWCzA8kC195Zn6UitBcBGXbPbtjktU2dk2Deprnf6sR15GAyHLQKUjAPa3gqD74g7Eea3NSqkb9FfYRZzEm2MTbCtTDZAKSHezJwb
662A42E4: tpubDFGqX4Ge633XixPNo4uF5h6sPkv32bwJrknDmmPGMq8Tn3Pu9QgWfk5hUiDe7gvv2eaFeaHXgjiZwKvnP3AhusoaWBK3qTv8cznyHxxGoSF");
        let (multisig, name) = MultiSigDetails::from_config(&config).unwrap();
        let expected = MultiSigDetails {
            policy_threshold: 2,
            policy_total_keys: 2,
            format: AddressType::P2wsh,
            network_kind: NetworkKind::Test,
            signers: vec![
                MultiSigSigner {
                    derivation: String::from("m/48'/1'/0'/2'"),
                    fingerprint: String::from("AB88DE89"),
                    pubkey: String::from(
                        "tpubDFUc8ddWCzA8kC195Zn6UitBcBGXbPbtjktU2dk2Deprnf6sR15GAyHLQKUjAPa3gqD74g7Eea3NSqkb9FfYRZzEm2MTbCtTDZAKSHezJwb",
                    ),
                },
                MultiSigSigner {
                    derivation: String::from("m/48'/1'/0'/2'"),
                    fingerprint: String::from("662A42E4"),
                    pubkey: String::from(
                        "tpubDFGqX4Ge633XixPNo4uF5h6sPkv32bwJrknDmmPGMq8Tn3Pu9QgWfk5hUiDe7gvv2eaFeaHXgjiZwKvnP3AhusoaWBK3qTv8cznyHxxGoSF",
                    ),
                },
            ],
        };
        assert_eq!(expected, multisig);
        assert_eq!(Some(String::from("Multisig 2-of-2 Test")), name);
    }

    #[test]
    fn multisig_from_config_2() {
        let config = String::from("Name: Multisig 2-of-2 Test
Policy: 2 of 2
Format: P2WSH

Derivation: m/48'/1'/0'/2'
AB88DE89: tpubDFUc8ddWCzA8kC195Zn6UitBcBGXbPbtjktU2dk2Deprnf6sR15GAyHLQKUjAPa3gqD74g7Eea3NSqkb9FfYRZzEm2MTbCtTDZAKSHezJwb

Derivation: m/48'/1'/0'/2'
662A42E4: tpubDFGqX4Ge633XixPNo4uF5h6sPkv32bwJrknDmmPGMq8Tn3Pu9QgWfk5hUiDe7gvv2eaFeaHXgjiZwKvnP3AhusoaWBK3qTv8cznyHxxGoSF");
        let (multisig, name) = MultiSigDetails::from_config(&config).unwrap();
        let expected = MultiSigDetails {
            policy_threshold: 2,
            policy_total_keys: 2,
            format: AddressType::P2wsh,
            network_kind: NetworkKind::Test,
            signers: vec![
                MultiSigSigner {
                    derivation: String::from("m/48'/1'/0'/2'"),
                    fingerprint: String::from("662A42E4"),
                    pubkey: String::from(
                        "tpubDFGqX4Ge633XixPNo4uF5h6sPkv32bwJrknDmmPGMq8Tn3Pu9QgWfk5hUiDe7gvv2eaFeaHXgjiZwKvnP3AhusoaWBK3qTv8cznyHxxGoSF",
                    ),
                },
                MultiSigSigner {
                    derivation: String::from("m/48'/1'/0'/2'"),
                    fingerprint: String::from("AB88DE89"),
                    pubkey: String::from(
                        "tpubDFUc8ddWCzA8kC195Zn6UitBcBGXbPbtjktU2dk2Deprnf6sR15GAyHLQKUjAPa3gqD74g7Eea3NSqkb9FfYRZzEm2MTbCtTDZAKSHezJwb",
                    ),
                },
            ],
        };
        assert_eq!(expected, multisig);
        assert_eq!(Some(String::from("Multisig 2-of-2 Test")), name);
    }
}

use anyhow::{self, Context, bail};
use bdk_core::bitcoin::hex::DisplayHex;
#[cfg(feature = "sha2")]
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use crate::account::{Descriptor, NgAccount, RemoteUpdate};
use crate::bip39::{Descriptors, MasterKey};
use crate::db::RedbMetaStorage;
use crate::store::MetaStorage;
use crate::utils::get_address_type;
use bdk_wallet::KeychainKind;
use bdk_wallet::WalletPersister;
use bdk_wallet::bitcoin::bip32::{
    self, ChainCode, ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub,
};
use bdk_wallet::bitcoin::secp256k1::{PublicKey, Secp256k1, Signing};
use bdk_wallet::bitcoin::{self, Network, NetworkKind as BtcNetworkKind};
use foundation_urtypes::registry::{
    ChildNumber as UrChildNumber, HDKeyRef, Key as UrKey, Terminal,
};
use bdk_wallet::descriptor::Descriptor as BdkDescriptor;
use bdk_wallet::miniscript::{
    ForEachKey,
    descriptor::{
        DescriptorPublicKey, DescriptorSecretKey, DescriptorXKey, ShInner, SortedMultiVec,
        Wildcard, WshInner,
    },
};
use regex::Regex;
use serde::{Deserialize, Serialize};

pub const MULTI_SIG_SIGNER_LIMIT: usize = 20;
pub const ACCEPTED_FORMATS: &[AddressType] = &[AddressType::P2wsh, AddressType::P2ShWsh];

/// Rewrites a SLIP-132 prefixed multisig extended public key to its canonical
/// `xpub`/`tpub` form so that `bip32::Xpub::from_str` will accept it.
///
/// Handles exactly the four multisig SLIP-132 encodings:
///   * `Ypub` (mainnet P2SH-P2WSH)
///   * `Zpub` (mainnet P2WSH)
///   * `Upub` (testnet P2SH-P2WSH)
///   * `Vpub` (testnet P2WSH)
///
/// The lowercase singlesig encodings (`ypub`/`zpub`/`upub`/`vpub`) are NOT
/// normalized here — they belong to single-sig wallet formats and would never
/// appear in a valid multisig config. Returning them unchanged causes
/// `from_config` to reject them downstream, which is the correct behavior.
/// Plain `xpub`/`tpub` and unparseable strings also pass through unchanged.
//
// BlueWallet emits `Zpub` whenever the multisig Format is P2WSH, which caused
// `from_config` to fail on otherwise-valid imports — see SFT-6907.
fn normalize_slip132(key: &str) -> String {
    const XPUB: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
    const TPUB: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];
    const MAPPINGS: &[([u8; 4], [u8; 4])] = &[
        ([0x02, 0x95, 0xB4, 0x3F], XPUB), // Ypub (mainnet P2SH-P2WSH)
        ([0x02, 0xAA, 0x7E, 0xD3], XPUB), // Zpub (mainnet P2WSH)
        ([0x02, 0x42, 0x89, 0xEF], TPUB), // Upub (testnet P2SH-P2WSH)
        ([0x02, 0x57, 0x54, 0x83], TPUB), // Vpub (testnet P2WSH)
    ];

    let Ok(mut bytes) = bitcoin::base58::decode_check(key) else {
        return key.to_string();
    };
    if bytes.len() < 4 {
        return key.to_string();
    }
    for (from, to) in MAPPINGS {
        if &bytes[..4] == from {
            bytes[..4].copy_from_slice(to);
            return bitcoin::base58::encode_check(&bytes);
        }
    }
    key.to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct MultiSigSigner {
    derivation: String,
    fingerprint: [u8; 4],
    pubkey: String,
}

impl PartialOrd for MultiSigSigner {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MultiSigSigner {
    fn cmp(&self, other: &Self) -> Ordering {
        // Sort by serialized public key bytes to match sortedmulti() behavior
        let self_pubkey = match self.get_pubkey() {
            Ok(pk) => pk.public_key.serialize(),
            Err(_) => return Ordering::Equal,
        };
        let other_pubkey = match other.get_pubkey() {
            Ok(pk) => pk.public_key.serialize(),
            Err(_) => return Ordering::Equal,
        };
        self_pubkey.cmp(&other_pubkey)
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
            fingerprint: fingerprint.to_bytes(),
            pubkey: pubkey.to_string(),
        }
    }

    pub fn get_derivation(&self) -> Result<DerivationPath, bip32::Error> {
        DerivationPath::from_str(&self.derivation)
    }

    pub fn get_fingerprint(&self) -> Fingerprint {
        Fingerprint::from(&self.fingerprint)
    }

    pub fn get_pubkey(&self) -> Result<Xpub, bip32::Error> {
        Xpub::from_str(&self.pubkey)
    }

    pub fn get_derivation_inner(&self) -> &str {
        &self.derivation
    }
    pub fn get_fingerprint_inner(&self) -> &[u8; 4] {
        &self.fingerprint
    }
    pub fn get_pubkey_str(&self) -> &str {
        &self.pubkey
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct MultiSigDetails {
    pub policy_threshold: usize,  // aka M
    pub policy_total_keys: usize, // aka N
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

impl fmt::Display for MultiSigDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Policy: {} of {}",
            self.policy_threshold, self.policy_total_keys
        )?;

        writeln!(f, "Format: {}\n", self.format.to_export_string())?;

        for (i, signer) in self.signers.iter().enumerate() {
            writeln!(f, "Derivation: {}", signer.derivation)?;
            write!(
                f,
                "{}: {}",
                signer.fingerprint.to_upper_hex_string(),
                signer.pubkey
            )?;
            if i + 1 != self.policy_total_keys {
                write!(f, "\n\n")?;
            }
        }

        Ok(())
    }
}

impl MultiSigDetails {
    pub fn new(
        policy_threshold: usize,
        policy_total_keys: usize,
        format: AddressType,
        mut network_kind: Option<NetworkKind>,
        mut signers: Vec<MultiSigSigner>,
    ) -> Result<Self, anyhow::Error> {
        // Sort by xpubs
        signers.sort();

        if signers.len() != policy_total_keys {
            anyhow::bail!(
                "Multisig number of signers should match the total keys (M) specified, expected {} found {}",
                policy_total_keys,
                signers.len()
            );
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

            // Ensure that all pubkeys indicate the same network kind, also checks against the specified network_kind
            let n = network_kind.get_or_insert(signer_network);
            if *n != signer_network {
                anyhow::bail!("Multisig config has pubkeys from mismatched network types");
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
            network_kind: network_kind.ok_or(anyhow::anyhow!(
                "Network kind was neither specified nor infered from xpubs"
            ))?,
            signers,
        })
    }

    pub fn get_signers(&self) -> &Vec<MultiSigSigner> {
        &self.signers
    }

    pub fn default_name(&self) -> String {
        format!(
            "Multisig-{}-of-{}-{:?}",
            self.policy_threshold, self.policy_total_keys, self.network_kind
        )
    }

    // TODO: replace anyhows with thiserrors
    pub fn from_config(config: &str) -> Result<(Self, String), anyhow::Error> {
        let mut name: Option<String> = None;
        let mut policy_threshold: Option<usize> = None;
        let mut policy_total_keys: Option<usize> = None;
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
                    policy_threshold = Some(captures[1].parse::<usize>()?);
                    policy_total_keys = Some(captures[2].parse::<usize>()?);
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
                    let pubkey = Xpub::from_str(&normalize_slip132(&value))?;

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
            None,
            signers.clone(),
        )?;

        let name = name.unwrap_or(res.default_name());

        Ok((res, name))
    }

    fn from_sorted_multi<T: bdk_wallet::descriptor::ScriptContext>(
        format: AddressType,
        sorted_multi: SortedMultiVec<DescriptorPublicKey, T>,
    ) -> Result<(Self, String), anyhow::Error> {
        sorted_multi.sanity_check()?;
        let signers = sorted_multi
            .pks()
            .iter()
            .filter_map(|pk| match pk {
                DescriptorPublicKey::XPub(desc_xpub) => {
                    let (fingerprint, derivation_path) = match &desc_xpub.origin {
                        Some((f, d)) => (*f, d.clone()),
                        None => {
                            log::error!(
                                "Descriptor xpub {} doesn't contain origin info",
                                desc_xpub.xkey
                            );
                            return None;
                        }
                    };
                    let xpub = desc_xpub.xkey;
                    Some(MultiSigSigner::new(&derivation_path, &fingerprint, &xpub))
                }
                DescriptorPublicKey::MultiXPub(desc_xpub) => {
                    let (fingerprint, derivation_path) = match &desc_xpub.origin {
                        Some((f, d)) => (*f, d.clone()),
                        None => {
                            log::error!(
                                "Descriptor xpub {} doesn't contain origin info",
                                desc_xpub.xkey
                            );
                            return None;
                        }
                    };
                    let xpub = desc_xpub.xkey;
                    Some(MultiSigSigner::new(&derivation_path, &fingerprint, &xpub))
                }
                other => {
                    println!("Descriptor has {other:?} rather than xpub");
                    None
                }
            })
            .collect::<Vec<MultiSigSigner>>();

        let res = Self::new(sorted_multi.k(), sorted_multi.n(), format, None, signers)?;

        let name = res.default_name();

        Ok((res, name))
    }

    /// Build a [`MultiSigDetails`] from a decoded `crypto-output`
    /// ([`foundation_urtypes::registry::Terminal`]) descriptor tree.
    ///
    /// Callers obtain `terminal` from
    /// `foundation_urtypes::value::decode_output_descriptor`. This path is
    /// what lets Prime import animated multisig QRs from wallets like
    /// Sparrow that emit `ur:crypto-output/...` frames rather than the
    /// text-config or string-descriptor formats.
    ///
    /// Accepted shapes (mirroring [`Self::from_descriptor`]):
    /// - `wsh(sortedmulti(M, xpub1, xpub2, ...))` → `P2wsh`
    /// - `sh(wsh(sortedmulti(M, xpub1, xpub2, ...)))` → `P2ShWsh`
    ///
    /// Non-sorted `multisig`, taproot, bare addresses, raw scripts, and any
    /// other descriptor shapes are rejected — Prime doesn't support them
    /// today and accepting them here would let an import succeed that would
    /// later fail at spend time.
    pub fn from_crypto_output(
        terminal: &Terminal<'_, '_>,
    ) -> Result<(Self, String), anyhow::Error> {
        let (format, multikey) = match terminal {
            Terminal::WitnessScriptHash(inner) => match &**inner {
                Terminal::SortedMultisig(mk) => (AddressType::P2wsh, mk),
                Terminal::Multisig(_) => anyhow::bail!(
                    "crypto-output multisig must be sorted (sortedmulti), got unsorted multi"
                ),
                _ => anyhow::bail!(
                    "crypto-output wsh() must wrap sortedmulti, other scripts are not accepted"
                ),
            },
            Terminal::ScriptHash(outer) => match &**outer {
                Terminal::WitnessScriptHash(inner) => match &**inner {
                    Terminal::SortedMultisig(mk) => (AddressType::P2ShWsh, mk),
                    Terminal::Multisig(_) => anyhow::bail!(
                        "crypto-output multisig must be sorted (sortedmulti), got unsorted multi"
                    ),
                    _ => anyhow::bail!(
                        "crypto-output sh(wsh()) must wrap sortedmulti, other scripts are not accepted"
                    ),
                },
                _ => anyhow::bail!(
                    "crypto-output sh() must wrap wsh(sortedmulti), other scripts are not accepted"
                ),
            },
            _ => anyhow::bail!(
                "crypto-output descriptors must be wsh(sortedmulti) or sh(wsh(sortedmulti))"
            ),
        };

        // Reject duplicate cosigner keys up front. `from_descriptor` catches
        // this via miniscript's `sanity_check()`; `from_config` checks full-
        // tuple equality on each parsed `MultiSigSigner`. Neither applies on
        // this path — `Self::new` does not dedupe and
        // `wsh(sortedmulti(2, X, X))` would otherwise import as a nominal
        // 2-of-2 that spends with a single signature from X, silently
        // collapsing the effective threshold. Compare on the pubkey string
        // (the encoded xpub) so repeats of the same key under a different
        // derivation annotation are also rejected.
        let mut signers: Vec<MultiSigSigner> = Vec::new();
        for k in multikey.keys.iter() {
            let signer = hdkey_to_signer(&k)?;
            if signers.iter().any(|existing| existing.pubkey == signer.pubkey) {
                anyhow::bail!(
                    "crypto-output multisig contains duplicate cosigner keys"
                );
            }
            signers.push(signer);
        }

        let res = Self::new(
            multikey.threshold as usize,
            signers.len(),
            format,
            None,
            signers,
        )?;
        let name = res.default_name();
        Ok((res, name))
    }

    pub fn from_descriptor(descriptor: &str) -> Result<(Self, String), anyhow::Error> {
        let descriptor = BdkDescriptor::<DescriptorPublicKey>::from_str(descriptor)?;

        match descriptor {
            BdkDescriptor::Sh(desc) => match desc.into_inner() {
                ShInner::Wsh(d) => match d.into_inner() {
                    WshInner::SortedMulti(ms) => Self::from_sorted_multi(AddressType::P2ShWsh, ms),
                    _ => anyhow::bail!(
                        "Multisig descriptors should be wrapped by Sh(Wsh()) at most, other scripts are not currently accepted."
                    ),
                },
                _ => anyhow::bail!(
                    "Multisig descriptors starting with Sh() should contain Wsh(SortedMulti()), other scripts are not currently accepted"
                ),
            },
            BdkDescriptor::Wsh(desc) => match desc.into_inner() {
                WshInner::SortedMulti(ms) => Self::from_sorted_multi(AddressType::P2wsh, ms),
                _ => anyhow::bail!(
                    "Multisig descriptors starting with Wsh() should only contain a SortedMulti(), other scripts are not currently accepted."
                ),
            },
            _ => anyhow::bail!("Multisig descriptors should start with Sh() or Wsh()."),
        }
    }

    fn signer_to_xpub(
        &self,
        signer: &MultiSigSigner,
        keychain: KeychainKind,
    ) -> Option<DescriptorPublicKey> {
        let (fingerprint, derivation_path, pubkey) = match (
            signer.get_fingerprint(),
            signer.get_derivation(),
            signer.get_pubkey(),
        ) {
            (f, Ok(d), Ok(p)) => (f, d, p),
            _ => return None,
        };
        let path = DerivationPath::master().child(ChildNumber::Normal {
            index: keychain as u32,
        });
        let descriptor_x_key: DescriptorXKey<Xpub> = DescriptorXKey {
            origin: Some((fingerprint, derivation_path)),
            xkey: pubkey,
            derivation_path: path,
            wildcard: Wildcard::Unhardened,
        };
        Some(DescriptorPublicKey::XPub(descriptor_x_key))
    }

    pub fn to_descriptor<C: Signing>(
        &self,
        keychain: KeychainKind,
        secp: &Secp256k1<C>,
        master_key: Option<&MasterKey>,
    ) -> Result<
        (
            BdkDescriptor<DescriptorPublicKey>,
            BTreeMap<DescriptorPublicKey, DescriptorSecretKey>,
        ),
        anyhow::Error,
    > {
        let signers = self
            .signers
            .iter()
            .filter_map(|s| self.signer_to_xpub(s, keychain))
            .collect::<Vec<DescriptorPublicKey>>();

        let descriptor = match self.format {
            AddressType::P2ShWsh => BdkDescriptor::<DescriptorPublicKey>::new_sh_wsh_sortedmulti(
                self.policy_threshold,
                signers,
            )?,
            AddressType::P2wsh => BdkDescriptor::<DescriptorPublicKey>::new_wsh_sortedmulti(
                self.policy_threshold,
                signers,
            )?,
            other => anyhow::bail!(
                "Tried to make a descriptor from an unsupported multisig format: {:?}",
                other
            ),
        };

        let mut keymap = BTreeMap::<DescriptorPublicKey, DescriptorSecretKey>::new();

        if let Some(master) = master_key {
            let fp = master.fingerprint;
            let master_xprv = Xpriv::new_master(self.network_kind, &master.key.0)?;

            descriptor.for_each_key(|pubkey| {
                if let DescriptorPublicKey::XPub(xkey) = pubkey
                    && let Some(origin) = &xkey.origin
                    && origin.0 == fp
                    && let Ok(derived_xprv) = master_xprv.derive_priv(secp, &origin.1)
                {
                    let derived_xpub = Xpub::from_priv(secp, &derived_xprv);
                    let desc_xkey = DescriptorXKey {
                        origin: Some(origin.clone()),
                        xkey: derived_xprv,
                        derivation_path: xkey.derivation_path.clone(),
                        wildcard: xkey.wildcard,
                    };
                    keymap.insert(
                        DescriptorPublicKey::XPub(DescriptorXKey {
                            origin: Some(origin.clone()),
                            xkey: derived_xpub,
                            derivation_path: xkey.derivation_path.clone(),
                            wildcard: xkey.wildcard,
                        }),
                        DescriptorSecretKey::XPrv(desc_xkey),
                    );
                }
                true
            });
        }
        Ok((descriptor, keymap))
    }

    pub fn get_bip(&self) -> Result<String, anyhow::Error> {
        Ok(match self.format {
            AddressType::P2ShWsh => String::from("48_1"),
            AddressType::P2wsh => String::from("48_2"),
            other => anyhow::bail!(
                "Tried to get bip of a descriptor from an unsupported multisig format: {:?}",
                other
            ),
        })
    }

    pub fn get_descriptors<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        master_key: Option<&MasterKey>,
    ) -> anyhow::Result<Vec<Descriptors>> {
        let (external_desc, external_keymap) =
            self.to_descriptor(KeychainKind::External, secp, master_key)?;
        let (internal_desc, internal_keymap) =
            self.to_descriptor(KeychainKind::Internal, secp, master_key)?;
        let descriptor_type = external_desc.desc_type();

        Ok(vec![Descriptors {
            bip: self.get_bip()?,
            export_addr_hint: self.format,
            descriptor: (external_desc, external_keymap),
            change_descriptor: (internal_desc, internal_keymap),
            descriptor_type,
        }])
    }

    pub fn to_config(&self, mut name: String) -> String {
        name.insert_str(0, "Name: ");
        name.push('\n');
        name.push_str(&self.to_string());
        name
    }

    #[cfg(feature = "sha2")]
    pub fn sha256(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.policy_threshold.to_le_bytes());
        hasher.update(self.policy_total_keys.to_le_bytes());
        hasher.update(format!("{:?}", self.format).as_bytes());
        hasher.update(format!("{:?}", self.network_kind).as_bytes());

        let mut signers = self.signers.clone();
        signers.sort();

        for s in signers {
            hasher.update(s.derivation.as_bytes());
            hasher.update(s.fingerprint);
            hasher.update(s.pubkey.as_bytes());
        }

        hasher.finalize().into()
    }
}

/// Convert a `foundation-urtypes` key entry into a [`MultiSigSigner`].
///
/// We walk the CBOR-decoded view (`DerivedKeyRef` + `KeypathRef`) and
/// reconstruct a `bitcoin::bip32::Xpub` from its raw bytes so downstream
/// code can treat it identically to xpubs coming from text-config or
/// string-descriptor imports.
fn hdkey_to_signer(key: &UrKey<'_>) -> Result<MultiSigSigner, anyhow::Error> {
    let hdkey = match key {
        UrKey::HDKey(h) => h,
        UrKey::ECKey(_) => {
            anyhow::bail!("crypto-output multisig key is a bare EC pubkey; need an hdkey/xpub")
        }
    };
    let derived = match hdkey {
        HDKeyRef::DerivedKey(d) => d,
        HDKeyRef::MasterKey(_) => {
            anyhow::bail!("crypto-output multisig key is a master key; need a derived xpub")
        }
    };

    let origin = derived
        .origin
        .as_ref()
        .context("crypto-output hdkey is missing origin info (need master fingerprint + path)")?;

    let src_fp = origin
        .source_fingerprint
        .context("crypto-output hdkey origin is missing source-fingerprint")?;
    let master_fingerprint = Fingerprint::from(src_fp.get().to_be_bytes());

    let mut path_components: Vec<ChildNumber> = Vec::with_capacity(origin.components.len());
    for comp in origin.components.iter() {
        let index = match comp.number {
            UrChildNumber::Number(n) => n,
            UrChildNumber::Range(_) => {
                anyhow::bail!("crypto-output hdkey origin contains a wildcard path component")
            }
        };
        path_components.push(if comp.is_hardened {
            ChildNumber::Hardened { index }
        } else {
            ChildNumber::Normal { index }
        });
    }
    let derivation_path = DerivationPath::from(path_components.clone());

    let chain_code_bytes = derived
        .chain_code
        .context("crypto-output hdkey is missing chain code")?;

    let public_key = PublicKey::from_slice(&derived.key_data)
        .context("crypto-output hdkey has invalid compressed pubkey")?;

    // CoinInfo network is the BIP44 SLIP-44-ish value: 0 = mainnet, 1 = testnet.
    // Absent → default to mainnet (matches `from_sorted_multi` which also
    // defers network inference to `Self::new`).
    let network = match derived.use_info.as_ref().map(|ci| ci.network) {
        Some(0) | None => BtcNetworkKind::Main,
        Some(1) => BtcNetworkKind::Test,
        Some(other) => {
            anyhow::bail!("crypto-output hdkey has unsupported network index {other}")
        }
    };

    let depth = origin
        .depth
        .unwrap_or_else(|| origin.components.len() as u8);

    let parent_fingerprint = derived
        .parent_fingerprint
        .map(|fp| Fingerprint::from(fp.get().to_be_bytes()))
        .unwrap_or_default();

    let child_number = path_components
        .last()
        .copied()
        .unwrap_or(ChildNumber::Normal { index: 0 });

    let xpub = Xpub {
        network,
        depth,
        parent_fingerprint,
        child_number,
        public_key,
        chain_code: ChainCode::from(chain_code_bytes),
    };

    Ok(MultiSigSigner::new(
        &derivation_path,
        &master_fingerprint,
        &xpub,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
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

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
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

impl AddressType {
    pub fn flatten(&self) -> Self {
        match self {
            AddressType::P2pkh => AddressType::P2pkh,
            AddressType::P2sh => AddressType::P2sh,
            AddressType::P2wpkh => AddressType::P2wpkh,
            AddressType::P2wsh => AddressType::P2wsh,
            AddressType::P2tr => AddressType::P2tr,
            AddressType::P2ShWpkh => AddressType::P2sh,
            AddressType::P2ShWsh => AddressType::P2sh,
        }
    }

    pub fn to_export_string(&self) -> String {
        match self {
            AddressType::P2pkh => "P2PKH",
            AddressType::P2sh => "P2SH",
            AddressType::P2wpkh => "P2WPKH",
            AddressType::P2wsh => "P2WSH",
            AddressType::P2tr => "P2TR",
            AddressType::P2ShWpkh => "P2WPKH-P2SH",
            AddressType::P2ShWsh => "P2WSH-P2SH",
        }
        .into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct NgDescriptor {
    pub internal: String,
    pub external: Option<String>,
    pub address_type: AddressType,
    // This is necessary for export and won't
    // necessarily match the regular address_type
    // for multisig-only descriptors
    pub export_addr_hint: Option<AddressType>,
}

impl fmt::Debug for NgDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NgDescriptor")
            .field("internal", &"<redacted descriptor>")
            .field(
                "external",
                &self.external.as_ref().map(|_| "<redacted descriptor>"),
            )
            .field("address_type", &self.address_type)
            .field("export_addr_hint", &self.export_addr_hint)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone)]
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
    pub network: Network,
    pub id: String,
    pub multisig: Option<MultiSigDetails>,
    #[serde(default)]
    pub archived: bool,
}

impl fmt::Debug for NgAccountConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let descriptors = format!("<redacted; {} descriptors>", self.descriptors.len());
        f.debug_struct("NgAccountConfig")
            .field("name", &self.name)
            .field("color", &self.color)
            .field("seed_has_passphrase", &self.seed_has_passphrase)
            .field("device_serial", &self.device_serial)
            .field("date_added", &self.date_added)
            .field("preferred_address_type", &self.preferred_address_type)
            .field("index", &self.index)
            .field("descriptors", &descriptors)
            .field("date_synced", &self.date_synced)
            .field("network", &self.network)
            .field("id", &self.id)
            .field("multisig", &self.multisig)
            .field("archived", &self.archived)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NgAccountBackup {
    pub ng_account_config: NgAccountConfig,
    //envoy 2.0.1 doesnt include xfp in backup
    #[serde(default)]
    pub xfp: String,
    //envoy 2.0.1 doesnt include public_descriptors in backup
    #[serde(default)]
    pub public_descriptors: Vec<(AddressType, String)>,
    pub last_used_index: Vec<(AddressType, KeychainKind, u32)>,
    pub notes: HashMap<String, String>,
    pub tags: HashMap<String, String>,
    pub do_not_spend: HashMap<String, bool>,
}

impl fmt::Debug for NgAccountBackup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let public_descriptors = format!(
            "<redacted; {} public descriptors>",
            self.public_descriptors.len()
        );
        f.debug_struct("NgAccountBackup")
            .field("ng_account_config", &self.ng_account_config)
            .field("xfp", &self.xfp)
            .field("public_descriptors", &public_descriptors)
            .field("last_used_index", &self.last_used_index)
            .field("notes", &self.notes)
            .field("tags", &self.tags)
            .field("do_not_spend", &self.do_not_spend)
            .finish()
    }
}

impl NgAccountConfig {
    pub fn serialize(&self) -> String {
        serde_json::to_string_pretty(self).unwrap()
    }

    pub fn deserialize(data: &str) -> Self {
        serde_json::from_str(data).unwrap()
    }

    pub fn has_private_descriptors(&self) -> bool {
        self.descriptors.iter().any(|descriptor| {
            descriptor_contains_private_material(&descriptor.internal)
                || descriptor
                    .external
                    .as_ref()
                    .is_some_and(|external| descriptor_contains_private_material(external))
        })
    }

    pub fn clear_private_descriptors(&mut self) {
        if self.has_private_descriptors() {
            self.descriptors = vec![];
        }
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

    pub fn from_storage(meta_storage: impl MetaStorage) -> Option<NgAccountConfig> {
        meta_storage.get_config().unwrap_or_else(|e| {
            log::info!("Error reading config {e:?}");
            None
        })
    }
    pub fn to_remote_update(mut self) -> Vec<u8> {
        self.clear_private_descriptors();
        RemoteUpdate::new(Some(self), vec![]).serialize()
    }

    pub fn from_file(db_path: Option<String>) -> Option<NgAccountConfig> {
        let meta_storage = RedbMetaStorage::from_file(db_path).ok()?;
        Self::from_storage(meta_storage)
    }
}

fn descriptor_contains_private_material(descriptor: &str) -> bool {
    let descriptor = descriptor.to_ascii_lowercase();
    ["xprv", "tprv", "yprv", "zprv", "uprv", "vprv"]
        .iter()
        .any(|marker| descriptor.contains(marker))
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
            archived: None,
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
    archived: Option<bool>,
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

    pub fn multisig(mut self, multisig: MultiSigDetails) -> Self {
        self.multisig = Some(multisig);
        self
    }

    pub fn build_in_memory(self) -> anyhow::Result<NgAccount<P>> {
        let meta_storage = Arc::new(crate::store::InMemoryMetaStorage::default());
        self.build(meta_storage)
    }

    pub fn build_from_file(self, db_path: Option<String>) -> anyhow::Result<NgAccount<P>> {
        let meta_storage = Arc::new(RedbMetaStorage::from_file(db_path)?);
        self.build(meta_storage)
    }

    pub fn build_from_db(self, db: redb::Database) -> anyhow::Result<NgAccount<P>> {
        let meta_storage = Arc::new(RedbMetaStorage::from_db(db));
        self.build(meta_storage)
    }

    pub fn build(self, storage: Arc<dyn MetaStorage>) -> anyhow::Result<NgAccount<P>> {
        let descriptors = self
            .descriptors
            .ok_or(anyhow::anyhow!("Descriptors are required"))?;

        let ng_descriptors = descriptors
            .iter()
            .map(|d| NgDescriptor {
                external: d.external.clone(),
                internal: d.internal.clone(),
                address_type: get_address_type(&d.internal),
                export_addr_hint: None,
            })
            .collect();

        let ng_account_config = NgAccountConfig {
            name: self.name.ok_or(anyhow::anyhow!("Name is required"))?,
            color: self.color.ok_or(anyhow::anyhow!("Color is required"))?,
            device_serial: self.device_serial,
            date_added: self.date_added,
            network: self.network.ok_or(anyhow::anyhow!("Network is required"))?,
            preferred_address_type: match self.multisig {
                Some(ref m) => m.format.flatten(),
                None => self
                    .preferred_address_type
                    .ok_or(anyhow::anyhow!("Preferred address type is required"))?,
            },
            descriptors: ng_descriptors,
            index: if self.multisig.is_none() {
                self.index.ok_or(anyhow::anyhow!("Index is required"))?
            } else {
                0
            },
            id: self.id.ok_or(anyhow::anyhow!("id is required"))?,
            date_synced: self.date_synced,
            seed_has_passphrase: self.seed_has_passphrase.unwrap_or(false),
            multisig: self.multisig,
            archived: self.archived.unwrap_or_default(),
        };

        NgAccount::new_from_descriptors(ng_account_config, storage, descriptors)
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
                    fingerprint: [0xAB, 0x88, 0xDE, 0x89],
                    pubkey: String::from(
                        "tpubDFUc8ddWCzA8kC195Zn6UitBcBGXbPbtjktU2dk2Deprnf6sR15GAyHLQKUjAPa3gqD74g7Eea3NSqkb9FfYRZzEm2MTbCtTDZAKSHezJwb",
                    ),
                },
                MultiSigSigner {
                    derivation: String::from("m/48'/1'/0'/2'"),
                    fingerprint: [0x66, 0x2A, 0x42, 0xE4],
                    pubkey: String::from(
                        "tpubDFGqX4Ge633XixPNo4uF5h6sPkv32bwJrknDmmPGMq8Tn3Pu9QgWfk5hUiDe7gvv2eaFeaHXgjiZwKvnP3AhusoaWBK3qTv8cznyHxxGoSF",
                    ),
                },
            ],
        };
        assert_eq!(expected, multisig);
        assert_eq!(String::from("Multisig 2-of-2 Test"), name);

        let secp = Secp256k1::new();
        let receive_descriptor = multisig
            .to_descriptor(KeychainKind::External, &secp, None)
            .unwrap()
            .0;
        let expected_receive_descriptor = String::from(
            "wsh(sortedmulti(2,[ab88de89/48'/1'/0'/2']tpubDFUc8ddWCzA8kC195Zn6UitBcBGXbPbtjktU2dk2Deprnf6sR15GAyHLQKUjAPa3gqD74g7Eea3NSqkb9FfYRZzEm2MTbCtTDZAKSHezJwb/0/*,[662a42e4/48'/1'/0'/2']tpubDFGqX4Ge633XixPNo4uF5h6sPkv32bwJrknDmmPGMq8Tn3Pu9QgWfk5hUiDe7gvv2eaFeaHXgjiZwKvnP3AhusoaWBK3qTv8cznyHxxGoSF/0/*))#7atlaq2g",
        );

        assert_eq!(receive_descriptor.to_string(), expected_receive_descriptor);

        let change_descriptor = multisig
            .to_descriptor(KeychainKind::Internal, &secp, None)
            .unwrap()
            .0;
        let expected_change_descriptor = String::from(
            "wsh(sortedmulti(2,[ab88de89/48'/1'/0'/2']tpubDFUc8ddWCzA8kC195Zn6UitBcBGXbPbtjktU2dk2Deprnf6sR15GAyHLQKUjAPa3gqD74g7Eea3NSqkb9FfYRZzEm2MTbCtTDZAKSHezJwb/1/*,[662a42e4/48'/1'/0'/2']tpubDFGqX4Ge633XixPNo4uF5h6sPkv32bwJrknDmmPGMq8Tn3Pu9QgWfk5hUiDe7gvv2eaFeaHXgjiZwKvnP3AhusoaWBK3qTv8cznyHxxGoSF/1/*))#8wcmnnla",
        );

        assert_eq!(change_descriptor.to_string(), expected_change_descriptor);

        let descriptors = multisig.get_descriptors(&secp, None).unwrap();

        let descriptor = &descriptors[0];
        assert_eq!(String::from("48_2"), descriptor.bip);
        assert_eq!(expected_receive_descriptor, descriptor.descriptor_xpub());
        assert_eq!(
            expected_change_descriptor,
            descriptor.change_descriptor_xpub()
        );
        assert_eq!(
            bdk_wallet::miniscript::descriptor::DescriptorType::WshSortedMulti,
            descriptor.descriptor_type
        );

        let expected_config = String::from("Name: Multisig 2-of-2 Test
Policy: 2 of 2
Format: P2WSH

Derivation: m/48'/1'/0'/2'
AB88DE89: tpubDFUc8ddWCzA8kC195Zn6UitBcBGXbPbtjktU2dk2Deprnf6sR15GAyHLQKUjAPa3gqD74g7Eea3NSqkb9FfYRZzEm2MTbCtTDZAKSHezJwb

Derivation: m/48'/1'/0'/2'
662A42E4: tpubDFGqX4Ge633XixPNo4uF5h6sPkv32bwJrknDmmPGMq8Tn3Pu9QgWfk5hUiDe7gvv2eaFeaHXgjiZwKvnP3AhusoaWBK3qTv8cznyHxxGoSF");

        assert_eq!(
            multisig.to_config(String::from("Multisig 2-of-2 Test")),
            expected_config
        );
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
                    fingerprint: [0x66, 0x2A, 0x42, 0xE4],
                    pubkey: String::from(
                        "tpubDFGqX4Ge633XixPNo4uF5h6sPkv32bwJrknDmmPGMq8Tn3Pu9QgWfk5hUiDe7gvv2eaFeaHXgjiZwKvnP3AhusoaWBK3qTv8cznyHxxGoSF",
                    ),
                },
                MultiSigSigner {
                    derivation: String::from("m/48'/1'/0'/2'"),
                    fingerprint: [0xAB, 0x88, 0xDE, 0x89],
                    pubkey: String::from(
                        "tpubDFUc8ddWCzA8kC195Zn6UitBcBGXbPbtjktU2dk2Deprnf6sR15GAyHLQKUjAPa3gqD74g7Eea3NSqkb9FfYRZzEm2MTbCtTDZAKSHezJwb",
                    ),
                },
            ],
        };
        assert_eq!(expected, multisig);
        assert_eq!(String::from("Multisig 2-of-2 Test"), name);
    }

    #[test]
    fn multisig_from_descriptor_1() {
        let descriptor = String::from(
            "wsh(sortedmulti(2,[71C8BD85/48h/0h/0h/2h]xpub6ESpvmZa75rCQWKik2KoCZrjTi6xhSubZKJ25rbtgZRk2g9tZTJqubhaGD3dJeqruw9KMCaanoEfJ1PVtBXiwTuuqLVwk9ucqkRv1sKWiEC/<0;1>/*,[AB88DE89/48h/0h/0h/2h]xpub6EPJuK8Ejz82nKc7PsRgcYqdcQH9G1ZikCTasr9i79CbXxMMiPfxEyA14S6HPTHufmcQR7x8t5L3BP9tRfm9EBRBPic2xV892j9z4ePESae/<0;1>/*,[A9F9964A/48h/0h/0h/2h]xpub6FQY5W8WygMVYY2nTP188jFHNdZfH2t9qtcS8SPpFatUGiciqUsGZpNvEa1oABEyeAsrUL2XSnvuRUdrhf5LcMXcjhrUFBcneBYYZzky3Mc/<0;1>/*))",
        );
        println!("I am here!");
        let (multisig, name) = MultiSigDetails::from_descriptor(&descriptor).unwrap();
        let expected = MultiSigDetails::new(
            2,
            3,
            AddressType::P2wsh,
            Some(NetworkKind::Main),
            vec![
                MultiSigSigner {
                    derivation: String::from("m/48'/0'/0'/2'"),
                    fingerprint: [0x71, 0xC8, 0xBD, 0x85],
                    pubkey: String::from("xpub6ESpvmZa75rCQWKik2KoCZrjTi6xhSubZKJ25rbtgZRk2g9tZTJqubhaGD3dJeqruw9KMCaanoEfJ1PVtBXiwTuuqLVwk9ucqkRv1sKWiEC"),
                },
                MultiSigSigner {
                    derivation: String::from("m/48'/0'/0'/2'"),
                    fingerprint: [0xAB, 0x88, 0xDE, 0x89],
                    pubkey: String::from("xpub6EPJuK8Ejz82nKc7PsRgcYqdcQH9G1ZikCTasr9i79CbXxMMiPfxEyA14S6HPTHufmcQR7x8t5L3BP9tRfm9EBRBPic2xV892j9z4ePESae"),
                },
                MultiSigSigner {
                    derivation: String::from("m/48'/0'/0'/2'"),
                    fingerprint: [0xA9, 0xF9, 0x96, 0x4A],
                    pubkey: String::from("xpub6FQY5W8WygMVYY2nTP188jFHNdZfH2t9qtcS8SPpFatUGiciqUsGZpNvEa1oABEyeAsrUL2XSnvuRUdrhf5LcMXcjhrUFBcneBYYZzky3Mc"),
                }
            ],
        ).unwrap();
        assert_eq!(multisig, expected);
        assert_eq!(String::from("Multisig-2-of-3-Main"), name);
    }

    #[test]
    fn multisig_from_descriptor_2() {
        let descriptor = String::from(
            "sh(wsh(sortedmulti(2,[71C8BD85/48h/0h/0h/1h]xpub6ESpvmZa75rCQWKik2KoCZrjTi6xhSubZKJ25rbtgZRk2g9tZTJqubhaGD3dJeqruw9KMCaanoEfJ1PVtBXiwTuuqLVwk9ucqkRv1sKWiEC/<0;1>/*,[AB88DE89/48h/0h/0h/1h]xpub6EPJuK8Ejz82nKc7PsRgcYqdcQH9G1ZikCTasr9i79CbXxMMiPfxEyA14S6HPTHufmcQR7x8t5L3BP9tRfm9EBRBPic2xV892j9z4ePESae/<0;1>/*,[A9F9964A/48h/0h/0h/1h]xpub6FQY5W8WygMVYY2nTP188jFHNdZfH2t9qtcS8SPpFatUGiciqUsGZpNvEa1oABEyeAsrUL2XSnvuRUdrhf5LcMXcjhrUFBcneBYYZzky3Mc/<0;1>/*)))",
        );
        println!("I am here!");
        let (multisig, name) = MultiSigDetails::from_descriptor(&descriptor).unwrap();
        let expected = MultiSigDetails::new(
            2,
            3,
            AddressType::P2ShWsh,
            Some(NetworkKind::Main),
            vec![
                MultiSigSigner {
                    derivation: String::from("m/48'/0'/0'/1'"),
                    fingerprint: [0x71, 0xC8, 0xBD, 0x85],
                    pubkey: String::from("xpub6ESpvmZa75rCQWKik2KoCZrjTi6xhSubZKJ25rbtgZRk2g9tZTJqubhaGD3dJeqruw9KMCaanoEfJ1PVtBXiwTuuqLVwk9ucqkRv1sKWiEC"),
                },
                MultiSigSigner {
                    derivation: String::from("m/48'/0'/0'/1'"),
                    fingerprint: [0xAB, 0x88, 0xDE, 0x89],
                    pubkey: String::from("xpub6EPJuK8Ejz82nKc7PsRgcYqdcQH9G1ZikCTasr9i79CbXxMMiPfxEyA14S6HPTHufmcQR7x8t5L3BP9tRfm9EBRBPic2xV892j9z4ePESae"),
                },
                MultiSigSigner {
                    derivation: String::from("m/48'/0'/0'/1'"),
                    fingerprint: [0xA9, 0xF9, 0x96, 0x4A],
                    pubkey: String::from("xpub6FQY5W8WygMVYY2nTP188jFHNdZfH2t9qtcS8SPpFatUGiciqUsGZpNvEa1oABEyeAsrUL2XSnvuRUdrhf5LcMXcjhrUFBcneBYYZzky3Mc"),
                }
            ],
        ).unwrap();
        assert_eq!(multisig, expected);
        assert_eq!(String::from("Multisig-2-of-3-Main"), name);
    }

    // Regression test for SFT-6907: BlueWallet emits P2WSH multisig exports
    // with SLIP-132 `Zpub` extended keys. Before the SLIP-132 normalization
    // step in `from_config`, `Xpub::from_str` rejected these prefixes and the
    // import fell through to `from_descriptor`, which then reported a
    // confusing "unprintable character 0x0a" error from the newline-laden
    // config text.
    #[test]
    fn multisig_from_config_bluewallet_zpub() {
        let config = String::from("# BlueWallet Multisig setup file
# this file contains only public keys and is safe to
# distribute among cosigners
#
Name: Multisig Vault
Policy: 2 of 2
Derivation: m/48'/0'/0'/2'
Format: P2WSH

441C5C1A: Zpub75VbUBtx3Mx8Z4vxYGGhwPPHnL6vYqGhyVq8iEbDbbZSwGw8uZQvhPuH2FnwoN2JGhvGqB4jBrHzhwfGk2Mui78RoYUXzCzGVutX9xea215

6015C0F4: Zpub75WVDNjeAJrPuZkrgPQCxqf2QLNvkXtWYfosic2G2BvbvRwMRxc2P2kk6vabVRiN582SiuCE6ChZTXUSWeGMvcamVxMecL6Uc3zTWkYpXnG
");
        let (multisig, name) = MultiSigDetails::from_config(&config).unwrap();
        assert_eq!(name, String::from("Multisig Vault"));
        assert_eq!(multisig.policy_threshold, 2);
        assert_eq!(multisig.policy_total_keys, 2);
        assert_eq!(multisig.format, AddressType::P2wsh);
        assert_eq!(multisig.network_kind, NetworkKind::Main);
        assert_eq!(multisig.signers.len(), 2);
        assert_eq!(multisig.signers[0].fingerprint, [0x44, 0x1C, 0x5C, 0x1A]);
        assert_eq!(multisig.signers[1].fingerprint, [0x60, 0x15, 0xC0, 0xF4]);
        assert_eq!(multisig.signers[0].derivation, String::from("m/48'/0'/0'/2'"));
        // Normalization should rewrite Zpub → xpub so downstream consumers
        // (descriptor building, signing, display) only ever see canonical
        // extended keys.
        assert!(multisig.signers[0].pubkey.starts_with("xpub"));
        assert!(multisig.signers[1].pubkey.starts_with("xpub"));
    }

    #[test]
    fn normalize_slip132_passes_xpub_through_unchanged() {
        let xpub = "xpub6ESpvmZa75rCQWKik2KoCZrjTi6xhSubZKJ25rbtgZRk2g9tZTJqubhaGD3dJeqruw9KMCaanoEfJ1PVtBXiwTuuqLVwk9ucqkRv1sKWiEC";
        assert_eq!(normalize_slip132(xpub), xpub);
    }

    #[test]
    fn normalize_slip132_passes_tpub_through_unchanged() {
        let tpub = "tpubDFUc8ddWCzA8kC195Zn6UitBcBGXbPbtjktU2dk2Deprnf6sR15GAyHLQKUjAPa3gqD74g7Eea3NSqkb9FfYRZzEm2MTbCtTDZAKSHezJwb";
        assert_eq!(normalize_slip132(tpub), tpub);
    }

    #[test]
    fn normalize_slip132_passes_garbage_through_unchanged() {
        assert_eq!(normalize_slip132("not-a-real-xpub"), "not-a-real-xpub");
        assert_eq!(normalize_slip132(""), "");
    }

    #[test]
    fn normalize_slip132_zpub_yields_parseable_xpub() {
        // Real BlueWallet-emitted P2WSH Zpub — after normalization it must
        // parse as a standard extended public key.
        let zpub = "Zpub75VbUBtx3Mx8Z4vxYGGhwPPHnL6vYqGhyVq8iEbDbbZSwGw8uZQvhPuH2FnwoN2JGhvGqB4jBrHzhwfGk2Mui78RoYUXzCzGVutX9xea215";
        let normalized = normalize_slip132(zpub);
        assert!(normalized.starts_with("xpub"));
        assert!(Xpub::from_str(&normalized).is_ok());
    }

    // Round-trips the other three supported multisig encodings by taking a
    // known-good xpub/tpub, rewriting the version bytes to the target prefix,
    // running it back through normalize_slip132, and asserting we recover the
    // original. This exercises each mapping without needing hand-crafted
    // Ypub/Upub/Vpub fixtures.
    fn roundtrip_through_prefix(canonical: &str, slip132_version: [u8; 4], prefix: &str) {
        let mut bytes = bitcoin::base58::decode_check(canonical).unwrap();
        bytes[..4].copy_from_slice(&slip132_version);
        let slip132 = bitcoin::base58::encode_check(&bytes);
        assert!(
            slip132.starts_with(prefix),
            "expected {prefix}…, got {slip132}"
        );
        assert_eq!(normalize_slip132(&slip132), canonical);
    }

    #[test]
    fn normalize_slip132_ypub_roundtrips_to_xpub() {
        let xpub = "xpub6ESpvmZa75rCQWKik2KoCZrjTi6xhSubZKJ25rbtgZRk2g9tZTJqubhaGD3dJeqruw9KMCaanoEfJ1PVtBXiwTuuqLVwk9ucqkRv1sKWiEC";
        roundtrip_through_prefix(xpub, [0x02, 0x95, 0xB4, 0x3F], "Ypub");
    }

    #[test]
    fn normalize_slip132_vpub_roundtrips_to_tpub() {
        let tpub = "tpubDFUc8ddWCzA8kC195Zn6UitBcBGXbPbtjktU2dk2Deprnf6sR15GAyHLQKUjAPa3gqD74g7Eea3NSqkb9FfYRZzEm2MTbCtTDZAKSHezJwb";
        roundtrip_through_prefix(tpub, [0x02, 0x57, 0x54, 0x83], "Vpub");
    }

    #[test]
    fn normalize_slip132_upub_roundtrips_to_tpub() {
        let tpub = "tpubDFUc8ddWCzA8kC195Zn6UitBcBGXbPbtjktU2dk2Deprnf6sR15GAyHLQKUjAPa3gqD74g7Eea3NSqkb9FfYRZzEm2MTbCtTDZAKSHezJwb";
        roundtrip_through_prefix(tpub, [0x02, 0x42, 0x89, 0xEF], "Upub");
    }

    // Singlesig SLIP-132 encodings (lowercase zpub here) are deliberately NOT
    // normalized — they belong to single-sig wallets and should never appear
    // in a multisig config. normalize_slip132 should return them unchanged so
    // that Xpub::from_str surfaces the error naturally.
    #[test]
    fn normalize_slip132_singlesig_zpub_passes_through_unchanged() {
        let xpub = "xpub6ESpvmZa75rCQWKik2KoCZrjTi6xhSubZKJ25rbtgZRk2g9tZTJqubhaGD3dJeqruw9KMCaanoEfJ1PVtBXiwTuuqLVwk9ucqkRv1sKWiEC";
        let mut bytes = bitcoin::base58::decode_check(xpub).unwrap();
        bytes[..4].copy_from_slice(&[0x04, 0xB2, 0x47, 0x46]); // zpub (BIP84 singlesig)
        let zpub = bitcoin::base58::encode_check(&bytes);
        assert!(zpub.starts_with("zpub"));
        assert_eq!(normalize_slip132(&zpub), zpub);
    }

    // Build a `Terminal::WitnessScriptHash(SortedMultisig(...))` tree from
    // `(xpub_str, fingerprint_hex, derivation_str)` entries, encode it to
    // CBOR, and return the bytes plus the byte-backing storage. Mirrors
    // what `minicbor::to_vec(&Terminal)` gives us when the sender is
    // e.g. Sparrow.
    #[cfg(test)]
    fn encode_wsh_sortedmulti_cbor(
        threshold: u8,
        entries: &[(&str, [u8; 4], &str)],
    ) -> Vec<u8> {
        use foundation_arena::boxed::Box as ArenaBox;
        use foundation_urtypes::registry::{
            CoinInfo, CoinType, DerivedKeyRef, HDKeyRef as UrHDKeyRef, Key, KeypathRef, Keys,
            Multikey, PathComponents, Terminal, TerminalContext,
        };
        use std::num::NonZeroU32;

        // Pre-decompose each entry into stable byte storage that outlives
        // every borrow below.
        struct Entry {
            key_data: [u8; 33],
            chain_code: [u8; 32],
            path_raw: Vec<u32>,
            source_fingerprint: NonZeroU32,
            parent_fingerprint: Option<NonZeroU32>,
            depth: u8,
        }
        let decomposed: Vec<Entry> = entries
            .iter()
            .map(|(xpub_str, xfp, deriv)| {
                let xpub = Xpub::from_str(xpub_str).unwrap();
                let deriv_path = DerivationPath::from_str(deriv).unwrap();
                let path_raw: Vec<u32> = deriv_path
                    .into_iter()
                    .map(|cn| match cn {
                        ChildNumber::Normal { index } => *index,
                        ChildNumber::Hardened { index } => *index | (1 << 31),
                    })
                    .collect();
                Entry {
                    key_data: xpub.public_key.serialize(),
                    chain_code: xpub.chain_code.to_bytes(),
                    path_raw,
                    source_fingerprint: NonZeroU32::new(u32::from_be_bytes(*xfp)).unwrap(),
                    parent_fingerprint: NonZeroU32::new(u32::from_be_bytes(
                        xpub.parent_fingerprint.to_bytes(),
                    )),
                    depth: xpub.depth,
                }
            })
            .collect();

        let arena: TerminalContext<4> = TerminalContext::new();
        let keys_owned: Vec<Key> = decomposed
            .iter()
            .map(|e| {
                Key::HDKey(UrHDKeyRef::DerivedKey(DerivedKeyRef {
                    is_private: false,
                    key_data: e.key_data,
                    chain_code: Some(e.chain_code),
                    use_info: Some(CoinInfo::new(CoinType::BTC, CoinInfo::NETWORK_MAINNET)),
                    origin: Some(KeypathRef {
                        components: PathComponents::from(e.path_raw.as_slice()),
                        source_fingerprint: Some(e.source_fingerprint),
                        depth: Some(e.depth),
                    }),
                    children: None,
                    parent_fingerprint: e.parent_fingerprint,
                    name: None,
                    note: None,
                }))
            })
            .collect();
        let keys = Keys::from(keys_owned.as_slice());
        let sortedmulti = ArenaBox::new_in(
            Terminal::SortedMultisig(Multikey { threshold, keys }),
            &arena,
        )
        .unwrap();
        let root = Terminal::WitnessScriptHash(sortedmulti);
        minicbor::to_vec(&root).unwrap()
    }

    #[test]
    fn multisig_from_crypto_output_wsh_sortedmulti() {
        use foundation_urtypes::registry::TerminalContext;
        use foundation_urtypes::value::decode_output_descriptor;

        // Same signer set as `multisig_from_descriptor_1`.
        let entries: &[(&str, [u8; 4], &str)] = &[
            (
                "xpub6ESpvmZa75rCQWKik2KoCZrjTi6xhSubZKJ25rbtgZRk2g9tZTJqubhaGD3dJeqruw9KMCaanoEfJ1PVtBXiwTuuqLVwk9ucqkRv1sKWiEC",
                [0x71, 0xC8, 0xBD, 0x85],
                "m/48'/0'/0'/2'",
            ),
            (
                "xpub6EPJuK8Ejz82nKc7PsRgcYqdcQH9G1ZikCTasr9i79CbXxMMiPfxEyA14S6HPTHufmcQR7x8t5L3BP9tRfm9EBRBPic2xV892j9z4ePESae",
                [0xAB, 0x88, 0xDE, 0x89],
                "m/48'/0'/0'/2'",
            ),
            (
                "xpub6FQY5W8WygMVYY2nTP188jFHNdZfH2t9qtcS8SPpFatUGiciqUsGZpNvEa1oABEyeAsrUL2XSnvuRUdrhf5LcMXcjhrUFBcneBYYZzky3Mc",
                [0xA9, 0xF9, 0x96, 0x4A],
                "m/48'/0'/0'/2'",
            ),
        ];

        let cbor = encode_wsh_sortedmulti_cbor(2, entries);

        let arena: TerminalContext<4> = TerminalContext::new();
        let terminal = decode_output_descriptor("crypto-output", &cbor, &arena).unwrap();
        let (multisig, name) = MultiSigDetails::from_crypto_output(&terminal).unwrap();

        let expected = MultiSigDetails::new(
            2,
            3,
            AddressType::P2wsh,
            Some(NetworkKind::Main),
            vec![
                MultiSigSigner {
                    derivation: String::from("m/48'/0'/0'/2'"),
                    fingerprint: [0x71, 0xC8, 0xBD, 0x85],
                    pubkey: String::from("xpub6ESpvmZa75rCQWKik2KoCZrjTi6xhSubZKJ25rbtgZRk2g9tZTJqubhaGD3dJeqruw9KMCaanoEfJ1PVtBXiwTuuqLVwk9ucqkRv1sKWiEC"),
                },
                MultiSigSigner {
                    derivation: String::from("m/48'/0'/0'/2'"),
                    fingerprint: [0xAB, 0x88, 0xDE, 0x89],
                    pubkey: String::from("xpub6EPJuK8Ejz82nKc7PsRgcYqdcQH9G1ZikCTasr9i79CbXxMMiPfxEyA14S6HPTHufmcQR7x8t5L3BP9tRfm9EBRBPic2xV892j9z4ePESae"),
                },
                MultiSigSigner {
                    derivation: String::from("m/48'/0'/0'/2'"),
                    fingerprint: [0xA9, 0xF9, 0x96, 0x4A],
                    pubkey: String::from("xpub6FQY5W8WygMVYY2nTP188jFHNdZfH2t9qtcS8SPpFatUGiciqUsGZpNvEa1oABEyeAsrUL2XSnvuRUdrhf5LcMXcjhrUFBcneBYYZzky3Mc"),
                },
            ],
        )
        .unwrap();
        assert_eq!(multisig, expected);
        assert_eq!("Multisig-2-of-3-Main", name);
    }

    #[test]
    fn multisig_from_crypto_output_rejects_unsorted_multi() {
        use foundation_arena::boxed::Box as ArenaBox;
        use foundation_urtypes::registry::{
            CoinInfo, CoinType, DerivedKeyRef, HDKeyRef as UrHDKeyRef, Key, KeypathRef, Keys,
            Multikey, PathComponents, Terminal, TerminalContext,
        };
        use std::num::NonZeroU32;

        // Hand-roll an unsorted `multi(...)` — our validator must reject
        // even if the rest of the shape is otherwise identical to a valid
        // sortedmulti.
        let xpub = Xpub::from_str(
            "xpub6ESpvmZa75rCQWKik2KoCZrjTi6xhSubZKJ25rbtgZRk2g9tZTJqubhaGD3dJeqruw9KMCaanoEfJ1PVtBXiwTuuqLVwk9ucqkRv1sKWiEC"
        )
        .unwrap();
        let key_data = xpub.public_key.serialize();
        let chain_code = xpub.chain_code.to_bytes();
        let path_raw: Vec<u32> = vec![48 | (1 << 31), 1 << 31, 1 << 31, 2 | (1 << 31)];
        let source_fingerprint = NonZeroU32::new(u32::from_be_bytes([0x71, 0xC8, 0xBD, 0x85])).unwrap();

        let arena: TerminalContext<4> = TerminalContext::new();
        let k = Key::HDKey(UrHDKeyRef::DerivedKey(DerivedKeyRef {
            is_private: false,
            key_data,
            chain_code: Some(chain_code),
            use_info: Some(CoinInfo::new(CoinType::BTC, CoinInfo::NETWORK_MAINNET)),
            origin: Some(KeypathRef {
                components: PathComponents::from(path_raw.as_slice()),
                source_fingerprint: Some(source_fingerprint),
                depth: Some(4),
            }),
            children: None,
            parent_fingerprint: NonZeroU32::new(u32::from_be_bytes(
                xpub.parent_fingerprint.to_bytes(),
            )),
            name: None,
            note: None,
        }));
        let keys_storage: &[Key] = &[k.clone(), k];
        let keys = Keys::from(keys_storage);
        let multi = ArenaBox::new_in(
            Terminal::Multisig(Multikey { threshold: 2, keys }),
            &arena,
        )
        .unwrap();
        let root = Terminal::WitnessScriptHash(multi);

        let err = MultiSigDetails::from_crypto_output(&root).unwrap_err();
        assert!(err.to_string().contains("sortedmulti"), "err: {err}");
    }

    #[test]
    fn multisig_from_crypto_output_rejects_duplicate_cosigners() {
        use foundation_urtypes::registry::TerminalContext;
        use foundation_urtypes::value::decode_output_descriptor;

        // `wsh(sortedmulti(2, X, X))` — the reviewer's PR #115 repro. Two
        // identical cosigner keys collapse to a single signature at
        // consensus, silently turning a nominal 2-of-2 into a 1-of-1. The
        // descriptor path catches this via miniscript's `sanity_check()`;
        // this path must reject it explicitly.
        let xpub = "xpub6ESpvmZa75rCQWKik2KoCZrjTi6xhSubZKJ25rbtgZRk2g9tZTJqubhaGD3dJeqruw9KMCaanoEfJ1PVtBXiwTuuqLVwk9ucqkRv1sKWiEC";
        let entries: &[(&str, [u8; 4], &str)] = &[
            (xpub, [0x71, 0xC8, 0xBD, 0x85], "m/48'/0'/0'/2'"),
            (xpub, [0x71, 0xC8, 0xBD, 0x85], "m/48'/0'/0'/2'"),
        ];
        let cbor = encode_wsh_sortedmulti_cbor(2, entries);

        let arena: TerminalContext<4> = TerminalContext::new();
        let terminal = decode_output_descriptor("crypto-output", &cbor, &arena).unwrap();
        let err = MultiSigDetails::from_crypto_output(&terminal).unwrap_err();
        assert!(
            err.to_string().contains("duplicate cosigner"),
            "err: {err}"
        );
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn deterministic_equation_and_hashes() {
        // These xpubs may not match their paths for real-world use, since they were derived from script type 3 before it was removed
        let descriptor_a = String::from(
            "wsh(sortedmulti(2,[71C8BD85/48h/0h/0h/2h]xpub6ESpvmZa75rCQWKik2KoCZrjTi6xhSubZKJ25rbtgZRk2g9tZTJqubhaGD3dJeqruw9KMCaanoEfJ1PVtBXiwTuuqLVwk9ucqkRv1sKWiEC/<0;1>/*,[AB88DE89/48h/0h/0h/2h]xpub6EPJuK8Ejz82nKc7PsRgcYqdcQH9G1ZikCTasr9i79CbXxMMiPfxEyA14S6HPTHufmcQR7x8t5L3BP9tRfm9EBRBPic2xV892j9z4ePESae/<0;1>/*,[A9F9964A/48h/0h/0h/2h]xpub6FQY5W8WygMVYY2nTP188jFHNdZfH2t9qtcS8SPpFatUGiciqUsGZpNvEa1oABEyeAsrUL2XSnvuRUdrhf5LcMXcjhrUFBcneBYYZzky3Mc/<0;1>/*))",
        );
        let descriptor_b = String::from(
            "wsh(sortedmulti(2,[AB88DE89/48h/0h/0h/2h]xpub6EPJuK8Ejz82nKc7PsRgcYqdcQH9G1ZikCTasr9i79CbXxMMiPfxEyA14S6HPTHufmcQR7x8t5L3BP9tRfm9EBRBPic2xV892j9z4ePESae/<0;1>/*,[71C8BD85/48h/0h/0h/2h]xpub6ESpvmZa75rCQWKik2KoCZrjTi6xhSubZKJ25rbtgZRk2g9tZTJqubhaGD3dJeqruw9KMCaanoEfJ1PVtBXiwTuuqLVwk9ucqkRv1sKWiEC/<0;1>/*,[A9F9964A/48h/0h/0h/2h]xpub6FQY5W8WygMVYY2nTP188jFHNdZfH2t9qtcS8SPpFatUGiciqUsGZpNvEa1oABEyeAsrUL2XSnvuRUdrhf5LcMXcjhrUFBcneBYYZzky3Mc/<0;1>/*))",
        );
        let (multisig_a, _) = MultiSigDetails::from_descriptor(&descriptor_a).unwrap();
        let (multisig_b, _) = MultiSigDetails::from_descriptor(&descriptor_b).unwrap();

        assert_eq!(multisig_a, multisig_b);
        assert_eq!(multisig_a.sha256(), multisig_b.sha256())
    }
}

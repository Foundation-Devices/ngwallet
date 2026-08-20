// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Stateful Miniscript wallet policies for hardware signing devices.
//!
//! The initial support boundary is deliberately narrow: checksummed P2WSH
//! descriptors using keys, thresholds, boolean composition, and one absolute
//! or relative timelock per recovery branch. Policy registration is the trust
//! anchor for address verification, change detection, and PSBT signing.

use {
    crate::{bip39::Descriptors, config::AddressType},
    bdk_wallet::{
        bitcoin::{
            Network,
            bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
            hashes::{Hash, HashEngine, sha256},
            secp256k1::{Secp256k1, Signing},
        },
        descriptor::ExtendedDescriptor,
        keys::KeyMap,
        miniscript::{
            Descriptor, DescriptorPublicKey, ForEachKey,
            policy::{Liftable, Semantic},
        },
    },
    serde::{Deserialize, Serialize},
    std::{collections::HashSet, str::FromStr},
    thiserror::Error,
};

pub mod psbt;
pub mod signing;
pub mod transport;

pub const POLICY_SCHEMA_VERSION: u32 = 1;
pub const MAX_DESCRIPTOR_BYTES: usize = 4_096;
pub const MAX_KEYS: usize = 20;

type Sem = Semantic<DescriptorPublicKey>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("invalid wallet policy: {0}")]
    Parse(String),
    #[error("unsupported wallet policy: {0}")]
    Unsupported(String),
    #[error("wallet policy does not contain a key owned by this Passport")]
    NoDeviceKey,
    #[error("wallet policy key matches the fingerprint but not the derived Passport xpub")]
    DeviceKeyMismatch,
    #[error("wallet policy network does not match the selected Bitcoin network")]
    NetworkMismatch,
    #[error("wallet-policy transaction does not match: {0}")]
    Match(String),
    #[error("wallet-policy signing failed: {0}")]
    Sign(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum SpendPathKind {
    Primary,
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct SpendPath {
    pub kind: SpendPathKind,
    pub threshold: usize,
    pub total_keys: usize,
    /// Raw BIP68 sequence value used by `older()`, if present.
    pub relative_timelock: Option<u32>,
    /// Raw nLockTime value used by `after()`, if present.
    pub absolute_timelock: Option<u32>,
    pub signer_fingerprints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct PolicySigner {
    pub fingerprint: String,
    pub derivation_path: String,
    pub xpub: String,
    pub owned_by_device: bool,
}

/// Canonical, registered wallet policy persisted with a native Bitcoin account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct WalletPolicy {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub name: String,
    /// `bitcoin`, `testnet`, `testnet4`, `signet`, or `regtest`.
    pub network: String,
    /// Canonical checksummed multipath descriptor.
    pub descriptor: String,
    pub descriptor_checksum: String,
    /// Canonical BIP388-style descriptor template and key vector.
    pub template: String,
    pub keys: Vec<String>,
    /// Foundation registration-envelope identity. Other transports may leave
    /// this empty and use the descriptor identity instead.
    #[serde(default)]
    pub policy_id: String,
    pub signers: Vec<PolicySigner>,
    pub paths: Vec<SpendPath>,
}

fn default_schema_version() -> u32 {
    POLICY_SCHEMA_VERSION
}

impl WalletPolicy {
    /// Register a checksummed descriptor after validating its supported
    /// Miniscript shape and proving ownership of exactly one extended key.
    pub fn from_descriptor<C: Signing>(
        name: impl Into<String>,
        network: Network,
        descriptor: &str,
        master: &Xpriv,
        secp: &Secp256k1<C>,
    ) -> Result<Self> {
        let parsed = parse_descriptor(descriptor, true)?;
        validate_network(&parsed, network)?;
        let fingerprint = master.fingerprint(secp);
        let signers = collect_signers(&parsed, master, secp)?;
        let owned = signers
            .iter()
            .filter(|signer| signer.owned_by_device)
            .count();
        if owned == 0 {
            return Err(Error::NoDeviceKey);
        }
        if owned != 1 {
            return Err(Error::Unsupported(
                "a policy must contain exactly one extended key owned by this Passport".into(),
            ));
        }
        let paths = analyze_paths(&parsed)?;
        let fingerprint_text = fingerprint.to_string();
        if paths.iter().any(|path| {
            path.signer_fingerprints
                .iter()
                .filter(|candidate| *candidate == &fingerprint_text)
                .count()
                > 1
        }) {
            return Err(Error::Unsupported(
                "a spending path cannot require more than one signature from this Passport".into(),
            ));
        }
        let canonical = parsed.to_string();
        let checksum = canonical
            .rsplit_once('#')
            .map(|(_, checksum)| checksum.to_owned())
            .ok_or_else(|| Error::Parse("descriptor checksum is missing".into()))?;
        let body = canonical
            .rsplit_once('#')
            .map(|(body, _)| body)
            .ok_or_else(|| Error::Parse("descriptor checksum is missing".into()))?;
        let (template, keys) = transport::descriptor_to_template(body)?;

        let policy = Self {
            schema_version: POLICY_SCHEMA_VERSION,
            name: sanitize_name(&name.into()),
            network: network.to_string(),
            descriptor: canonical,
            descriptor_checksum: checksum,
            template,
            keys,
            policy_id: String::new(),
            signers,
            paths,
        };
        // The native Bitcoin app deliberately binds coordinator exports and
        // imported policies to the selected BIP48 account number.
        policy.device_account_index()?;
        Ok(policy)
    }

    /// Register Foundation's versioned wallet-policy JSON envelope.
    pub fn from_registration<C: Signing>(
        bytes: &[u8],
        selected_network: Network,
        master: &Xpriv,
        secp: &Secp256k1<C>,
    ) -> Result<Self> {
        let registration = transport::PolicyRegistration::from_json(bytes)?;
        if registration.network.network_kind() != selected_network.into() {
            return Err(Error::NetworkMismatch);
        }
        let descriptor = registration.canonical_descriptor()?;
        let mut policy = Self::from_descriptor(
            registration.name.clone(),
            selected_network,
            &descriptor,
            master,
            secp,
        )?;
        policy.template = registration.template;
        policy.keys = registration.keys;
        policy.policy_id = registration.policy_id;
        Ok(policy)
    }

    /// Receive and change descriptors in BDK's `(external, internal)` order.
    pub fn receive_change_descriptors(&self) -> Result<(String, String)> {
        let descriptor = parse_descriptor(&self.descriptor, true)?;
        let singles = descriptor
            .into_single_descriptors()
            .map_err(|error| Error::Parse(format!("invalid multipath descriptor: {error}")))?;
        if singles.len() != 2 {
            return Err(Error::Unsupported(
                "wallet policies must contain exactly two receive/change derivation branches"
                    .into(),
            ));
        }
        Ok((singles[0].to_string(), singles[1].to_string()))
    }

    /// Public descriptor pair used by the native account wallet. Signing is
    /// intentionally performed only after registered-policy validation with
    /// the device master key, so the BDK key maps remain empty here.
    pub fn bdk_descriptors(&self) -> Result<Vec<Descriptors>> {
        let (receive, change) = self.receive_change_descriptors()?;
        let receive = ExtendedDescriptor::from_str(&receive)
            .map_err(|error| Error::Parse(format!("invalid receive descriptor: {error}")))?;
        let change = ExtendedDescriptor::from_str(&change)
            .map_err(|error| Error::Parse(format!("invalid change descriptor: {error}")))?;
        let descriptor_type = receive.desc_type();
        Ok(vec![Descriptors {
            bip: "policy".into(),
            export_addr_hint: AddressType::P2wsh,
            descriptor: (receive, KeyMap::new()),
            change_descriptor: (change, KeyMap::new()),
            descriptor_type,
        }])
    }

    /// Stable account identity independent of the user-visible name.
    pub fn account_hash(&self) -> [u8; 32] {
        let mut engine = sha256::Hash::engine();
        engine.input(b"Passport Miniscript Account\0");
        engine.input(self.network.as_bytes());
        engine.input(self.descriptor.as_bytes());
        sha256::Hash::from_engine(engine).to_byte_array()
    }

    /// Account index from the device-owned BIP48 key origin.
    pub fn device_account_index(&self) -> Result<u32> {
        let owned = self
            .signers
            .iter()
            .find(|signer| signer.owned_by_device)
            .ok_or(Error::NoDeviceKey)?;
        let path = DerivationPath::from_str(owned.derivation_path.trim_start_matches("m/"))
            .map_err(|_| Error::Parse("invalid device signer derivation path".into()))?;
        let expected_coin = if self.network == Network::Bitcoin.to_string() {
            0
        } else {
            1
        };
        match path.as_ref() {
            [
                ChildNumber::Hardened { index: 48 },
                ChildNumber::Hardened { index: coin },
                ChildNumber::Hardened { index: account },
                ChildNumber::Hardened { index: 2 },
            ] if *coin == expected_coin => Ok(*account),
            _ => Err(Error::Unsupported(
                "device policy key must use m/48'/coin_type'/account'/2'".into(),
            )),
        }
    }
}

fn parse_descriptor(text: &str, require_checksum: bool) -> Result<Descriptor<DescriptorPublicKey>> {
    let text = text.trim();
    if text.is_empty() || text.len() > MAX_DESCRIPTOR_BYTES {
        return Err(Error::Parse("descriptor is empty or too large".into()));
    }
    if require_checksum
        && !text.rsplit_once('#').is_some_and(|(_, checksum)| {
            checksum.len() == 8 && checksum.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
    {
        return Err(Error::Parse(
            "an explicit descriptor checksum is required".into(),
        ));
    }
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(text)
        .map_err(|error| Error::Parse(format!("invalid descriptor: {error}")))?;
    if !matches!(descriptor, Descriptor::Wsh(_)) {
        return Err(Error::Unsupported(
            "initial Miniscript account support is limited to P2WSH (wsh)".into(),
        ));
    }
    validate_supported_wsh(&descriptor)?;
    Ok(descriptor)
}

fn validate_supported_wsh(descriptor: &Descriptor<DescriptorPublicKey>) -> Result<()> {
    let singles = descriptor
        .clone()
        .into_single_descriptors()
        .map_err(|error| Error::Parse(format!("invalid multipath descriptor: {error}")))?;
    if singles.len() != 2 {
        return Err(Error::Unsupported(
            "wallet policy must contain exactly two receive/change branches".into(),
        ));
    }
    let policy = singles[0]
        .lift()
        .map_err(|error| Error::Parse(format!("could not lift descriptor policy: {error}")))?;
    let mut branches = Vec::new();
    collect_branches(&policy, &mut branches);
    if branches.is_empty() {
        return Err(Error::Unsupported(
            "policy has no spendable branches".into(),
        ));
    }
    let mut primary_count = 0usize;
    for branch in branches {
        validate_branch(branch)?;
        let mut relative = Vec::new();
        let mut absolute = Vec::new();
        collect_locks(branch, &mut relative, &mut absolute);
        if relative.iter().any(|lock| lock & (1 << 22) != 0) {
            return Err(Error::Unsupported(
                "time-based BIP68 recovery delays are not supported in the initial release".into(),
            ));
        }
        if relative.len() + absolute.len() > 1 {
            return Err(Error::Unsupported(
                "a recovery branch may contain only one timelock".into(),
            ));
        }
        if relative.is_empty() && absolute.is_empty() {
            primary_count += 1;
        }
    }
    if primary_count != 1 {
        return Err(Error::Unsupported(
            "policy must contain exactly one non-timelocked primary branch".into(),
        ));
    }
    Ok(())
}

fn validate_branch(semantic: &Sem) -> Result<()> {
    match semantic {
        Semantic::Unsatisfiable | Semantic::Trivial => Err(Error::Unsupported(
            "trivial and unsatisfiable branches are not supported".into(),
        )),
        Semantic::Sha256(_)
        | Semantic::Hash256(_)
        | Semantic::Ripemd160(_)
        | Semantic::Hash160(_) => Err(Error::Unsupported(
            "hashlock policies are not supported in the initial release".into(),
        )),
        Semantic::Thresh(threshold) => {
            for child in threshold.iter() {
                validate_branch(child.as_ref())?;
            }
            Ok(())
        }
        Semantic::Key(_) | Semantic::Older(_) | Semantic::After(_) => Ok(()),
    }
}

fn validate_network(descriptor: &Descriptor<DescriptorPublicKey>, network: Network) -> Result<()> {
    let mut mismatch = false;
    descriptor.for_each_key(|key| {
        match key {
            DescriptorPublicKey::XPub(key) if key.xkey.network != network.into() => mismatch = true,
            DescriptorPublicKey::MultiXPub(key) if key.xkey.network != network.into() => {
                mismatch = true
            }
            _ => {}
        }
        true
    });
    if mismatch {
        Err(Error::NetworkMismatch)
    } else {
        Ok(())
    }
}

fn collect_signers<C: Signing>(
    descriptor: &Descriptor<DescriptorPublicKey>,
    master: &Xpriv,
    secp: &Secp256k1<C>,
) -> Result<Vec<PolicySigner>> {
    let device_fingerprint = master.fingerprint(secp);
    let mut signers = Vec::new();
    let mut seen = HashSet::new();
    let mut ownership_error = None;
    descriptor.for_each_key(|key| {
        let (origin, xpub) = match key {
            DescriptorPublicKey::XPub(key) => (&key.origin, &key.xkey),
            DescriptorPublicKey::MultiXPub(key) => (&key.origin, &key.xkey),
            DescriptorPublicKey::Single(_) => {
                ownership_error = Some(Error::Unsupported(
                    "wallet policy keys must be ranged extended public keys".into(),
                ));
                return true;
            }
        };
        let Some((fingerprint, path)) = origin else {
            ownership_error = Some(Error::Unsupported(
                "every wallet policy key must include its complete origin".into(),
            ));
            return true;
        };
        let identity = format!("{fingerprint}:{path}:{xpub}");
        if !seen.insert(identity) {
            return true;
        }
        let owned = if *fingerprint == device_fingerprint {
            match master.derive_priv(secp, path) {
                Ok(derived) if Xpub::from_priv(secp, &derived) == *xpub => true,
                _ => {
                    ownership_error = Some(Error::DeviceKeyMismatch);
                    false
                }
            }
        } else {
            false
        };
        signers.push(PolicySigner {
            fingerprint: fingerprint.to_string(),
            derivation_path: format!("m/{path}"),
            xpub: xpub.to_string(),
            owned_by_device: owned,
        });
        true
    });
    if let Some(error) = ownership_error {
        return Err(error);
    }
    Ok(signers)
}

fn analyze_paths(descriptor: &Descriptor<DescriptorPublicKey>) -> Result<Vec<SpendPath>> {
    let singles = descriptor
        .clone()
        .into_single_descriptors()
        .map_err(|error| Error::Parse(format!("invalid multipath descriptor: {error}")))?;
    let semantic = singles[0]
        .lift()
        .map_err(|error| Error::Parse(format!("could not lift descriptor policy: {error}")))?;
    let mut branches = Vec::new();
    collect_branches(&semantic, &mut branches);
    Ok(branches.into_iter().map(analyze_branch).collect())
}

fn collect_branches<'a>(semantic: &'a Sem, output: &mut Vec<&'a Sem>) {
    if let Semantic::Thresh(threshold) = semantic {
        let is_or = threshold.k() == 1 && threshold.n() > 1;
        let only_keys = threshold
            .iter()
            .all(|child| matches!(child.as_ref(), Semantic::Key(_)));
        if is_or && !only_keys {
            for child in threshold.iter() {
                collect_branches(child.as_ref(), output);
            }
            return;
        }
    }
    output.push(semantic);
}

fn analyze_branch(semantic: &Sem) -> SpendPath {
    let mut relative = Vec::new();
    let mut absolute = Vec::new();
    collect_locks(semantic, &mut relative, &mut absolute);
    let fingerprints = collect_keys(semantic);
    let (threshold, total_keys) = key_threshold(semantic);
    SpendPath {
        kind: if relative.is_empty() && absolute.is_empty() {
            SpendPathKind::Primary
        } else {
            SpendPathKind::Recovery
        },
        threshold,
        total_keys,
        relative_timelock: relative.first().copied(),
        absolute_timelock: absolute.first().copied(),
        signer_fingerprints: fingerprints,
    }
}

fn collect_locks(semantic: &Sem, relative: &mut Vec<u32>, absolute: &mut Vec<u32>) {
    match semantic {
        Semantic::Older(lock) => relative.push(lock.to_consensus_u32()),
        Semantic::After(lock) => absolute.push(lock.to_consensus_u32()),
        Semantic::Thresh(threshold) => {
            for child in threshold.iter() {
                collect_locks(child.as_ref(), relative, absolute);
            }
        }
        _ => {}
    }
}

fn collect_keys(semantic: &Sem) -> Vec<String> {
    match semantic {
        Semantic::Key(key) => vec![key.master_fingerprint().to_string()],
        Semantic::Thresh(threshold) => threshold
            .iter()
            .flat_map(|child| collect_keys(child.as_ref()))
            .collect(),
        _ => Vec::new(),
    }
}

fn key_threshold(semantic: &Sem) -> (usize, usize) {
    match semantic {
        Semantic::Key(_) => (1, 1),
        Semantic::Thresh(threshold) => {
            let children = threshold
                .iter()
                .map(|child| child.as_ref())
                .collect::<Vec<_>>();
            let key_count = children
                .iter()
                .filter(|child| matches!(child, Semantic::Key(_)))
                .count();
            let lock_count = children
                .iter()
                .filter(|child| matches!(child, Semantic::Older(_) | Semantic::After(_)))
                .count();
            let nested = children.iter().find(|child| {
                !matches!(
                    child,
                    Semantic::Key(_) | Semantic::Older(_) | Semantic::After(_)
                )
            });
            if key_count > 0 && nested.is_none() {
                (threshold.k().saturating_sub(lock_count).max(1), key_count)
            } else if let Some(nested) = nested {
                key_threshold(nested)
            } else {
                (1, key_count.max(1))
            }
        }
        _ => (1, 1),
    }
}

fn sanitize_name(name: &str) -> String {
    let mut name = name
        .chars()
        .filter(|character| character.is_ascii() && !character.is_ascii_control())
        .collect::<String>();
    name.truncate(20);
    let name = name.trim();
    if name.is_empty() {
        "Wallet Policy".into()
    } else {
        name.into()
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        bdk_wallet::bitcoin::{
            bip32::DerivationPath,
            secp256k1::{All, Secp256k1},
        },
    };

    fn key_expression(secp: &Secp256k1<All>, master: &Xpriv, path: &str) -> String {
        let path = DerivationPath::from_str(path).unwrap();
        let account = master.derive_priv(secp, &path).unwrap();
        format!(
            "[{}/{}]{}/<0;1>/*",
            master.fingerprint(secp),
            path,
            Xpub::from_priv(secp, &account),
        )
    }

    fn fixture(relative: bool, account: u32) -> (String, Xpriv, Secp256k1<All>) {
        let secp = Secp256k1::new();
        let device = Xpriv::new_master(Network::Testnet, &[1; 32]).unwrap();
        let recovery_a = Xpriv::new_master(Network::Testnet, &[2; 32]).unwrap();
        let recovery_b = Xpriv::new_master(Network::Testnet, &[3; 32]).unwrap();
        let path = format!("48'/1'/{account}'/2'");
        let device_key = key_expression(&secp, &device, &path);
        let key_a = key_expression(&secp, &recovery_a, &path);
        let key_b = key_expression(&secp, &recovery_b, &path);
        let recovery = if relative {
            format!("and_v(v:multi(2,{key_a},{key_b}),older(4320))")
        } else {
            format!("and_v(v:multi(2,{key_a},{key_b}),after(1785542400))")
        };
        let raw = format!("wsh(or_d(pk({device_key}),{recovery}))");
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&raw)
            .unwrap()
            .to_string();
        (descriptor, device, secp)
    }

    #[test]
    fn registers_relative_recovery_and_uses_selected_account() {
        let (descriptor, master, secp) = fixture(true, 1);
        let policy = WalletPolicy::from_descriptor(
            "AnchorWatch",
            Network::Testnet,
            &descriptor,
            &master,
            &secp,
        )
        .unwrap();
        assert_eq!(policy.device_account_index().unwrap(), 1);
        assert_eq!(policy.paths.len(), 2);
        assert_eq!(policy.paths[0].kind, SpendPathKind::Primary);
        assert_eq!(policy.paths[1].relative_timelock, Some(4320));
        assert!(
            policy
                .receive_change_descriptors()
                .unwrap()
                .0
                .starts_with("wsh(")
        );
    }

    #[test]
    fn registers_absolute_recovery() {
        let (descriptor, master, secp) = fixture(false, 0);
        let policy =
            WalletPolicy::from_descriptor("Nunchuk", Network::Testnet, &descriptor, &master, &secp)
                .unwrap();
        assert_eq!(policy.paths[1].absolute_timelock, Some(1_785_542_400));
    }

    #[test]
    fn rejects_wrong_seed_and_missing_checksum() {
        let (descriptor, _master, secp) = fixture(true, 0);
        let wrong = Xpriv::new_master(Network::Testnet, &[9; 32]).unwrap();
        assert_eq!(
            WalletPolicy::from_descriptor("Wrong", Network::Testnet, &descriptor, &wrong, &secp),
            Err(Error::NoDeviceKey),
        );
        let body = descriptor.rsplit_once('#').unwrap().0;
        assert!(matches!(
            WalletPolicy::from_descriptor("No checksum", Network::Testnet, body, &wrong, &secp),
            Err(Error::Parse(_)),
        ));
    }

    #[test]
    fn registration_envelope_round_trip() {
        let (descriptor, master, secp) = fixture(true, 0);
        let policy =
            WalletPolicy::from_descriptor("Liana", Network::Testnet, &descriptor, &master, &secp)
                .unwrap();
        let mut registration = transport::PolicyRegistration {
            format: transport::POLICY_FORMAT.into(),
            version: transport::PROTOCOL_VERSION,
            name: policy.name.clone(),
            network: transport::PolicyNetwork::Tbtc,
            template: policy.template.clone(),
            keys: policy.keys.clone(),
            policy_id: String::new(),
        };
        registration.policy_id = registration.calculate_policy_id();
        let json = serde_json::to_vec(&registration).unwrap();
        let imported =
            WalletPolicy::from_registration(&json, Network::Testnet, &master, &secp).unwrap();
        assert_eq!(imported.descriptor, policy.descriptor);
        assert_eq!(imported.policy_id, registration.policy_id);
    }
}

mod multisig;
mod op_return;
mod p2pkh;
mod p2sh;
mod p2tr;
mod p2wpkh;
mod p2wsh;

use crate::bip32::{NgAccountPath, ParsePathError};
use bdk_wallet::bitcoin::bip32;
use bdk_wallet::bitcoin::bip32::{
    ChildNumber, DerivationPath, Fingerprint, KeySource, Xpriv, Xpub,
};
use bdk_wallet::bitcoin::psbt;
use bdk_wallet::bitcoin::psbt::Psbt;
use bdk_wallet::bitcoin::secp256k1::{PublicKey, Secp256k1, Signing, Verification, XOnlyPublicKey};
use bdk_wallet::bitcoin::{
    Address, Amount, CompressedPublicKey, Network, NetworkKind, TapLeafHash, TxIn, TxOut,
};
use bdk_wallet::descriptor::ExtendedDescriptor;
use bdk_wallet::keys::{DescriptorPublicKey, SinglePub, SinglePubKey};
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;

/// Details of a PSBT.
#[derive(Debug, Clone)]
pub struct TransactionDetails {
    /// The amount spent including change.
    pub total_with_self_send: Amount,
    /// The total self send amount, including change and transfers.
    pub total_self_send: Amount,
    /// The fee of this transaction.
    pub fee: Amount,
    /// The descriptors discovered in the PSBT.
    pub descriptors: HashSet<ExtendedDescriptor>,
    /// The inputs.
    pub inputs: Vec<PsbtInput>,
    /// The outputs.
    pub outputs: Vec<PsbtOutput>,
}

impl TransactionDetails {
    /// Total amount sent to external addresses (including OP_RETURNs).
    pub fn total(&self) -> Amount {
        self.total_with_self_send
            .checked_sub(self.total_self_send)
            .unwrap_or(Amount::ZERO)
    }

    /// Returns true if the entire transaction is a self-send.
    pub fn is_self_send(&self) -> bool {
        self.total() == Amount::ZERO
    }
}

#[derive(Debug, Clone)]
pub struct PsbtInput {
    /// Amount, in satoshis.
    pub amount: Amount,
    /// The address of the input.
    pub address: Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsbtOutput {
    /// Amount spent, in satoshis.
    pub amount: Amount,
    /// The kind of output.
    pub kind: OutputKind,
}

impl PsbtOutput {
    /// Convert this output to a Bitcoin address.
    pub fn to_address(&self) -> Option<&Address> {
        match self.kind {
            OutputKind::Change(ref address) => Some(address),
            OutputKind::Transfer { ref address, .. } => Some(address),
            OutputKind::Suspicious(ref address) => Some(address),
            OutputKind::External(ref address) => Some(address),
            _ => None,
        }
    }

    /// Returns true if the output is a self-send.
    pub fn is_self_send(&self) -> bool {
        self.kind.is_self_send()
    }
}

/// The recipient of funds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputKind {
    /// A change output.
    Change(Address),

    /// A transfer to an account of the same wallet.
    Transfer {
        /// The receiving address.
        address: Address,
        /// The account where the address belongs to.
        account: u32,
    },

    /// An address external to this wallet.
    External(Address),

    /// The receiving address is on a non-standard derivation path.
    Suspicious(Address),

    /// OP_RETURN
    OpReturn(Vec<OpReturnPart>),
}

impl OutputKind {
    /// Construct an output kind from the derivation path.
    pub fn from_derivation_path(
        path: &DerivationPath,
        expected_purpose: u32,
        network: Network,
        address: Address,
    ) -> Result<Self, Error> {
        let maybe_account_path =
            NgAccountPath::parse(path).map_err(|e| Error::invalid_path(path.clone(), e))?;
        let Some(account_path) = maybe_account_path else {
            return Ok(OutputKind::Suspicious(address));
        };

        if !account_path.matches(expected_purpose, network) {
            return Ok(OutputKind::Suspicious(address));
        }

        if !account_path.is_for_address() {
            return Ok(OutputKind::Suspicious(address));
        }

        let is_change = account_path.is_change().unwrap_or(false);
        Ok(if is_change {
            OutputKind::Change(address)
        } else {
            OutputKind::Transfer {
                address,
                account: account_path.account,
            }
        })
    }

    /// Returns true if the output kind is a self-send.
    pub fn is_self_send(&self) -> bool {
        match self {
            OutputKind::Change(_) | OutputKind::Transfer { .. } | OutputKind::Suspicious(_) => true,
            OutputKind::External(_) | OutputKind::OpReturn(_) => false,
        }
    }
}

/// Parts of an OP_RETURN output type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpReturnPart {
    /// An UTF-8 message pushed onto the stack.
    Message(String),
    /// A binary part pushed onto the stack, not valid UTF-8.
    Binary(Vec<u8>),
    /// Rest of unknown instructions.
    Unknown(Vec<u8>),
}

/// Errors that can happen during PSBT validation.
#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to derive key: {0}")]
    Bip32(#[from] bip32::Error),

    #[error("PSBT error: {0}")]
    Psbt(#[from] psbt::Error),

    /// An extended public key is missing.
    #[error("missing global extended public key for derivation path: {0}")]
    MissingGlobalXpub(DerivationPath),

    /// The network of the PSBT couldn't be determined because more than one
    /// network was used in xpubs or derivation paths.
    #[error("the Bitcoin network used in the PSBT is not consistent")]
    NetworkInconsistency,

    /// A standard derivation path is invalid.
    #[error("the derivation path ({error}) in the PSBT does not conform to standard: {error}")]
    InvalidDerivationPath {
        path: DerivationPath,
        error: ParsePathError,
    },

    /// One of the public keys in the PSBT doesn't match our derivation.
    #[error("fraudulent key")]
    FraudulentKey,

    /// No inputs in the PSBT match the wallet fingerprint.
    #[error("transaction cannot be signed, no input matches the wallet fingerprint")]
    CantSign,

    /// Failed to calculate taproot key
    #[error("failed to calculate taproot key")]
    InvalidTaprootKey,
    // Input validation errors.
    /// Information missing for input.
    #[error("the input number {index} is missing")]
    MissingInput { index: usize },

    /// Funding UTXO information missing for input.
    #[error("the input number {index} is missing")]
    MissingInputFundingUtxo { index: usize },

    #[error("the witness script of output number {index} is invalid")]
    InvalidWitnessScript { index: usize },

    #[error("the redeem script of output number {index} is invalid")]
    InvalidRedeemScript { index: usize },

    /// The input is fraudulent.
    #[error("the input number {index} is fraudulent")]
    FraudulentInput { index: usize },

    // Output validation errors.
    /// Information missing for output.
    #[error("the output number {index} is missing")]
    MissingOutput { index: usize },

    /// The script of the output is unknown and can't be validated or shown
    /// to the user if not a change address.
    #[error("the output number {index} script type is unknown")]
    UnknownOutputScript { index: usize },

    /// The PSBT specifies multiple keys for an output that belongs to us
    /// but the script type for the output is single-sig only, e.g. P2PKH,
    /// P2WPKH.
    #[error("multiple keys for output number {index} were not expected")]
    MultipleKeysNotExpected { index: usize },

    #[error("no keys found for output number {index}")]
    ExpectedKeys { index: usize },

    /// The change output is fraudulent.
    #[error("the output number {index} is fraudulent")]
    FraudulentOutput { index: usize },

    /// The change output type is deprecated (P2PK).
    #[error("the output number {index} uses a deprecated output type")]
    DeprecatedOutputType { index: usize },

    #[error("the output number {index} does not have a redeem script")]
    MissingRedeemScript { index: usize },

    #[error("the output number {index} does not have a witness script")]
    MissingWitnessScript { index: usize },

    // TODO(jeandudey): Remove this.
    #[error("not yet implemented")]
    Unimplemented,
}

impl Error {
    fn invalid_path(path: DerivationPath, error: ParsePathError) -> Self {
        Self::InvalidDerivationPath { path, error }
    }
}

/// Validate the network of a PSBT.
pub fn validate_network(psbt: &Psbt) -> Result<Option<NetworkKind>, Error> {
    let mut maybe_network =
        psbt.xpub
            .iter()
            .try_fold(None, |mut maybe_network, (xpub, source)| {
                let network = *maybe_network.get_or_insert(xpub.network);
                if network != xpub.network {
                    return Err(Error::NetworkInconsistency);
                }

                // In case we have a BIP-0044 like path validate that coin type
                // and the Xpub network kind match.
                let maybe_path = NgAccountPath::parse(&source.1)
                    .map_err(|e| Error::invalid_path(source.1.clone(), e))?;
                if let Some(path) = maybe_path {
                    // Only return an error if coin type is a standard one.
                    if let Some(false) = path.is_valid_for_network_kind(xpub.network) {
                        return Err(Error::NetworkInconsistency);
                    }
                }

                Ok(Some(network))
            })?;

    // We can only determine the network from the path if it is
    // account-like as here we only have public keys instead of xpubs.
    for input in psbt.inputs.iter() {
        maybe_network = validate_bip32_derivation_network(&input.bip32_derivation, maybe_network)?;
        maybe_network = validate_tap_key_origins_network(&input.tap_key_origins, maybe_network)?;
    }

    for output in psbt.outputs.iter() {
        maybe_network = validate_bip32_derivation_network(&output.bip32_derivation, maybe_network)?;
        maybe_network = validate_tap_key_origins_network(&output.tap_key_origins, maybe_network)?;
    }

    Ok(maybe_network)
}

fn validate_bip32_derivation_network(
    bip32_derivation: &BTreeMap<PublicKey, KeySource>,
    maybe_network: Option<NetworkKind>,
) -> Result<Option<NetworkKind>, Error> {
    bip32_derivation
        .iter()
        .try_fold(maybe_network, |maybe_network, (_public_key, source)| {
            validate_key_source_network(maybe_network, source)
        })
}

fn validate_tap_key_origins_network(
    tap_key_origins: &BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    maybe_network: Option<NetworkKind>,
) -> Result<Option<NetworkKind>, Error> {
    tap_key_origins.iter().try_fold(
        maybe_network,
        |maybe_network, (_x_only_public_key, (_leaf_hashes, source))| {
            validate_key_source_network(maybe_network, source)
        },
    )
}

fn validate_key_source_network(
    mut maybe_network: Option<NetworkKind>,
    source: &KeySource,
) -> Result<Option<NetworkKind>, Error> {
    let maybe_path =
        NgAccountPath::parse(&source.1).map_err(|e| Error::invalid_path(source.1.clone(), e))?;

    let Some(path) = maybe_path else {
        return Ok(maybe_network);
    };

    if let Some(network_kind) = path.to_network_kind() {
        // Highly unlikely that maybe_network is not set already, but
        // do so if there weren't any global xpubs.
        let network = *maybe_network.get_or_insert(network_kind);

        if let Some(false) = path.is_valid_for_network_kind(network) {
            return Err(Error::NetworkInconsistency);
        }
    }

    Ok(maybe_network)
}

/// Validate a PSBT against the master key.
pub fn validate<C>(
    secp: &Secp256k1<C>,
    master_key: &Xpriv,
    psbt: &Psbt,
    network: Network,
) -> Result<TransactionDetails, Error>
where
    C: Signing + Verification,
{
    // SAFETY: This is allowed because the implementation of ExtendedDescriptor
    // correctly implements hash with interior mutability as Tr does not hash
    // the spend_info field which can be mutated.
    //
    // See: <https://rust-lang.github.io/rust-clippy/master/index.html#mutable_key_type>.
    #[allow(clippy::mutable_key_type)]
    let mut descriptors = HashSet::new();
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();

    let fingerprint = master_key.fingerprint(secp);

    // TODO: After validating these xpubs use these to validate further
    // derivations in the inputs and outputs, to also verify the keys that
    // aren't "ours" to avoid creating spending from/to a multisig where
    // the other keys don't belong to the parties here.
    //
    // Of course the caller must also make sure that the descriptors we
    // return for multisig are valid too.
    let maybe_valid = validate_xpubs(secp, master_key, &psbt.xpub, fingerprint)?;
    match maybe_valid {
        Some(true) => (),
        Some(false) => return Err(Error::FraudulentKey),
        // Some PSBT creators don't specify global xpubs, instead each input
        // and output specify the BIP-0032 derivations on bip32_derivations
        // and/or tap_key_origins.
        None => (),
    }

    let is_fingerprint_present = psbt.inputs.iter().any(|input| {
        let has_bip32 = input
            .bip32_derivation
            .iter()
            .any(|(_, (v, _))| *v == fingerprint);

        let has_tap = input
            .tap_key_origins
            .iter()
            .any(|(_, (_, (v, _)))| *v == fingerprint);

        has_bip32 || has_tap
    });

    if !is_fingerprint_present {
        return Err(Error::CantSign);
    }

    for (i, input) in psbt.inputs.iter().enumerate() {
        let Some(txin) = psbt.unsigned_tx.input.get(i) else {
            return Err(Error::MissingInput { index: i });
        };

        if let Some(non_witness_utxo) = input.non_witness_utxo.as_ref() {
            let computed_txid = non_witness_utxo.compute_txid();
            if computed_txid != txin.previous_output.txid {
                return Err(Error::FraudulentInput { index: i });
            }
        }

        let has_our_public_keys =
            validate_public_keys(secp, master_key, &input.bip32_derivation, fingerprint)
                .map_err(Error::from)
                .and_then(|maybe_valid| match maybe_valid {
                    Some(true) => Ok(true),
                    Some(false) => Err(Error::FraudulentKey),
                    None => Ok(false),
                })?;

        let has_our_x_only_public_keys =
            validate_x_only_public_keys(secp, master_key, &input.tap_key_origins, fingerprint)
                .map_err(Error::from)
                .and_then(|maybe_valid| match maybe_valid {
                    Some(true) => Ok(true),
                    Some(false) => Err(Error::FraudulentKey),
                    None => Ok(false),
                })?;

        let is_our_input = has_our_public_keys || has_our_x_only_public_keys;

        if !is_our_input {
            continue;
        }

        let funding_utxo =
            funding_utxo(input, txin).ok_or(Error::MissingInputFundingUtxo { index: i })?;

        if funding_utxo.script_pubkey.is_p2tr() {
            // Only single-sig P2TR supported for now.
            if input.tap_key_origins.len() != 1 {
                return Err(Error::MultipleKeysNotExpected { index: i });
            }

            let (x_only_pk, (_, source)) = input.tap_key_origins.first_key_value().unwrap();
            let address = Address::p2tr(secp, *x_only_pk, None, network);
            if !address.matches_script_pubkey(&funding_utxo.script_pubkey) {
                return Err(Error::FraudulentInput { index: i });
            }

            inputs.push(PsbtInput {
                amount: funding_utxo.value,
                address,
            });
            descriptors.insert(p2tr::descriptor(secp, master_key, &source.1, network));
        } else if funding_utxo.script_pubkey.is_p2wpkh() {
            if input.bip32_derivation.len() != 1 {
                return Err(Error::MultipleKeysNotExpected { index: i });
            }

            let (pk, source) = input.bip32_derivation.first_key_value().unwrap();

            let pk = CompressedPublicKey(*pk);
            let address = Address::p2wpkh(&pk, network);
            if !address.matches_script_pubkey(&funding_utxo.script_pubkey) {
                return Err(Error::FraudulentInput { index: i });
            }

            inputs.push(PsbtInput {
                amount: funding_utxo.value,
                address,
            });
            descriptors.insert(p2wpkh::descriptor(secp, master_key, &source.1, network));
        } else if funding_utxo.script_pubkey.is_p2pkh() {
            if input.bip32_derivation.len() != 1 {
                return Err(Error::MultipleKeysNotExpected { index: i });
            }

            let (pk, source) = input.bip32_derivation.first_key_value().unwrap();

            let pk = CompressedPublicKey(*pk);
            let address = Address::p2pkh(pk, network);
            if !address.matches_script_pubkey(&funding_utxo.script_pubkey) {
                return Err(Error::FraudulentInput { index: i });
            }

            inputs.push(PsbtInput {
                amount: funding_utxo.value,
                address,
            });
            descriptors.insert(p2pkh::descriptor(secp, master_key, &source.1, network));
        } else if funding_utxo.script_pubkey.is_p2wsh() {
            // TODO: Construct the address to check that it matches script_pubkey.

            if let Some(witness_script) = input.witness_script.as_ref() {
                if witness_script.is_multisig() {
                    let required_signers = multisig::disassemble(witness_script).unwrap();
                    descriptors.insert(p2wsh::multisig_descriptor(
                        required_signers,
                        &psbt.xpub,
                        &input.bip32_derivation,
                    )?);
                } else {
                    return Err(Error::Unimplemented);
                }
            } else {
                return Err(Error::MissingWitnessScript { index: i });
            }
        } else if funding_utxo.script_pubkey.is_p2sh() {
            if let Some(redeem_script) = input.redeem_script.as_ref() {
                if redeem_script.is_p2wpkh() {
                    if input.bip32_derivation.len() != 1 {
                        return Err(Error::MultipleKeysNotExpected { index: i });
                    }

                    let (pk, source) = input.bip32_derivation.first_key_value().unwrap();

                    let pk = CompressedPublicKey(*pk);
                    let address = Address::p2shwpkh(&pk, network);
                    if !address.matches_script_pubkey(&funding_utxo.script_pubkey) {
                        return Err(Error::FraudulentInput { index: i });
                    }

                    inputs.push(PsbtInput {
                        amount: funding_utxo.value,
                        address,
                    });
                    descriptors.insert(p2sh::p2shwpkh_descriptor(
                        secp, master_key, &source.1, network,
                    ));
                } else if redeem_script.is_p2wsh() {
                    if let Some(witness_script) = input.witness_script.as_ref() {
                        if witness_script.is_multisig() {
                            let required_signers = multisig::disassemble(witness_script).unwrap();
                            descriptors.insert(p2sh::wsh_multisig_descriptor(
                                required_signers,
                                &psbt.xpub,
                                &input.bip32_derivation,
                            )?);
                        } else {
                            return Err(Error::Unimplemented);
                        }
                    } else {
                        return Err(Error::MissingWitnessScript { index: i });
                    }
                } else {
                    // TODO: Change to UnknownInputScript
                    return Err(Error::UnknownOutputScript { index: i });
                }
            } else {
                return Err(Error::InvalidRedeemScript { index: i });
            }
        }
    }

    let mut total_with_self_send = Amount::ZERO;
    let mut total_self_send = Amount::ZERO;
    for (i, output) in psbt.outputs.iter().enumerate() {
        let Some(txout) = psbt.unsigned_tx.output.get(i) else {
            return Err(Error::MissingOutput { index: i });
        };

        let has_our_public_keys =
            validate_public_keys(secp, master_key, &output.bip32_derivation, fingerprint)
                .map_err(Error::from)
                .and_then(|maybe_valid| match maybe_valid {
                    Some(true) => Ok(true),
                    Some(false) => Err(Error::FraudulentKey),
                    None => Ok(false),
                })?;

        let has_our_x_only_public_keys =
            validate_x_only_public_keys(secp, master_key, &output.tap_key_origins, fingerprint)
                .map_err(Error::from)
                .and_then(|maybe_valid| match maybe_valid {
                    Some(true) => Ok(true),
                    Some(false) => Err(Error::FraudulentKey),
                    None => Ok(false),
                })?;

        let is_internal = has_our_public_keys || has_our_x_only_public_keys;

        let output_details = validate_output(secp, output, txout, network, is_internal, i)?;

        total_with_self_send += output_details.amount;
        if output_details.is_self_send() {
            total_self_send += output_details.amount;
        }

        outputs.push(output_details);
    }

    Ok(TransactionDetails {
        total_with_self_send,
        total_self_send,
        fee: psbt.fee()?,
        descriptors,
        inputs,
        outputs,
    })
}

/// Validate that the extended public keys in `xpubs` are correctly derived
/// from the `master_key`.
///
/// The `fingerprint` parameter should be equal to `master_key.fingerprint()`,
/// but it is passed as a parameter to avoid calculating it each time since it
/// involves converting the Xpriv to an Xpub and calculating the identifier
/// which can be time consuming.
///
/// # Return
///
/// - `Ok(None)`: the `fingerprint` didn't match any of the xpubs.
/// - `Ok(Some(true))`: the `fingerprint` matched at least one of the xpubs and
///   the derived xpubs matched correctly.
/// - `Ok(Some(false))`: the `fingerprint` matched at least one of the xpubs but
///   the derived xpubs didn't match, highly likely this is fraudulent.
/// - `Err(_)`: failed to derive one of the xpubs from the master key.
fn validate_xpubs<C>(
    secp: &Secp256k1<C>,
    master_key: &Xpriv,
    xpubs: &BTreeMap<Xpub, KeySource>,
    fingerprint: Fingerprint,
) -> Result<Option<bool>, bip32::Error>
where
    C: Signing,
{
    debug_assert!(is_master_key(master_key));
    debug_assert!(master_key.fingerprint(secp) == fingerprint);

    let mut fingerprint_seen = false;
    for (xpub, source) in keys_iterator(xpubs, fingerprint) {
        debug_assert!(source.0 == fingerprint);
        fingerprint_seen = true;

        let derived_xpriv = master_key.derive_priv(secp, &source.1)?;
        let derived_xpub = Xpub::from_priv(secp, &derived_xpriv);
        if xpub != &derived_xpub {
            return Ok(Some(false));
        }
    }

    if fingerprint_seen {
        Ok(Some(true))
    } else {
        Ok(None)
    }
}

/// Returns true if the `xpriv` is a master key.
fn is_master_key(xpriv: &Xpriv) -> bool {
    xpriv.depth == 0
        && xpriv.parent_fingerprint.as_bytes() == &[0; 4]
        && xpriv.child_number == ChildNumber::Normal { index: 0 }
}

/// Validate that the public keys in `bip32_derivations` are correctly
/// derived from the `master_key`.
///
/// # Return
///
/// This has the same behaviour as in [`validate_xpubs`].
fn validate_public_keys<C>(
    secp: &Secp256k1<C>,
    master_key: &Xpriv,
    bip32_derivations: &BTreeMap<PublicKey, KeySource>,
    fingerprint: Fingerprint,
) -> Result<Option<bool>, bip32::Error>
where
    C: Signing,
{
    debug_assert!(is_master_key(master_key));
    debug_assert!(master_key.fingerprint(secp) == fingerprint);

    let mut fingerprint_seen = false;
    for (pk, source) in keys_iterator(bip32_derivations, fingerprint) {
        debug_assert!(source.0 == fingerprint);
        fingerprint_seen = true;

        let derived_xpriv = master_key.derive_priv(secp, &source.1)?;
        let derived_xpub = Xpub::from_priv(secp, &derived_xpriv);
        if pk != &derived_xpub.public_key {
            return Ok(Some(false));
        }
    }

    if fingerprint_seen {
        Ok(Some(true))
    } else {
        Ok(None)
    }
}

/// Validate that the X-only public keys in `tap_key_origins` are correctly
/// derived from the `master_key`.
///
/// # Return
///
/// This has the same behaviour as in [`validate_xpubs`].
fn validate_x_only_public_keys<C>(
    secp: &Secp256k1<C>,
    master_key: &Xpriv,
    tap_key_origins: &BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    fingerprint: Fingerprint,
) -> Result<Option<bool>, bip32::Error>
where
    C: Signing,
{
    debug_assert!(is_master_key(master_key));
    debug_assert!(master_key.fingerprint(secp) == fingerprint);

    let mut fingerprint_seen = false;
    for (x_only_pk, (_, source)) in x_only_keys_iterator(tap_key_origins, fingerprint) {
        debug_assert!(source.0 == fingerprint);
        fingerprint_seen = true;

        let derived_xpriv = master_key.derive_priv(secp, &source.1)?;
        let derived_xpub = Xpub::from_priv(secp, &derived_xpriv);
        if x_only_pk != &derived_xpub.public_key.x_only_public_key().0 {
            return Ok(Some(false));
        }
    }

    if fingerprint_seen {
        Ok(Some(true))
    } else {
        Ok(None)
    }
}

/// Returns an iterator over the extended public keys matching the fingerprint.
fn keys_iterator<K>(
    keys: &BTreeMap<K, KeySource>,
    fingerprint: Fingerprint,
) -> impl Iterator<Item = (&K, &KeySource)> {
    keys.iter()
        .filter(move |(_, source)| fingerprint == source.0)
}

/// Returns an iterator over the x-only public keys matching the fingerprint.
fn x_only_keys_iterator<K>(
    keys: &BTreeMap<K, (Vec<TapLeafHash>, KeySource)>,
    fingerprint: Fingerprint,
) -> impl Iterator<Item = (&K, &(Vec<TapLeafHash>, KeySource))> {
    keys.iter()
        .filter(move |(_, (_, source))| fingerprint == source.0)
}

fn funding_utxo<'a>(input: &'a psbt::Input, txin: &'a TxIn) -> Option<&'a TxOut> {
    match (input.witness_utxo.as_ref(), input.non_witness_utxo.as_ref()) {
        (Some(witness_utxo), _) => Some(witness_utxo),
        (None, Some(non_witness_utxo)) => {
            let vout = txin.previous_output.vout as usize;
            non_witness_utxo.output.get(vout)
        }
        (None, None) => None,
    }
}

/// Validate a PSBT output.
fn validate_output<C>(
    secp: &Secp256k1<C>,
    output: &psbt::Output,
    txout: &TxOut,
    network: Network,
    is_internal: bool,
    index: usize,
) -> Result<PsbtOutput, Error>
where
    C: Verification,
{
    if !is_internal {
        let kind = if txout.script_pubkey.is_op_return() {
            op_return::parse(txout)
        } else {
            let address = Address::from_script(&txout.script_pubkey, network.params())
                .map_err(|_| Error::UnknownOutputScript { index })?;

            PsbtOutput {
                amount: txout.value,
                kind: OutputKind::External(address),
            }
        };

        return Ok(kind);
    }

    if txout.script_pubkey.is_p2tr() {
        p2tr::validate_output(secp, output, txout, network, index)
    } else if txout.script_pubkey.is_p2wpkh() {
        p2wpkh::validate_output(output, txout, network, index)
    } else if txout.script_pubkey.is_p2wsh() {
        p2wsh::validate_output(output, txout, network, index)
    } else if txout.script_pubkey.is_p2pkh() {
        p2pkh::validate_output(output, txout, network, index)
    } else if txout.script_pubkey.is_p2sh() {
        p2sh::validate_output(output, txout, network, index)
    } else if txout.script_pubkey.is_p2pk() {
        // Don't even try to validate this, just error out if the PSBT contains
        // this output type.
        Err(Error::DeprecatedOutputType { index })
    } else {
        Err(Error::UnknownOutputScript { index })
    }
}

pub(crate) fn derive_account_xpub<C>(
    secp: &Secp256k1<C>,
    master_key: &Xpriv,
    path: impl AsRef<[ChildNumber]>,
) -> Xpub
where
    C: Signing,
{
    let prefix = &path.as_ref()[..3];
    let derived_xpriv = master_key.derive_priv(secp, &prefix).unwrap();
    Xpub::from_priv(secp, &derived_xpriv)
}

pub(crate) fn derive_full_descriptor_pubkey<C>(
    secp: &Secp256k1<C>,
    master_key: &Xpriv,
    path: impl AsRef<[ChildNumber]>,
) -> DescriptorPublicKey
where
    C: Signing,
{
    let derived_xpriv = master_key.derive_priv(secp, &path).unwrap();
    let derived_xpub = Xpub::from_priv(secp, &derived_xpriv);
    DescriptorPublicKey::Single(SinglePub {
        origin: Some((master_key.fingerprint(secp), path.as_ref().into())),
        key: SinglePubKey::FullKey(derived_xpub.to_pub().into()),
    })
}

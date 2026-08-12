use crate::bip32::NgAccountPath;
use crate::config::MultiSigDetails;
use crate::psbt::{
    Error, OutputKind, PsbtOutput, derive_account_xpub, derive_full_descriptor_pubkey,
    multisig, registered_multisig_output_kind, sort_keys,
};
use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::bip32::{ChildNumber, DerivationPath, KeySource, Xpriv, Xpub};
use bdk_wallet::bitcoin::psbt;
use bdk_wallet::bitcoin::secp256k1::{PublicKey, Secp256k1, Signing, Verification};
use bdk_wallet::bitcoin::{Address, CompressedPublicKey, Network, TxOut};
use bdk_wallet::descriptor::{Descriptor, ExtendedDescriptor, Segwitv0};
use bdk_wallet::keys::DescriptorPublicKey;
use bdk_wallet::miniscript::descriptor::{DescriptorXKey, Wildcard};
use bdk_wallet::miniscript::descriptor::{Sh, Wpkh};
use bdk_wallet::miniscript::{ForEachKey, Miniscript};
use bdk_wallet::template::Bip49Public;
use std::collections::BTreeMap;

pub fn validate_output<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    output: &psbt::Output,
    txout: &TxOut,
    network: Network,
    index: usize,
    registered_multisig: Option<&MultiSigDetails>,
) -> Result<PsbtOutput, Error> {
    debug_assert!(txout.script_pubkey.is_p2sh());

    let redeem_script = output
        .redeem_script
        .as_ref()
        .ok_or_else(|| Error::MissingRedeemScript { index })?;

    if redeem_script.is_p2wpkh() {
        validate_p2wpkh_nested_in_p2sh_output(output, txout, network, index)
    } else if redeem_script.is_p2wsh() {
        let witness_script = output
            .witness_script
            .as_ref()
            .ok_or_else(|| Error::MissingWitnessScript { index })?;

        let ms = Miniscript::<_, Segwitv0>::parse(witness_script)
            .map_err(|_| Error::InvalidWitnessScript { index })?;
        let descriptor = Sh::new_wsh(ms)
            .map(Descriptor::Sh)
            .map_err(|_| Error::InvalidWitnessScript { index })?;

        // Verify that all keys in the descriptor are in the bip32_derivation map
        // which should have been validated already.
        let are_keys_valid =
            descriptor.for_each_key(|pk| output.bip32_derivation.contains_key(&pk.inner));
        if !are_keys_valid {
            return Err(Error::FraudulentOutput { index });
        }

        let address = descriptor
            .address(network)
            .map_err(|_| Error::InvalidWitnessScript { index })?;
        if !address.matches_script_pubkey(&txout.script_pubkey) {
            return Err(Error::FraudulentOutput { index });
        }

        let kind = registered_multisig
            .and_then(|multisig| {
                registered_multisig_output_kind(
                    secp,
                    multisig,
                    &output.bip32_derivation,
                    &txout.script_pubkey,
                    address.clone(),
                )
            })
            .unwrap_or(OutputKind::External(address));

        Ok(PsbtOutput {
            amount: txout.value,
            kind,
        })
    } else if redeem_script.is_multisig() {
        validate_legacy_multisig_output(
            secp,
            output,
            txout,
            redeem_script,
            network,
            index,
            registered_multisig,
        )
    } else {
        Err(Error::InvalidRedeemScript { index })
    }
}

fn validate_legacy_multisig_output<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    output: &psbt::Output,
    txout: &TxOut,
    redeem_script: &bdk_wallet::bitcoin::Script,
    network: Network,
    index: usize,
    registered_multisig: Option<&MultiSigDetails>,
) -> Result<PsbtOutput, Error> {
    multisig::disassemble_sorted(redeem_script)
        .map_err(|_| Error::InvalidMultisigScript { index })?;
    let address =
        Address::p2sh(redeem_script, network).map_err(|_| Error::InvalidRedeemScript { index })?;
    if !address.matches_script_pubkey(&txout.script_pubkey) {
        return Err(Error::FraudulentOutput { index });
    }

    let kind = registered_multisig
        .and_then(|multisig| {
            registered_multisig_output_kind(
                secp,
                multisig,
                &output.bip32_derivation,
                &txout.script_pubkey,
                address.clone(),
            )
        })
        .unwrap_or(OutputKind::External(address));
    Ok(PsbtOutput {
        amount: txout.value,
        kind,
    })
}

fn validate_p2wpkh_nested_in_p2sh_output(
    output: &psbt::Output,
    txout: &TxOut,
    network: Network,
    index: usize,
) -> Result<PsbtOutput, Error> {
    if output.bip32_derivation.len() != 1 {
        return Err(Error::MultipleKeysNotExpected { index });
    }

    let (pk, source) = output
        .bip32_derivation
        .first_key_value()
        .expect("the previous statement checks for at least one entry");

    // Check that the script_pubkey matches our computed address.
    let compressed_pk = CompressedPublicKey(*pk);
    let address = Address::p2shwpkh(&compressed_pk, network);
    if !address.matches_script_pubkey(&txout.script_pubkey) {
        return Err(Error::FraudulentOutput { index });
    }

    Ok(PsbtOutput {
        amount: txout.value,
        kind: OutputKind::from_derivation_path(&source.1, 49, network, address)?,
    })
}

/// Compute the account descriptor for P2WPKH from the `path` derivation path.
pub fn p2shwpkh_descriptor<C>(
    secp: &Secp256k1<C>,
    master_key: &Xpriv,
    path: impl AsRef<[ChildNumber]>,
    network: Network,
) -> ExtendedDescriptor
where
    C: Signing,
{
    match NgAccountPath::parse(&path) {
        Ok(Some(account_path)) => {
            // Not a valid BIP-0049 derivation path, just return the full derivation path and
            // the computed public key.
            if !account_path.matches(49, network) || !account_path.is_for_address() {
                let pk = derive_full_descriptor_pubkey(secp, master_key, path);
                return ExtendedDescriptor::new_sh_with_wpkh(Wpkh::new(pk).unwrap());
            }

            let xpub = derive_account_xpub(secp, master_key, path);
            Bip49Public(
                xpub,
                master_key.fingerprint(secp),
                account_path
                    .keychain_kind()
                    .expect("is_for_address checks for this"),
            )
            .build_account(network, account_path.account)
            .unwrap()
            .0
        }
        _ => {
            let pk = derive_full_descriptor_pubkey(secp, master_key, path);
            ExtendedDescriptor::new_sh_with_wpkh(Wpkh::new(pk).unwrap())
        }
    }
}

/// Returns the descriptor for a P2WSH wrapped in P2SH multisig account.
///
/// The `required_signers` parameter must be known before hand, by for
/// example, disassembling the multisig script.
pub fn wsh_multisig_descriptor(
    required_signers: u8,
    global_xpubs: &BTreeMap<Xpub, KeySource>,
    bip32_derivations: &BTreeMap<PublicKey, KeySource>,
) -> Result<[ExtendedDescriptor; 2], Error> {
    let (external_keys, internal_keys) = multisig_descriptor_keys(global_xpubs, bip32_derivations)?;

    let external_descriptor =
        ExtendedDescriptor::new_sh_wsh_sortedmulti(usize::from(required_signers), external_keys)
            .map_err(|_| Error::InvalidMultisigDescriptor)?;
    let internal_descriptor =
        ExtendedDescriptor::new_sh_wsh_sortedmulti(usize::from(required_signers), internal_keys)
            .map_err(|_| Error::InvalidMultisigDescriptor)?;

    Ok([external_descriptor, internal_descriptor])
}

/// Returns the external and internal descriptors for a legacy P2SH
/// `sortedmulti` account.
pub fn legacy_multisig_descriptor(
    required_signers: u8,
    global_xpubs: &BTreeMap<Xpub, KeySource>,
    bip32_derivations: &BTreeMap<PublicKey, KeySource>,
) -> Result<[ExtendedDescriptor; 2], Error> {
    let (external_keys, internal_keys) = multisig_descriptor_keys(global_xpubs, bip32_derivations)?;

    let external_descriptor =
        ExtendedDescriptor::new_sh_sortedmulti(usize::from(required_signers), external_keys)
            .map_err(|_| Error::InvalidMultisigDescriptor)?;
    let internal_descriptor =
        ExtendedDescriptor::new_sh_sortedmulti(usize::from(required_signers), internal_keys)
            .map_err(|_| Error::InvalidMultisigDescriptor)?;

    Ok([external_descriptor, internal_descriptor])
}

fn multisig_descriptor_keys(
    global_xpubs: &BTreeMap<Xpub, KeySource>,
    bip32_derivations: &BTreeMap<PublicKey, KeySource>,
) -> Result<(Vec<DescriptorPublicKey>, Vec<DescriptorPublicKey>), Error> {
    // Find the account Xpubs in the global Xpub map of the PSBT.
    let xpubs = bip32_derivations
        .iter()
        .map(|(_, (subpath_fingerprint, subpath))| {
            global_xpubs
                .iter()
                .find(|(_, (global_fingerprint, global_path))| {
                    subpath_fingerprint == global_fingerprint
                        && subpath.as_ref().starts_with(global_path.as_ref())
                })
                .ok_or_else(|| Error::MissingGlobalXpub(subpath.clone()))
        });

    let mut external_keys = Vec::new();
    let mut internal_keys = Vec::new();
    for maybe_xpub in xpubs {
        let (xpub, source) = maybe_xpub?;

        let external_key = DescriptorPublicKey::XPub(DescriptorXKey {
            origin: Some(source.clone()),
            xkey: *xpub,
            derivation_path: DerivationPath::from(vec![ChildNumber::Normal { index: 0 }]),
            wildcard: Wildcard::Unhardened,
        });

        let internal_key = DescriptorPublicKey::XPub(DescriptorXKey {
            origin: Some(source.clone()),
            xkey: *xpub,
            derivation_path: DerivationPath::from(vec![ChildNumber::Normal { index: 1 }]),
            wildcard: Wildcard::Unhardened,
        });

        external_keys.push(external_key);
        internal_keys.push(internal_key);
    }

    sort_keys(&mut external_keys);
    sort_keys(&mut internal_keys);

    Ok((external_keys, internal_keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AddressType, MultiSigSigner};
    use bdk_wallet::bitcoin::hashes::{Hash, sha256};
    use bdk_wallet::bitcoin::opcodes::all::{OP_EQUAL, OP_HASH160, OP_PUSHBYTES_0, OP_RETURN};
    use bdk_wallet::bitcoin::{Amount, Script, ScriptBuf, WScriptHash};

    fn p2sh_script_pubkey() -> ScriptBuf {
        let mut bytes = Vec::with_capacity(23);
        bytes.push(OP_HASH160.to_u8());
        bytes.push(20);
        bytes.extend_from_slice(&[0u8; 20]);
        bytes.push(OP_EQUAL.to_u8());
        ScriptBuf::from_bytes(bytes)
    }

    fn p2wsh_redeem_script() -> ScriptBuf {
        // OP_0 <32-byte witness program> -> matches Script::is_p2wsh().
        let inner = sha256::Hash::const_hash(b"fixture witness script");
        let hash = WScriptHash::from_byte_array(inner.to_byte_array());
        ScriptBuf::new_p2wsh(&hash)
    }

    fn output_with_scripts(
        redeem_script: ScriptBuf,
        witness_script: Option<ScriptBuf>,
    ) -> psbt::Output {
        psbt::Output {
            redeem_script: Some(redeem_script),
            witness_script,
            ..Default::default()
        }
    }

    fn txout() -> TxOut {
        TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: p2sh_script_pubkey(),
        }
    }

    fn registered_legacy_output(
        seed_offset: u8,
        keychain: KeychainKind,
    ) -> (psbt::Output, TxOut, MultiSigDetails) {
        let secp = Secp256k1::new();
        let address_index = 7;
        let mut signers = Vec::new();
        let mut derivations = BTreeMap::new();

        for cosigner in 0..2 {
            let master =
                Xpriv::new_master(Network::Bitcoin, &[seed_offset + cosigner as u8; 32]).unwrap();
            let fingerprint = master.fingerprint(&secp);
            let account_path = DerivationPath::from(vec![
                ChildNumber::Hardened { index: 45 },
                ChildNumber::Normal { index: cosigner },
            ]);
            let account_xpriv = master.derive_priv(&secp, &account_path).unwrap();
            signers.push(MultiSigSigner::new(
                &account_path,
                &fingerprint,
                &Xpub::from_priv(&secp, &account_xpriv),
            ));

            let mut address_path = account_path.as_ref().to_vec();
            address_path.extend([
                ChildNumber::Normal {
                    index: keychain as u32,
                },
                ChildNumber::Normal {
                    index: address_index,
                },
            ]);
            let address_path = DerivationPath::from(address_path);
            let public_key =
                Xpub::from_priv(&secp, &master.derive_priv(&secp, &address_path).unwrap())
                    .public_key;
            derivations.insert(public_key, (fingerprint, address_path));
        }

        let multisig = MultiSigDetails::new(2, 2, AddressType::P2sh, None, signers).unwrap();
        let descriptor = multisig
            .to_descriptor(keychain, &secp, None)
            .unwrap()
            .0
            .derived_descriptor(&secp, address_index)
            .unwrap();
        let redeem_script = descriptor.explicit_script().unwrap();
        let txout = TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: descriptor.script_pubkey(),
        };
        let mut output = output_with_scripts(redeem_script, None);
        output.bip32_derivation = derivations;

        (output, txout, multisig)
    }

    /// A nested P2SH-P2WSH with a malformed witness_script must not panic.
    #[test]
    fn nested_malformed_witness_script_returns_error() {
        let witness_script = ScriptBuf::from_bytes(vec![0xff; 32]);
        let output = output_with_scripts(p2wsh_redeem_script(), Some(witness_script));

        let result = validate_output(
            &Secp256k1::new(),
            &output,
            &txout(),
            Network::Bitcoin,
            0,
            None,
        );
        assert!(matches!(
            result,
            Err(Error::InvalidWitnessScript { index: 0 })
        ));
    }

    /// A nested P2SH-P2WSH whose witness_script is syntactically valid Script
    /// but not valid Miniscript must surface a structured error.
    #[test]
    fn nested_non_miniscript_witness_script_returns_error() {
        let witness_script = Script::builder().push_opcode(OP_RETURN).into_script();
        let output = output_with_scripts(p2wsh_redeem_script(), Some(witness_script));

        let result = validate_output(
            &Secp256k1::new(),
            &output,
            &txout(),
            Network::Bitcoin,
            0,
            None,
        );
        assert!(matches!(
            result,
            Err(Error::InvalidWitnessScript { index: 0 })
        ));
    }

    /// A nested P2SH-P2WSH with an empty witness_script triggers the parser.
    #[test]
    fn nested_empty_witness_script_returns_error() {
        let output = output_with_scripts(p2wsh_redeem_script(), Some(ScriptBuf::new()));

        let result = validate_output(
            &Secp256k1::new(),
            &output,
            &txout(),
            Network::Bitcoin,
            0,
            None,
        );
        assert!(matches!(
            result,
            Err(Error::InvalidWitnessScript { index: 0 })
        ));
    }

    /// Missing witness_script when redeem_script is P2WSH must return a
    /// structured error rather than panicking later.
    #[test]
    fn nested_missing_witness_script_returns_error() {
        let output = output_with_scripts(p2wsh_redeem_script(), None);

        let result = validate_output(
            &Secp256k1::new(),
            &output,
            &txout(),
            Network::Bitcoin,
            4,
            None,
        );
        assert!(matches!(
            result,
            Err(Error::MissingWitnessScript { index: 4 })
        ));
    }

    /// Missing redeem_script altogether must return MissingRedeemScript.
    #[test]
    fn missing_redeem_script_returns_error() {
        let output = psbt::Output::default();

        let result = validate_output(
            &Secp256k1::new(),
            &output,
            &txout(),
            Network::Bitcoin,
            9,
            None,
        );
        assert!(matches!(
            result,
            Err(Error::MissingRedeemScript { index: 9 })
        ));
    }

    #[test]
    fn registered_legacy_p2sh_change_is_recognized() {
        let (output, txout, multisig) = registered_legacy_output(1, KeychainKind::Internal);
        let result = validate_output(
            &Secp256k1::new(),
            &output,
            &txout,
            Network::Bitcoin,
            0,
            Some(&multisig),
        )
        .unwrap();
        assert!(matches!(result.kind, OutputKind::Change(_)));
    }

    #[test]
    fn unregistered_legacy_p2sh_output_is_external() {
        let (output, txout, _) = registered_legacy_output(1, KeychainKind::Internal);
        let (_, _, different_multisig) = registered_legacy_output(3, KeychainKind::Internal);
        let result = validate_output(
            &Secp256k1::new(),
            &output,
            &txout,
            Network::Bitcoin,
            0,
            Some(&different_multisig),
        )
        .unwrap();
        assert!(matches!(result.kind, OutputKind::External(_)));
    }

    /// An unsupported P2SH redeem_script must return a structured error,
    /// not panic.
    #[test]
    fn non_multisig_p2sh_returns_invalid_redeem_script() {
        // Use a tiny non-segwit redeem script.
        let redeem_script = Script::builder()
            .push_opcode(OP_PUSHBYTES_0)
            .push_opcode(OP_RETURN)
            .into_script();
        let output = output_with_scripts(redeem_script, None);

        let result = validate_output(
            &Secp256k1::new(),
            &output,
            &txout(),
            Network::Bitcoin,
            0,
            None,
        );
        assert!(matches!(
            result,
            Err(Error::InvalidRedeemScript { index: 0 })
        ));
    }
}

use crate::bip32::NgAccountPath;
use crate::psbt::{Error, OutputKind, PsbtOutput, sort_keys};
use bdk_wallet::bitcoin::bip32::{ChildNumber, DerivationPath, KeySource, Xpub};
use bdk_wallet::bitcoin::psbt;
use bdk_wallet::bitcoin::secp256k1::PublicKey;
use bdk_wallet::bitcoin::{Network, TxOut};
use bdk_wallet::descriptor::{Descriptor, ExtendedDescriptor, Segwitv0};
use bdk_wallet::keys::DescriptorPublicKey;
use bdk_wallet::miniscript::descriptor::{DescriptorXKey, Wildcard, Wsh};
use bdk_wallet::miniscript::{ForEachKey, Miniscript};
use std::collections::BTreeMap;

/// Validate a Pay to Witness Script Hash (P2WSH).
pub fn validate_output(
    output: &psbt::Output,
    txout: &TxOut,
    network: Network,
    index: usize,
) -> Result<PsbtOutput, Error> {
    let witness_script = output
        .witness_script
        .as_ref()
        .ok_or_else(|| Error::MissingWitnessScript { index })?;
    let ms = Miniscript::<_, Segwitv0>::parse(witness_script)
        .map_err(|_| Error::InvalidWitnessScript { index })?;
    let descriptor = Wsh::new(ms)
        .map(Descriptor::Wsh)
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

    let (_, (_, path)) = output
        .bip32_derivation
        .first_key_value()
        .ok_or(Error::ExpectedKeys { index })?;

    let Some(purpose) = path.as_ref().iter().next() else {
        return Ok(PsbtOutput {
            amount: txout.value,
            kind: OutputKind::Suspicious(address),
        });
    };

    // TODO: Add support for other BIPs here.
    if matches!(purpose, ChildNumber::Hardened { index: 48 }) {
        // For BIP-0048 all paths used to derive an address should be equal.
        let mut are_paths_equal = true;
        for (_, (_, other_path)) in output.bip32_derivation.iter() {
            if other_path != path {
                are_paths_equal = false;
                break;
            }
        }

        if !are_paths_equal {
            return Ok(PsbtOutput {
                amount: txout.value,
                kind: OutputKind::Suspicious(address),
            });
        }

        let maybe_account_path =
            NgAccountPath::parse(path).map_err(|e| Error::invalid_path(path.clone(), e))?;
        let Some(account_path) = maybe_account_path else {
            return Ok(PsbtOutput {
                amount: txout.value,
                kind: OutputKind::Suspicious(address),
            });
        };

        if !matches!(account_path.script_type, Some(2)) {
            return Ok(PsbtOutput {
                amount: txout.value,
                kind: OutputKind::Suspicious(address),
            });
        }

        Ok(PsbtOutput {
            amount: txout.value,
            kind: OutputKind::from_derivation_path(path, 48, network, address)?,
        })
    } else {
        Ok(PsbtOutput {
            amount: txout.value,
            kind: OutputKind::Suspicious(address),
        })
    }
}

/// Returns the descriptor for a P2WSH multisig account.
///
/// The `required_signers` parameter must be known before hand, by for
/// example, disassembling the multisig script.
pub fn multisig_descriptor(
    required_signers: u8,
    global_xpubs: &BTreeMap<Xpub, KeySource>,
    bip32_derivations: &BTreeMap<PublicKey, KeySource>,
) -> Result<[ExtendedDescriptor; 2], Error> {
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

    let external_descriptor =
        ExtendedDescriptor::new_wsh_sortedmulti(usize::from(required_signers), external_keys)
            .unwrap();
    let internal_descriptor =
        ExtendedDescriptor::new_wsh_sortedmulti(usize::from(required_signers), internal_keys)
            .unwrap();

    Ok([external_descriptor, internal_descriptor])
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::opcodes::all::OP_RETURN;
    use bdk_wallet::bitcoin::{Amount, ScriptBuf, Script};

    fn empty_output_with_witness_script(witness_script: ScriptBuf) -> psbt::Output {
        psbt::Output {
            witness_script: Some(witness_script),
            ..Default::default()
        }
    }

    fn empty_txout() -> TxOut {
        TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new(),
        }
    }

    /// A malformed witness_script (random non-script bytes) must not panic
    /// when reaching the Miniscript parser.
    #[test]
    fn malformed_witness_script_returns_error() {
        let witness_script = ScriptBuf::from_bytes(vec![0xff; 32]);
        let output = empty_output_with_witness_script(witness_script);
        let txout = empty_txout();

        let result = validate_output(&output, &txout, Network::Bitcoin, 0);
        assert!(matches!(
            result,
            Err(Error::InvalidWitnessScript { index: 0 })
        ));
    }

    /// A syntactically valid script that is not a valid Miniscript expression
    /// must be reported as InvalidWitnessScript instead of panicking.
    #[test]
    fn non_miniscript_witness_script_returns_error() {
        let witness_script = Script::builder().push_opcode(OP_RETURN).into_script();
        let output = empty_output_with_witness_script(witness_script);
        let txout = empty_txout();

        let result = validate_output(&output, &txout, Network::Bitcoin, 0);
        assert!(matches!(
            result,
            Err(Error::InvalidWitnessScript { index: 0 })
        ));
    }

    /// An empty witness_script triggers the parser at the boundary and must
    /// not panic.
    #[test]
    fn empty_witness_script_returns_error() {
        let output = empty_output_with_witness_script(ScriptBuf::new());
        let txout = empty_txout();

        let result = validate_output(&output, &txout, Network::Bitcoin, 0);
        assert!(matches!(
            result,
            Err(Error::InvalidWitnessScript { index: 0 })
        ));
    }

    /// Missing witness_script must surface as a structured error.
    #[test]
    fn missing_witness_script_returns_error() {
        let output = psbt::Output::default();
        let txout = empty_txout();

        let result = validate_output(&output, &txout, Network::Bitcoin, 7);
        assert!(matches!(
            result,
            Err(Error::MissingWitnessScript { index: 7 })
        ));
    }
}

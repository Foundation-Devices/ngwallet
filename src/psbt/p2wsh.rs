use crate::bip32::NgAccountPath;
use crate::psbt::{Error, OutputKind, PsbtOutput};
use bdk_wallet::bitcoin::bip32::{ChildNumber, DerivationPath, KeySource, Xpub};
use bdk_wallet::bitcoin::psbt;
use bdk_wallet::bitcoin::secp256k1::PublicKey;
use bdk_wallet::bitcoin::{Network, TxOut};
use bdk_wallet::descriptor::{Descriptor, ExtendedDescriptor, Segwitv0};
use bdk_wallet::keys::DescriptorPublicKey;
use bdk_wallet::miniscript::descriptor::{DerivPaths, DescriptorMultiXKey, Wildcard, Wsh};
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
    let ms = Miniscript::<_, Segwitv0>::parse(witness_script).unwrap();
    let descriptor = Wsh::new(ms).map(Descriptor::Wsh).unwrap();

    // Verify that all keys in the descriptor are in the bip32_derivation map
    // which should have been validated already.
    let are_keys_valid =
        descriptor.for_each_key(|pk| output.bip32_derivation.contains_key(&pk.inner));
    if !are_keys_valid {
        return Err(Error::FraudulentOutput { index });
    }

    let address = descriptor.address(network).unwrap();
    if !address.matches_script_pubkey(&txout.script_pubkey) {
        return Err(Error::FraudulentOutput { index });
    }

    let (_, (_, path)) = output
        .bip32_derivation
        .first_key_value()
        .expect("at least one bip32 derivation should be present");

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
) -> Result<ExtendedDescriptor, Error> {
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

    let mut descriptor_pubkeys = Vec::new();
    for maybe_xpub in xpubs {
        let (xpub, source) = maybe_xpub?;

        let descriptor_pubkey = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: Some(source.clone()),
            xkey: *xpub,
            derivation_paths: DerivPaths::new(vec![
                DerivationPath::from(vec![ChildNumber::Normal { index: 0 }]),
                DerivationPath::from(vec![ChildNumber::Normal { index: 1 }]),
            ])
            .expect("the vector passed should not be empty"),
            wildcard: Wildcard::Unhardened,
        });
        descriptor_pubkeys.push(descriptor_pubkey);
    }

    Ok(
        ExtendedDescriptor::new_wsh_sortedmulti(usize::from(required_signers), descriptor_pubkeys)
            .unwrap(),
    )
}

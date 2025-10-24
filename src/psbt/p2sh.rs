use crate::bip32::NgAccountPath;
use crate::psbt::{
    Error, OutputKind, PsbtOutput, derive_account_xpub, derive_full_descriptor_pubkey, sort_keys,
};
use bdk_wallet::bitcoin::bip32::{ChildNumber, DerivationPath, KeySource, Xpriv, Xpub};
use bdk_wallet::bitcoin::psbt;
use bdk_wallet::bitcoin::secp256k1::{PublicKey, Secp256k1, Signing};
use bdk_wallet::bitcoin::{Address, CompressedPublicKey, Network, TxOut};
use bdk_wallet::descriptor::{Descriptor, ExtendedDescriptor, Segwitv0};
use bdk_wallet::keys::DescriptorPublicKey;
use bdk_wallet::miniscript::descriptor::{DescriptorXKey, Wildcard};
use bdk_wallet::miniscript::descriptor::{Sh, Wpkh};
use bdk_wallet::miniscript::{ForEachKey, Miniscript};
use bdk_wallet::template::{Bip49Public, DescriptorTemplate};
use std::collections::BTreeMap;

pub fn validate_output(
    output: &psbt::Output,
    txout: &TxOut,
    network: Network,
    index: usize,
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

        let ms = Miniscript::<_, Segwitv0>::parse(witness_script).unwrap();
        let descriptor = Sh::new_wsh(ms).map(Descriptor::Sh).unwrap();

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

            if !matches!(account_path.script_type, Some(1)) {
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
    } else {
        // TODO: Legacy P2SH (e.g. BIP45).
        Err(Error::Unimplemented)
    }
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
            .build(network)
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
        ExtendedDescriptor::new_sh_wsh_sortedmulti(usize::from(required_signers), external_keys)
            .unwrap();
    let internal_descriptor =
        ExtendedDescriptor::new_sh_wsh_sortedmulti(usize::from(required_signers), internal_keys)
            .unwrap();

    Ok([external_descriptor, internal_descriptor])
}

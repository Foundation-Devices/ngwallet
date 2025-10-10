use crate::bip32::NgAccountPath;
use crate::psbt::{
    Error, OutputKind, PsbtOutput, derive_account_xpub, derive_full_descriptor_pubkey,
};
use bdk_wallet::bitcoin::bip32::{ChildNumber, Xpriv};
use bdk_wallet::bitcoin::psbt;
use bdk_wallet::bitcoin::secp256k1::{Secp256k1, Signing};
use bdk_wallet::bitcoin::{Address, CompressedPublicKey, Network, TxOut};
use bdk_wallet::descriptor::ExtendedDescriptor;
use bdk_wallet::miniscript::descriptor::Wpkh;
use bdk_wallet::template::{Bip49Public, DescriptorTemplate};

pub fn validate_output(
    output: &psbt::Output,
    txout: &TxOut,
    network: Network,
    index: usize,
) -> Result<PsbtOutput, Error> {
    debug_assert!(txout.script_pubkey.is_p2sh());

    // There should be at least one.
    if output.bip32_derivation.is_empty() {
        return Err(Error::ExpectedKeys { index });
    }

    let (_, source) = output
        .bip32_derivation
        .first_key_value()
        .expect("the previous statement checks for at least one entry");

    if let Some(purpose) = source.1.as_ref().iter().next() {
        match purpose {
            ChildNumber::Hardened { index: 49 } => {
                return validate_p2wpkh_nested_in_p2sh_output(output, txout, network, index);
            }
            _ => return Err(Error::Unimplemented),
        }
    }

    Err(Error::Unimplemented)
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

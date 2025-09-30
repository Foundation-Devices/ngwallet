use crate::bip32::NgAccountPath;
use crate::psbt::{Error, Output, OutputKind, derive_account_xpub, derive_full_descriptor_pubkey};
use bdk_wallet::bitcoin::bip32::{ChildNumber, Xpriv};
use bdk_wallet::bitcoin::secp256k1::{Secp256k1, Signing};
use bdk_wallet::bitcoin::{Address, CompressedPublicKey, Network, TxOut, psbt};
use bdk_wallet::descriptor::ExtendedDescriptor;
use bdk_wallet::template::{Bip44Public, DescriptorTemplate};

/// Validate a Pay to Public Key Hash (P2PKH) output.
pub fn validate_output(
    output: &psbt::Output,
    txout: &TxOut,
    network: Network,
    index: usize,
) -> Result<Output, Error> {
    debug_assert!(txout.script_pubkey.is_p2pkh());

    // This output type is by definition single-sig only, so exactly one
    // public key is expected.
    if output.bip32_derivation.len() != 1 {
        return Err(Error::MultipleKeysNotExpected { index });
    }

    let (pk, source) = output
        .bip32_derivation
        .first_key_value()
        .expect("the previous statement should check for at least one entry");

    // Check that the script_pubkey matches our computed address.
    let compressed_pk = CompressedPublicKey(*pk);
    let address = Address::p2pkh(compressed_pk, network);
    if !address.matches_script_pubkey(&txout.script_pubkey) {
        return Err(Error::FraudulentOutput { index });
    }

    Ok(Output {
        amount: txout.value,
        kind: OutputKind::from_derivation_path(&source.1, 44, network, address)?,
    })
}

/// Compute the account descriptor for P2PKH from the `path` derivation path.
pub fn descriptor<C>(
    secp: &Secp256k1<C>,
    master_key: &Xpriv,
    path: impl AsRef<[ChildNumber]>,
    network: Network,
) -> String
where
    C: Signing,
{
    match NgAccountPath::parse(&path) {
        Ok(Some(account_path)) => {
            // Not a valid BIP-0084 derivation path or is not an address
            // derivation path, just return the full derivation path and the
            // computed public key.
            if !account_path.matches(44, network) || !account_path.is_for_address() {
                let pk = derive_full_descriptor_pubkey(secp, master_key, path);
                let descriptor = ExtendedDescriptor::new_pkh(pk).unwrap();
                return descriptor.to_string();
            }

            let xpub = derive_account_xpub(secp, master_key, path);
            let descriptor = Bip44Public(
                xpub,
                master_key.fingerprint(secp),
                account_path
                    .keychain_kind()
                    .expect("is_for_address checks for this"),
            )
            .build(network)
            .unwrap()
            .0;
            descriptor.to_string()
        }
        // Not a BIP-0044 account, just return the wpkh descriptor with the full derivation path
        // and the computed public key.
        _ => {
            let pk = derive_full_descriptor_pubkey(secp, master_key, path);
            let descriptor = ExtendedDescriptor::new_pkh(pk).unwrap();
            descriptor.to_string()
        }
    }
}

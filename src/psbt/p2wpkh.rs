use crate::bip32::NgAccountPath;
use crate::psbt::{
    Error, OutputKind, PsbtOutput, derive_account_xpub, derive_full_descriptor_pubkey,
};
use bdk_wallet::bitcoin::bip32::{ChildNumber, Xpriv};
use bdk_wallet::bitcoin::psbt;
use bdk_wallet::bitcoin::secp256k1::{Secp256k1, Signing};
use bdk_wallet::bitcoin::{Address, CompressedPublicKey, Network, TxOut};
use bdk_wallet::descriptor::ExtendedDescriptor;
use bdk_wallet::template::{Bip84Public, DescriptorTemplate};

/// Validate a Pay to Witness Public Key Hash (P2WPKH).
///
/// Checks that the public key provided in `output` match correctly the
/// `txout.script_pubkey`.
pub fn validate_output(
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
    let address = Address::p2wpkh(&compressed_pk, network);
    if !address.matches_script_pubkey(&txout.script_pubkey) {
        return Err(Error::FraudulentOutput { index });
    }

    Ok(PsbtOutput {
        amount: txout.value,
        kind: OutputKind::from_derivation_path(&source.1, 84, network, address)?,
    })
}

/// Compute the account descriptor for P2WPKH from the `path` derivation path.
pub fn descriptor<C>(
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
            // Not a valid BIP-0084 derivation path, just return the full derivation path and
            // the computed public key.
            if !account_path.matches(84, network) || !account_path.is_for_address() {
                let pk = derive_full_descriptor_pubkey(secp, master_key, path);
                return ExtendedDescriptor::new_wpkh(pk).unwrap();
            }

            let xpub = derive_account_xpub(secp, master_key, path);
            Bip84Public(
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
            ExtendedDescriptor::new_wpkh(pk).unwrap()
        }
    }
}

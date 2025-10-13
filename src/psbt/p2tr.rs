use crate::bip32::NgAccountPath;
use crate::psbt::{
    Error, OutputKind, PsbtOutput, derive_account_xpub, derive_full_descriptor_pubkey,
};
use bdk_wallet::bitcoin::bip32::{ChildNumber, Xpriv};
use bdk_wallet::bitcoin::psbt;
use bdk_wallet::bitcoin::secp256k1::{Secp256k1, Signing, Verification};
use bdk_wallet::bitcoin::{Address, Network, TxOut};
use bdk_wallet::descriptor::ExtendedDescriptor;
use bdk_wallet::template::{Bip86Public, DescriptorTemplate};

/// Validate a Pay to Taproot (P2TR) output.
///
/// # Notes
///
/// - This only supports single signature addresses based on BIP-0086.
pub fn validate_output<C>(
    secp: &Secp256k1<C>,
    output: &psbt::Output,
    txout: &TxOut,
    network: Network,
    index: usize,
) -> Result<PsbtOutput, Error>
where
    C: Verification,
{
    // Only single-sig support for now.
    if output.tap_key_origins.len() != 1 {
        return Err(Error::MultipleKeysNotExpected { index });
    }

    let (x_only_pk, (_, source)) = output
        .tap_key_origins
        .first_key_value()
        .expect("the previous statement checks for at least one entry");

    let address = Address::p2tr(secp, *x_only_pk, None, network);
    if !address.matches_script_pubkey(&txout.script_pubkey) {
        return Err(Error::FraudulentOutput { index });
    }

    Ok(PsbtOutput {
        amount: txout.value,
        kind: OutputKind::from_derivation_path(&source.1, 86, network, address)?,
    })
}

/// Compute the account descriptor for P2TR from the `path` derivation path.
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
            // Not a valid BIP-0086 derivation path or is not an address
            // derivation path, just return the full derivation path and the
            // computed public key.
            if !account_path.matches(86, network) || !account_path.is_for_address() {
                let pk = derive_full_descriptor_pubkey(secp, master_key, path);
                return ExtendedDescriptor::new_tr(pk, None).unwrap();
            }

            let xpub = derive_account_xpub(secp, master_key, path);
            Bip86Public(
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
        // Not a BIP-0086 account, just return the wpkh descriptor with the full derivation path
        // and the computed public key.
        _ => {
            let pk = derive_full_descriptor_pubkey(secp, master_key, path);
            ExtendedDescriptor::new_tr(pk, None).unwrap()
        }
    }
}

use crate::psbt::{Error, PsbtOutput, OutputKind};
use bdk_wallet::bitcoin::psbt;
use bdk_wallet::bitcoin::secp256k1::{Secp256k1, Verification};
use bdk_wallet::bitcoin::{Address, Network, TxOut, XOnlyPublicKey};

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
    if output.bip32_derivation.len() != 1 {
        return Err(Error::MultipleKeysNotExpected { index });
    }

    let (pk, source) = output
        .bip32_derivation
        .first_key_value()
        .expect("the previous statement checks for at least one entry");

    let x_only_public_key = XOnlyPublicKey::from(*pk);
    if let Some(psbt_x_only_public_key) = output.tap_internal_key
        && psbt_x_only_public_key != x_only_public_key
    {
        return Err(Error::FraudulentOutput { index });
    }

    let address = Address::p2tr(secp, x_only_public_key, None, network);
    if !address.matches_script_pubkey(&txout.script_pubkey) {
        return Err(Error::FraudulentOutput { index });
    }

    Ok(PsbtOutput {
        amount: txout.value,
        kind: OutputKind::from_derivation_path(&source.1, 86, network, address)?,
    })
}

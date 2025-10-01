use crate::psbt::{Error, PsbtOutput, OutputKind};
use bdk_wallet::bitcoin::bip32::ChildNumber;
use bdk_wallet::bitcoin::psbt;
use bdk_wallet::bitcoin::{Address, CompressedPublicKey, Network, TxOut};

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

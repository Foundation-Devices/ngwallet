use crate::config::MultiSigDetails;
use crate::psbt::{Error, OutputKind, PsbtOutput, p2sh, registered_multisig_output_kind};
use bdk_wallet::bitcoin::bip32::{KeySource, Xpub};
use bdk_wallet::bitcoin::psbt;
use bdk_wallet::bitcoin::secp256k1::{PublicKey, Secp256k1, Signing, Verification};
use bdk_wallet::bitcoin::{Network, TxOut};
use bdk_wallet::descriptor::{Descriptor, ExtendedDescriptor, Segwitv0};
use bdk_wallet::miniscript::descriptor::Wsh;
use bdk_wallet::miniscript::{ForEachKey, Miniscript};
use std::collections::BTreeMap;

pub fn validate_output<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    output: &psbt::Output,
    txout: &TxOut,
    network: Network,
    index: usize,
    registered_multisig: Option<&MultiSigDetails>,
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

/// Returns the descriptor for a P2WSH multisig account.
///
/// The `required_signers` parameter must be known before hand, by for
/// example, disassembling the multisig script.
pub fn multisig_descriptor(
    required_signers: u8,
    global_xpubs: &BTreeMap<Xpub, KeySource>,
    bip32_derivations: &BTreeMap<PublicKey, KeySource>,
) -> Result<[ExtendedDescriptor; 2], Error> {
    let (external_keys, internal_keys) =
        p2sh::multisig_descriptor_keys(global_xpubs, bip32_derivations)?;

    let external_descriptor =
        ExtendedDescriptor::new_wsh_sortedmulti(usize::from(required_signers), external_keys)
            .map_err(|_| Error::InvalidMultisigDescriptor)?;
    let internal_descriptor =
        ExtendedDescriptor::new_wsh_sortedmulti(usize::from(required_signers), internal_keys)
            .map_err(|_| Error::InvalidMultisigDescriptor)?;

    Ok([external_descriptor, internal_descriptor])
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
    use bdk_wallet::bitcoin::opcodes::all::OP_RETURN;
    use bdk_wallet::bitcoin::{Amount, Script, ScriptBuf};
    use std::str::FromStr;

    const ADDRESS_INDEX: u32 = 3;

    // A 2-of-3 receive input whose keys sit `fixed` steps below their global xpubs at `origin`.
    fn discovered_and_expected(
        origin: &str,
        fixed: [&[u32]; 3],
        with_master_xpubs: bool,
    ) -> ([ExtendedDescriptor; 2], [ExtendedDescriptor; 2]) {
        let secp = Secp256k1::new();
        let origin = DerivationPath::from_str(origin).unwrap();
        let mut global_xpubs = BTreeMap::new();
        let mut derivations = BTreeMap::new();
        let mut keys = [Vec::new(), Vec::new()];

        for (seed, fixed) in (1u8..).zip(fixed) {
            let master = Xpriv::new_master(Network::Bitcoin, &[seed; 32]).unwrap();
            let fingerprint = master.fingerprint(&secp);
            let xpub = Xpub::from_priv(&secp, &master.derive_priv(&secp, &origin).unwrap());
            global_xpubs.insert(xpub, (fingerprint, origin.clone()));
            if with_master_xpubs {
                global_xpubs.insert(
                    Xpub::from_priv(&secp, &master),
                    (fingerprint, DerivationPath::master()),
                );
            }

            let key_path = origin
                .extend(
                    fixed
                        .iter()
                        .map(|index| ChildNumber::Normal { index: *index })
                        .collect::<Vec<_>>(),
                )
                .extend([
                    ChildNumber::Normal { index: 0 },
                    ChildNumber::Normal {
                        index: ADDRESS_INDEX,
                    },
                ]);
            let public_key =
                Xpub::from_priv(&secp, &master.derive_priv(&secp, &key_path).unwrap()).public_key;
            derivations.insert(public_key, (fingerprint, key_path));

            let fixed = fixed
                .iter()
                .map(|index| format!("{index}/"))
                .collect::<String>();
            for (keychain, keys) in keys.iter_mut().enumerate() {
                keys.push(format!(
                    "[{fingerprint}/{origin}]{xpub}/{fixed}{keychain}/*"
                ));
            }
        }

        let discovered = multisig_descriptor(2, &global_xpubs, &derivations).unwrap();
        let expected = keys.map(|keys| {
            ExtendedDescriptor::from_str(&format!("wsh(sortedmulti(2,{}))", keys.join(",")))
                .unwrap()
        });
        (discovered, expected)
    }

    fn assert_same_scripts(
        discovered: &[ExtendedDescriptor; 2],
        expected: &[ExtendedDescriptor; 2],
    ) {
        for (discovered, expected) in discovered.iter().zip(expected) {
            assert_eq!(
                discovered
                    .at_derivation_index(ADDRESS_INDEX)
                    .unwrap()
                    .script_pubkey(),
                expected
                    .at_derivation_index(ADDRESS_INDEX)
                    .unwrap()
                    .script_pubkey()
            );
        }
    }

    /// BIP174 places each global xpub at its last hardened step, above BIP45 cosigner indexes.
    #[test]
    fn descriptor_keeps_fixed_steps_below_global_xpub() {
        let (discovered, expected) = discovered_and_expected("m/45'", [&[0], &[1], &[2]], false);
        assert_same_scripts(&discovered, &expected);
    }

    /// Master xpubs also prefix every key path, so the deepest global xpub must win.
    #[test]
    fn descriptor_prefers_deepest_global_xpub() {
        let (discovered, expected) = discovered_and_expected("m/48'/0'/0'/2'", [&[]; 3], true);
        assert_same_scripts(&discovered, &expected);

        let (discovered, expected) = discovered_and_expected("m/45'", [&[0], &[1], &[2]], true);
        assert_same_scripts(&discovered, &expected);
    }

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

        let result = validate_output(
            &Secp256k1::new(),
            &output,
            &txout,
            Network::Bitcoin,
            0,
            None,
        );
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

        let result = validate_output(
            &Secp256k1::new(),
            &output,
            &txout,
            Network::Bitcoin,
            0,
            None,
        );
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

        let result = validate_output(
            &Secp256k1::new(),
            &output,
            &txout,
            Network::Bitcoin,
            0,
            None,
        );
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

        let result = validate_output(
            &Secp256k1::new(),
            &output,
            &txout,
            Network::Bitcoin,
            7,
            None,
        );
        assert!(matches!(
            result,
            Err(Error::MissingWitnessScript { index: 7 })
        ));
    }
}

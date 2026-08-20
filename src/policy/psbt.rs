//! Match a PSBT against a registered policy. This is deliberately strict: the
//! stored descriptor, not coordinator-supplied scripts, is the trust anchor.

use {
    super::{Error, Result, SpendPathKind, WalletPolicy},
    crate::psbt::{OutputKind, PsbtInput, PsbtOutput, TransactionDetails},
    bdk_wallet::{
        bitcoin::{
            Address, Amount, Network, Psbt, Sequence, TxOut,
            bip32::{ChildNumber, Fingerprint},
            psbt,
            sighash::EcdsaSighashType,
        },
        miniscript::{
            Descriptor, DescriptorPublicKey,
            psbt::{PsbtInputExt, PsbtOutputExt},
        },
    },
    std::collections::HashSet,
};

#[derive(Debug, Clone, PartialEq)]
pub struct MatchResult {
    pub matched: bool,
    pub active_path: Option<SpendPathKind>,
    pub passport_can_sign: bool,
    pub expected_signatures: usize,
    pub change_outputs: HashSet<usize>,
    pub reasons: Vec<String>,
}

pub fn match_psbt(
    psbt: &Psbt,
    policy: &WalletPolicy,
    passport_fp: Fingerprint,
) -> Result<MatchResult> {
    let descriptor = policy
        .descriptor
        .parse::<Descriptor<DescriptorPublicKey>>()
        .map_err(|error| Error::Match(format!("registered descriptor: {error}")))?;
    let singles = descriptor
        .into_single_descriptors()
        .map_err(|error| Error::Match(format!("multipath split: {error}")))?;
    if psbt.inputs.is_empty() || psbt.inputs.len() != psbt.unsigned_tx.input.len() {
        return Err(Error::Match(
            "PSBT input maps do not match the unsigned transaction".into(),
        ));
    }
    if psbt.outputs.len() != psbt.unsigned_tx.output.len() {
        return Err(Error::Match(
            "PSBT output maps do not match the unsigned transaction".into(),
        ));
    }

    let mut expected_signatures = 0usize;
    for (index, input) in psbt.inputs.iter().enumerate() {
        validate_sighash(index, input)?;
        let utxo = input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| Error::Match(format!("input {index}: missing witness_utxo")))?;
        if !utxo.script_pubkey.is_p2wsh() || input.redeem_script.is_some() {
            return Err(Error::Match(format!(
                "input {index}: only native P2WSH policy inputs are supported"
            )));
        }
        expected_signatures = expected_signatures.saturating_add(
            match_input(input, &singles, passport_fp)
                .map_err(|reason| Error::Match(format!("input {index}: {reason}")))?,
        );
        validate_non_witness_utxo(index, psbt, input, utxo)?;
    }

    let compatible = psbt
        .unsigned_tx
        .input
        .iter()
        .map(|input| {
            compatible_paths(
                policy,
                psbt.unsigned_tx.version.0,
                input.sequence,
                psbt.unsigned_tx.lock_time.to_consensus_u32(),
            )
        })
        .collect::<Vec<_>>();
    let first = compatible.first().cloned().unwrap_or_default();
    if compatible.iter().any(|paths| paths != &first) {
        return Err(Error::Match(
            "inputs use mixed primary/recovery authorization conditions".into(),
        ));
    }
    let fingerprint = passport_fp.to_string();
    let selected = first.iter().copied().find(|path_index| {
        policy.paths[*path_index]
            .signer_fingerprints
            .contains(&fingerprint)
    });
    let Some(active_path_index) = selected else {
        return Err(Error::Match(
            "Passport has no key on an unlocked spending path".into(),
        ));
    };
    let active_path = policy.paths[active_path_index].kind;
    let derivation_inputs = psbt
        .inputs
        .iter()
        .filter(|input| {
            input
                .bip32_derivation
                .values()
                .any(|(fingerprint, _)| *fingerprint == passport_fp)
        })
        .count();
    if derivation_inputs != psbt.inputs.len() || expected_signatures < psbt.inputs.len() {
        return Err(Error::Match("refusing partial policy signing".into()));
    }

    let mut change_outputs = HashSet::new();
    for (index, (output, txout)) in psbt
        .outputs
        .iter()
        .zip(&psbt.unsigned_tx.output)
        .enumerate()
    {
        if match_output(output, txout, &singles, passport_fp)
            .map_err(|reason| Error::Match(format!("output {index}: {reason}")))?
        {
            change_outputs.insert(index);
        }
    }

    Ok(MatchResult {
        matched: true,
        active_path: Some(active_path),
        passport_can_sign: true,
        expected_signatures,
        change_outputs,
        reasons: Vec::new(),
    })
}

pub fn transaction_details(
    psbt: &Psbt,
    policy: &WalletPolicy,
    network: Network,
    matched: &MatchResult,
) -> Result<TransactionDetails> {
    let mut input_total = Amount::ZERO;
    let mut inputs = Vec::new();
    for (index, input) in psbt.inputs.iter().enumerate() {
        let utxo = input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| Error::Match(format!("input {index}: missing witness_utxo")))?;
        input_total = input_total
            .checked_add(utxo.value)
            .ok_or_else(|| Error::Match("input amount overflow".into()))?;
        let address = Address::from_script(&utxo.script_pubkey, network).map_err(|error| {
            Error::Match(format!("input {index}: invalid address script: {error}"))
        })?;
        inputs.push(PsbtInput {
            amount: utxo.value,
            address,
        });
    }

    let mut total_self_send = Amount::ZERO;
    let mut outputs = Vec::new();
    for (index, txout) in psbt.unsigned_tx.output.iter().enumerate() {
        let kind = if matched.change_outputs.contains(&index) {
            total_self_send = total_self_send
                .checked_add(txout.value)
                .ok_or_else(|| Error::Match("output amount overflow".into()))?;
            let address = Address::from_script(&txout.script_pubkey, network).map_err(|error| {
                Error::Match(format!("output {index}: invalid change script: {error}"))
            })?;
            OutputKind::Change(address)
        } else if txout.script_pubkey.is_op_return() {
            OutputKind::OpReturn(Vec::new())
        } else {
            let address = Address::from_script(&txout.script_pubkey, network).map_err(|error| {
                Error::Match(format!("output {index}: unsupported script: {error}"))
            })?;
            OutputKind::External(address)
        };
        outputs.push(PsbtOutput {
            amount: txout.value,
            kind,
        });
    }

    let descriptor = policy
        .descriptor
        .parse::<Descriptor<DescriptorPublicKey>>()
        .map_err(|error| Error::Match(format!("registered descriptor: {error}")))?;
    // SAFETY: ExtendedDescriptor's interior mutability is only its cached
    // Taproot spend info; descriptor equality and hashing do not mutate it.
    #[allow(clippy::mutable_key_type)]
    let descriptors = descriptor
        .into_single_descriptors()
        .map_err(|error| Error::Match(format!("multipath split: {error}")))?
        .into_iter()
        .collect();
    let fee = psbt
        .fee()
        .map_err(|error| Error::Match(format!("fee: {error}")))?;
    Ok(TransactionDetails {
        total_with_self_send: input_total
            .checked_sub(fee)
            .ok_or_else(|| Error::Match("fee exceeds inputs".into()))?,
        total_self_send,
        total_non_change_self_send: Amount::ZERO,
        fee,
        descriptors,
        inputs,
        outputs,
    })
}

fn compatible_paths(
    policy: &WalletPolicy,
    version: i32,
    sequence: Sequence,
    lock_time: u32,
) -> Vec<usize> {
    let sequence_blocks = sequence
        .to_relative_lock_time()
        .and_then(|lock| match lock {
            bdk_wallet::bitcoin::relative::LockTime::Blocks(height) => Some(height.value() as u32),
            bdk_wallet::bitcoin::relative::LockTime::Time(_) => None,
        });
    policy
        .paths
        .iter()
        .enumerate()
        .filter(|(_, path)| {
            if path.kind == SpendPathKind::Primary {
                return true;
            }
            let relative_ok = path.relative_timelock.is_none_or(|required| {
                version >= 2 && sequence_blocks.is_some_and(|actual| actual >= required)
            });
            let absolute_ok = path.absolute_timelock.is_none_or(|required| {
                sequence != Sequence::MAX
                    && lock_time >= required
                    && (lock_time < 500_000_000) == (required < 500_000_000)
            });
            relative_ok && absolute_ok
        })
        .map(|(index, _)| index)
        .collect()
}

fn derivation_indexes(
    derivations: &std::collections::BTreeMap<
        bdk_wallet::bitcoin::secp256k1::PublicKey,
        bdk_wallet::bitcoin::bip32::KeySource,
    >,
) -> HashSet<u32> {
    derivations
        .values()
        .filter_map(|(_, path)| path.into_iter().next_back())
        .filter_map(|child| match child {
            ChildNumber::Normal { index } => Some(*index),
            ChildNumber::Hardened { .. } => None,
        })
        .collect()
}

fn match_input(
    input: &psbt::Input,
    singles: &[Descriptor<DescriptorPublicKey>],
    passport_fp: Fingerprint,
) -> std::result::Result<usize, String> {
    let utxo = input
        .witness_utxo
        .as_ref()
        .ok_or_else(|| "missing witness_utxo".to_string())?;
    let witness_script = input
        .witness_script
        .as_ref()
        .ok_or_else(|| "missing witness_script".to_string())?;
    let indexes = derivation_indexes(&input.bip32_derivation);
    if indexes.is_empty() {
        return Err("missing unhardened policy derivations".into());
    }
    let mut matches = Vec::new();
    for descriptor in singles {
        for index in &indexes {
            let Ok(definite) = descriptor.at_derivation_index(*index) else {
                continue;
            };
            let mut expected = psbt::Input::default();
            let Ok(derived) = expected.update_with_descriptor_unchecked(&definite) else {
                continue;
            };
            if derived.script_pubkey() == utxo.script_pubkey
                && expected.witness_script.as_ref() == Some(witness_script)
                && expected.bip32_derivation == input.bip32_derivation
            {
                matches.push(
                    expected
                        .bip32_derivation
                        .values()
                        .filter(|(fingerprint, _)| *fingerprint == passport_fp)
                        .count(),
                );
            }
        }
    }
    match matches.as_slice() {
        [owned] if *owned > 0 => Ok(*owned),
        [..] if matches.len() > 1 => Err("derivations match the policy ambiguously".into()),
        _ => Err("scripts and derivations do not match the registered policy".into()),
    }
}

fn match_output(
    output: &psbt::Output,
    txout: &TxOut,
    singles: &[Descriptor<DescriptorPublicKey>],
    passport_fp: Fingerprint,
) -> std::result::Result<bool, String> {
    if !output
        .bip32_derivation
        .values()
        .any(|(fingerprint, _)| *fingerprint == passport_fp)
    {
        return Ok(false);
    }
    let indexes = derivation_indexes(&output.bip32_derivation);
    let mut matches = 0usize;
    for descriptor in singles {
        for index in &indexes {
            let Ok(definite) = descriptor.at_derivation_index(*index) else {
                continue;
            };
            let mut expected = psbt::Output::default();
            let Ok(derived) = expected.update_with_descriptor_unchecked(&definite) else {
                continue;
            };
            if derived.script_pubkey() == txout.script_pubkey
                && expected.bip32_derivation == output.bip32_derivation
                && (output.witness_script.is_none()
                    || output.witness_script == expected.witness_script)
                && output.redeem_script == expected.redeem_script
            {
                matches += 1;
            }
        }
    }
    match matches {
        0 => Err("derivations do not match a registered-policy output".into()),
        1 => Ok(true),
        _ => Err("derivations match the policy ambiguously".into()),
    }
}

fn validate_sighash(index: usize, input: &psbt::Input) -> Result<()> {
    let sighash = input
        .ecdsa_hash_ty()
        .map_err(|error| Error::Match(format!("input {index}: invalid sighash: {error}")))?;
    if sighash != EcdsaSighashType::All {
        return Err(Error::Match(format!(
            "input {index}: only SIGHASH_ALL is supported"
        )));
    }
    Ok(())
}

fn validate_non_witness_utxo(
    index: usize,
    psbt: &Psbt,
    input: &psbt::Input,
    witness_utxo: &TxOut,
) -> Result<()> {
    let Some(previous) = input.non_witness_utxo.as_ref() else {
        return Ok(());
    };
    let prevout = psbt
        .unsigned_tx
        .input
        .get(index)
        .ok_or_else(|| Error::Match(format!("input {index}: missing transaction input")))?
        .previous_output;
    if previous.compute_txid() != prevout.txid
        || previous.output.get(prevout.vout as usize) != Some(witness_utxo)
    {
        return Err(Error::Match(format!(
            "input {index}: witness/non-witness UTXO mismatch"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::policy::WalletPolicy,
        bdk_wallet::bitcoin::{
            OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Witness, absolute,
            bip32::{DerivationPath, Xpriv, Xpub},
            secp256k1::{All, Secp256k1},
            transaction::Version,
        },
        std::str::FromStr,
    };

    fn key(secp: &Secp256k1<All>, master: &Xpriv) -> String {
        let path = DerivationPath::from_str("48'/1'/1'/2'").unwrap();
        let account = master.derive_priv(secp, &path).unwrap();
        format!(
            "[{}/{}]{}/<0;1>/*",
            master.fingerprint(secp),
            path,
            Xpub::from_priv(secp, &account)
        )
    }

    fn fixture(device_primary: bool, absolute_lock: bool) -> (WalletPolicy, Xpriv, Secp256k1<All>) {
        let secp = Secp256k1::new();
        let device = Xpriv::new_master(Network::Testnet, &[11; 32]).unwrap();
        let other = Xpriv::new_master(Network::Testnet, &[12; 32]).unwrap();
        let (primary, recovery) = if device_primary {
            (key(&secp, &device), key(&secp, &other))
        } else {
            (key(&secp, &other), key(&secp, &device))
        };
        let lock = if absolute_lock {
            "after(500)"
        } else {
            "older(10)"
        };
        let raw = format!("wsh(or_d(pk({primary}),and_v(v:pk({recovery}),{lock})))");
        let descriptor = raw
            .parse::<Descriptor<DescriptorPublicKey>>()
            .unwrap()
            .to_string();
        let policy = WalletPolicy::from_descriptor(
            "Policy test",
            Network::Testnet,
            &descriptor,
            &device,
            &secp,
        )
        .unwrap();
        (policy, device, secp)
    }

    fn psbt_for(policy: &WalletPolicy, sequence: Sequence, lock_time: absolute::LockTime) -> Psbt {
        let descriptor = policy
            .descriptor
            .parse::<Descriptor<DescriptorPublicKey>>()
            .unwrap()
            .into_single_descriptors()
            .unwrap()
            .remove(0);
        let definite = descriptor.at_derivation_index(7).unwrap();
        let funding = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: definite.script_pubkey(),
        };
        let transaction = Transaction {
            version: Version::TWO,
            lock_time,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: definite.script_pubkey(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(transaction).unwrap();
        psbt.inputs[0]
            .update_with_descriptor_unchecked(&definite)
            .unwrap();
        psbt.inputs[0].witness_utxo = Some(funding);
        psbt
    }

    #[test]
    fn matches_and_signs_primary_path() {
        let (policy, master, secp) = fixture(true, false);
        let mut psbt = psbt_for(&policy, Sequence::MAX, absolute::LockTime::ZERO);
        let matched = match_psbt(&psbt, &policy, master.fingerprint(&secp)).unwrap();
        assert_eq!(matched.active_path, Some(SpendPathKind::Primary));
        assert_eq!(matched.expected_signatures, 1);
        crate::policy::signing::sign(&mut psbt, &master, &secp, 1).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    }

    #[test]
    fn matches_relative_and_absolute_recovery_paths() {
        let (relative, relative_master, secp) = fixture(false, false);
        let relative_psbt = psbt_for(
            &relative,
            Sequence::from_height(10),
            absolute::LockTime::ZERO,
        );
        let matched = match_psbt(
            &relative_psbt,
            &relative,
            relative_master.fingerprint(&secp),
        )
        .unwrap();
        assert_eq!(matched.active_path, Some(SpendPathKind::Recovery));

        let (absolute, absolute_master, secp) = fixture(false, true);
        let absolute_psbt = psbt_for(
            &absolute,
            Sequence::ENABLE_LOCKTIME_NO_RBF,
            absolute::LockTime::from_height(500).unwrap(),
        );
        let matched = match_psbt(
            &absolute_psbt,
            &absolute,
            absolute_master.fingerprint(&secp),
        )
        .unwrap();
        assert_eq!(matched.active_path, Some(SpendPathKind::Recovery));
    }

    #[test]
    fn rejects_coordinator_script_substitution() {
        let (policy, master, secp) = fixture(true, false);
        let mut psbt = psbt_for(&policy, Sequence::MAX, absolute::LockTime::ZERO);
        psbt.inputs[0].witness_script = Some(ScriptBuf::new());
        assert!(match_psbt(&psbt, &policy, master.fingerprint(&secp)).is_err());
    }

    #[test]
    fn does_not_confuse_distinct_recovery_branches() {
        let secp = Secp256k1::new();
        let device = Xpriv::new_master(Network::Testnet, &[21; 32]).unwrap();
        let primary = Xpriv::new_master(Network::Testnet, &[22; 32]).unwrap();
        let early_recovery = Xpriv::new_master(Network::Testnet, &[23; 32]).unwrap();
        let raw = format!(
            "wsh(or_i(pk({}),or_i(and_v(v:pk({}),older(5)),and_v(v:pk({}),older(10)))))",
            key(&secp, &primary),
            key(&secp, &early_recovery),
            key(&secp, &device),
        );
        let descriptor = raw
            .parse::<Descriptor<DescriptorPublicKey>>()
            .unwrap()
            .to_string();
        let policy = WalletPolicy::from_descriptor(
            "Multiple recovery",
            Network::Testnet,
            &descriptor,
            &device,
            &secp,
        )
        .unwrap();
        let psbt = psbt_for(&policy, Sequence::from_height(5), absolute::LockTime::ZERO);
        assert!(match_psbt(&psbt, &policy, device.fingerprint(&secp)).is_err());
    }
}

use ngwallet::bdk_wallet::bitcoin::{
    Address, Amount, CompressedPublicKey, Network, NetworkKind, OutPoint,
    PublicKey as BitcoinPublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute::LockTime,
    bip32::{DerivationPath, Fingerprint, Xpriv, Xpub},
    opcodes::all::OP_CHECKMULTISIG,
    psbt::{self, Psbt},
    script::Builder,
    secp256k1::{All, PublicKey as SecpPublicKey, Secp256k1},
    transaction::Version,
};
use ngwallet::config::{AddressType, MultiSigDetails, MultiSigSigner};
use ngwallet::psbt::{Error, OutputKind, TransactionDetails, validate};
use std::str::FromStr;

const NETWORK: Network = Network::Testnet4;
const FORMATS: [AddressType; 2] = [AddressType::P2wsh, AddressType::P2ShWsh];
const INPUT_SATS: u64 = 100_000_000;
const CHANGE_SATS: u64 = 50_000_000;
const PAYMENT_SATS: u64 = 40_000_000;

fn master(seed: u8) -> Xpriv {
    Xpriv::new_master(NETWORK, &[seed; 32]).unwrap()
}

/// BIP-0048 account path: script type 2 = P2WSH, 1 = P2SH-P2WSH.
fn account_path(format: AddressType, account: u32) -> DerivationPath {
    let script_type = match format {
        AddressType::P2wsh => 2,
        AddressType::P2ShWsh => 1,
        other => panic!("unsupported format {other:?}"),
    };
    DerivationPath::from_str(&format!("m/48'/1'/{account}'/{script_type}'")).unwrap()
}

fn xpub_at(secp: &Secp256k1<All>, master: &Xpriv, path: &DerivationPath) -> Xpub {
    Xpub::from_priv(secp, &master.derive_priv(secp, path).unwrap())
}

/// Leaf keys for `masters` at `{account_path}/{suffix}` (e.g. "0/0", "1/0").
fn keys_at(
    secp: &Secp256k1<All>,
    account: &DerivationPath,
    suffix: &str,
    masters: &[Xpriv],
) -> Vec<(SecpPublicKey, Fingerprint, DerivationPath)> {
    let accounts = vec![account.clone(); masters.len()];
    keys_at_roots(secp, &accounts, suffix, masters)
}

fn keys_at_roots(
    secp: &Secp256k1<All>,
    accounts: &[DerivationPath],
    suffix: &str,
    masters: &[Xpriv],
) -> Vec<(SecpPublicKey, Fingerprint, DerivationPath)> {
    assert_eq!(accounts.len(), masters.len());
    accounts
        .iter()
        .zip(masters)
        .map(|(account, master)| {
            let path = DerivationPath::from_str(&format!("{account}/{suffix}")).unwrap();
            (
                xpub_at(secp, master, &path).public_key,
                master.fingerprint(secp),
                path,
            )
        })
        .collect()
}

/// BIP-67 sorted bare multisig script, built from raw keys only.
fn multi_script(threshold: i64, keys: impl IntoIterator<Item = SecpPublicKey>) -> ScriptBuf {
    let mut keys: Vec<_> = keys.into_iter().collect();
    keys.sort_by_key(|k| k.serialize());
    let mut builder = Builder::new().push_int(threshold);
    for key in &keys {
        builder = builder.push_key(&BitcoinPublicKey::new(*key));
    }
    builder
        .push_int(keys.len() as i64)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script()
}

fn script_pubkey_for(format: AddressType, script: &ScriptBuf) -> ScriptBuf {
    let p2wsh = ScriptBuf::new_p2wsh(&script.wscript_hash());
    match format {
        AddressType::P2wsh => p2wsh,
        AddressType::P2ShWsh => ScriptBuf::new_p2sh(&p2wsh.script_hash()),
        other => panic!("unsupported format {other:?}"),
    }
}

/// Fill in `redeem_script` for nested formats.
fn with_redeem_script(format: AddressType, script: &ScriptBuf, nested: &mut Option<ScriptBuf>) {
    if format == AddressType::P2ShWsh {
        *nested = Some(ScriptBuf::new_p2wsh(&script.wscript_hash()));
    }
}

type Keys = [(SecpPublicKey, Fingerprint, DerivationPath)];

/// A multisig input spending `script` with the given derivation metadata.
fn input_for(
    format: AddressType,
    script: &ScriptBuf,
    sats: u64,
    keys: &Keys,
) -> (TxIn, psbt::Input) {
    let funding_out = TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: script_pubkey_for(format, script),
    };
    let funding_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![funding_out.clone()],
    };
    let mut input = psbt::Input {
        non_witness_utxo: Some(funding_tx.clone()),
        witness_utxo: Some(funding_out),
        witness_script: Some(script.clone()),
        ..Default::default()
    };
    with_redeem_script(format, script, &mut input.redeem_script);
    for (key, fp, path) in keys {
        input.bip32_derivation.insert(*key, (*fp, path.clone()));
    }
    (
        TxIn {
            previous_output: OutPoint {
                txid: funding_tx.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        },
        input,
    )
}

/// A multisig output paying to `script` with the given derivation metadata.
fn output_for(format: AddressType, script: &ScriptBuf, keys: &Keys) -> (TxOut, psbt::Output) {
    let mut output = psbt::Output {
        witness_script: Some(script.clone()),
        ..Default::default()
    };
    with_redeem_script(format, script, &mut output.redeem_script);
    for (key, fp, path) in keys {
        output.bip32_derivation.insert(*key, (*fp, path.clone()));
    }
    (
        TxOut {
            value: Amount::from_sat(CHANGE_SATS),
            script_pubkey: script_pubkey_for(format, script),
        },
        output,
    )
}

/// An honest spend from the registered 2-of-2 wallet (device = seed 1,
/// cosigner = seed 2): input at `/0/0`, change at `/1/0`, external payment.
fn honest_psbt(format: AddressType) -> (Psbt, MultiSigDetails) {
    let acct = account_path(format, 0);
    honest_psbt_with_roots(format, [acct.clone(), acct])
}

fn honest_psbt_with_roots(
    format: AddressType,
    accounts: [DerivationPath; 2],
) -> (Psbt, MultiSigDetails) {
    let secp = Secp256k1::new();
    let masters = [master(1), master(2)];

    let input_keys = keys_at_roots(&secp, &accounts, "0/0", &masters);
    let change_keys = keys_at_roots(&secp, &accounts, "1/0", &masters);
    let input_script = multi_script(2, [input_keys[0].0, input_keys[1].0]);
    let (txin, input) = input_for(format, &input_script, INPUT_SATS, &input_keys);
    let (change_txout, change_output) = output_for(
        format,
        &multi_script(2, [change_keys[0].0, change_keys[1].0]),
        &change_keys,
    );

    let payment = keys_at(&secp, &account_path(format, 0), "0/0", &[master(3)]);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: vec![
            change_txout,
            TxOut {
                value: Amount::from_sat(PAYMENT_SATS),
                script_pubkey: Address::p2wpkh(&CompressedPublicKey(payment[0].0), NETWORK)
                    .script_pubkey(),
            },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs = vec![input];
    psbt.outputs = vec![change_output, psbt::Output::default()];
    for (master, account) in masters.iter().zip(&accounts) {
        psbt.xpub.insert(
            xpub_at(&secp, master, account),
            (master.fingerprint(&secp), account.clone()),
        );
    }

    let signers = masters
        .iter()
        .zip(&accounts)
        .map(|(master, account)| {
            MultiSigSigner::new(
                account,
                &master.fingerprint(&secp),
                &xpub_at(&secp, master, account),
            )
        })
        .collect();
    let details =
        MultiSigDetails::new(2, 2, format, Some(NetworkKind::Test.into()), signers).unwrap();
    (psbt, details)
}

#[test]
fn registered_vendor_paths_validate_against_saved_signer_roots() {
    let cases = [
        (
            AddressType::P2ShWsh,
            [
                DerivationPath::from_str("m/49/1/0").unwrap(),
                DerivationPath::from_str("m/49/1/0").unwrap(),
            ],
        ),
        (
            AddressType::P2ShWsh,
            [
                DerivationPath::from_str("m/45'/1/0").unwrap(),
                DerivationPath::from_str("m/45'/1/0").unwrap(),
            ],
        ),
        (
            AddressType::P2wsh,
            [
                DerivationPath::from_str("m/45'/1'/11'/2").unwrap(),
                DerivationPath::from_str("m/45'/1'/12'/2").unwrap(),
            ],
        ),
    ];

    for (format, accounts) in cases {
        let (mut psbt, details) = honest_psbt_with_roots(format, accounts.clone());
        let result = validate_with(&details, &psbt).expect("registered spend must validate");
        assert!(
            matches!(result.outputs[0].kind, OutputKind::Change(_)),
            "format {format:?}"
        );
        assert_eq!(result.display_total(), Amount::from_sat(PAYMENT_SATS));

        let receive_keys =
            keys_at_roots(&Secp256k1::new(), &accounts, "0/7", &[master(1), master(2)]);
        let receive_script = multi_script(2, [receive_keys[0].0, receive_keys[1].0]);
        let (receive_txout, receive_output) = output_for(format, &receive_script, &receive_keys);
        psbt.unsigned_tx.output[0] = receive_txout;
        psbt.outputs[0] = receive_output;

        let result = validate_with(&details, &psbt).expect("registered transfer must validate");
        assert!(
            matches!(result.outputs[0].kind, OutputKind::Transfer { .. }),
            "format {format:?}"
        );
    }
}

fn validate_with(details: &MultiSigDetails, psbt: &Psbt) -> Result<TransactionDetails, Error> {
    validate(&Secp256k1::new(), &master(1), psbt, NETWORK, Some(details))
}

/// A PSBT with the honest change output replaced by an attacker-crafted
/// `threshold`-of-N multisig output over `keys`.
fn change_attack_psbt(format: AddressType, threshold: i64, keys: &Keys) -> (Psbt, MultiSigDetails) {
    let (mut psbt, details) = honest_psbt(format);
    let script = multi_script(threshold, keys.iter().map(|(key, _, _)| *key));
    let (txout, output) = output_for(format, &script, keys);
    psbt.unsigned_tx.output[0] = txout;
    psbt.outputs[0] = output;
    (psbt, details)
}

/// The attack output must be External and counted in the displayed total.
fn assert_external_and_counted(details: &MultiSigDetails, psbt: &Psbt) {
    let result = validate_with(details, psbt).expect("must not abort review");
    assert!(
        matches!(result.outputs[0].kind, OutputKind::External(_)),
        "expected External, got {:?}",
        result.outputs[0].kind
    );
    assert_eq!(
        result.display_total(),
        Amount::from_sat(CHANGE_SATS + PAYMENT_SATS)
    );
}

#[test]
fn registered_change_is_change() {
    for format in FORMATS {
        let (psbt, details) = honest_psbt(format);
        let result = validate_with(&details, &psbt).expect("honest spend must validate");
        assert!(
            matches!(result.outputs[0].kind, OutputKind::Change(_)),
            "format {format:?}"
        );
        assert_eq!(result.display_total(), Amount::from_sat(PAYMENT_SATS));
    }
}

/// The attacker registers their own account xpub in the PSBT global map so
/// every key resolves cleanly.
#[test]
fn sft7394_foreign_cosigner_with_global_xpub_is_external() {
    for format in FORMATS {
        let secp = Secp256k1::new();
        let acct = account_path(format, 0);
        let keys = keys_at(&secp, &acct, "1/0", &[master(1), master(3)]);
        let (mut psbt, details) = change_attack_psbt(format, 1, &keys);
        psbt.xpub.insert(
            xpub_at(&secp, &master(3), &acct),
            (master(3).fingerprint(&secp), acct.clone()),
        );
        assert_external_and_counted(&details, &psbt);
    }
}

/// Reduced threshold using only the registered keys (hostage variant).
#[test]
fn reduced_threshold_with_registered_keys_is_external() {
    for format in FORMATS {
        let secp = Secp256k1::new();
        let keys = keys_at(
            &secp,
            &account_path(format, 0),
            "1/0",
            &[master(1), master(2)],
        );
        let (psbt, details) = change_attack_psbt(format, 1, &keys);
        assert_external_and_counted(&details, &psbt);
    }
}

/// Change matching a *different* account of the same signers (account 1').
#[test]
fn cross_account_change_is_external() {
    for format in FORMATS {
        let secp = Secp256k1::new();
        let keys = keys_at(
            &secp,
            &account_path(format, 1),
            "1/0",
            &[master(1), master(2)],
        );
        let (psbt, details) = change_attack_psbt(format, 2, &keys);
        assert_external_and_counted(&details, &psbt);
    }
}

/// The poisoned-input bypass: an attacker-funded 1-of-2 input containing the
/// device key must not authorize attacker-controlled change, because the
/// input itself is rejected as not belonging to the registered account.
#[test]
fn poisoned_input_policy_is_rejected() {
    for format in FORMATS {
        let secp = Secp256k1::new();
        let acct = account_path(format, 0);
        let (mut psbt, details) = honest_psbt(format);
        let keys = keys_at(&secp, &acct, "0/0", &[master(1), master(3)]);
        let script = multi_script(1, [keys[0].0, keys[1].0]);
        let (txin, input) = input_for(format, &script, 1_000, &keys);
        psbt.unsigned_tx.input.push(txin);
        psbt.inputs.push(input);
        psbt.xpub.insert(
            xpub_at(&secp, &master(3), &acct),
            (master(3).fingerprint(&secp), acct.clone()),
        );

        assert!(
            matches!(
                validate_with(&details, &psbt),
                Err(Error::FraudulentInput { index: 1 })
            ),
            "attacker-funded 1-of-2 input must be rejected (format {format:?})"
        );
    }
}

#[test]
fn discovery_mode_reports_descriptors_but_never_change() {
    for format in FORMATS {
        let (psbt, _details) = honest_psbt(format);
        let result = validate(&Secp256k1::new(), &master(1), &psbt, NETWORK, None)
            .expect("discovery must succeed");

        // Reconstructed descriptors let the caller find the account...
        let prefix = match format {
            AddressType::P2wsh => "wsh(sortedmulti(2,",
            AddressType::P2ShWsh => "sh(wsh(sortedmulti(2,",
            other => panic!("{other:?}"),
        };
        assert!(
            result
                .descriptors
                .iter()
                .any(|d| d.to_string().starts_with(prefix))
        );
        // ...but even honest change is External without the registered config.
        assert!(matches!(result.outputs[0].kind, OutputKind::External(_)));
        assert_eq!(
            result.display_total(),
            Amount::from_sat(CHANGE_SATS + PAYMENT_SATS)
        );
    }
}

/// A 2-of-2 script with derivation metadata for only one key, and an
/// impossible 2-of-1 script, both used to panic descriptor reconstruction.
#[test]
fn env3050_inconsistent_metadata_never_panics() {
    for format in FORMATS {
        let secp = Secp256k1::new();
        let acct = account_path(format, 0);
        let keys = keys_at(&secp, &acct, "0/0", &[master(1), master(2)]);

        let cases = [
            // Complete script, incomplete metadata (2-of-2, one derivation).
            (multi_script(2, [keys[0].0, keys[1].0]), &keys[..1]),
            // Impossible threshold (2-of-1).
            (multi_script(2, [keys[0].0]), &keys[..1]),
        ];
        for (script, declared) in &cases {
            let (txin, input) = input_for(format, script, INPUT_SATS, declared);
            let mut psbt = Psbt::from_unsigned_tx(Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![txin],
                output: vec![],
            })
            .unwrap();
            psbt.inputs = vec![input];
            for m in [master(1), master(2)] {
                psbt.xpub.insert(
                    xpub_at(&secp, &m, &acct),
                    (m.fingerprint(&secp), acct.clone()),
                );
            }

            let result = std::panic::catch_unwind(|| {
                validate(&Secp256k1::new(), &master(1), &psbt, NETWORK, None)
            });
            assert!(
                matches!(result, Ok(Err(_))),
                "inconsistent metadata must error without panicking (format {format:?})"
            );
        }
    }
}

/// Output metadata whose derivation paths disagree cannot authorize change.
#[test]
fn mismatched_output_paths_are_external() {
    for format in FORMATS {
        let secp = Secp256k1::new();
        let (mut psbt, details) = honest_psbt(format);
        let cosigner_change =
            keys_at(&secp, &account_path(format, 0), "1/0", &[master(2)]).remove(0);
        // Corrupt the cosigner's declared path so the paths no longer agree.
        let wrong_path =
            DerivationPath::from_str(&format!("{}/1/9", account_path(format, 0))).unwrap();
        psbt.outputs[0]
            .bip32_derivation
            .insert(cosigner_change.0, (cosigner_change.1, wrong_path));

        let result = validate_with(&details, &psbt).expect("must not abort review");
        assert!(
            matches!(result.outputs[0].kind, OutputKind::External(_)),
            "format {format:?}"
        );
    }
}

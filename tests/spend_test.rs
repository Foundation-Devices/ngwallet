mod utils;

///PSBT input-validation
#[cfg(test)]
mod psbt_security_tests {
    use bdk_wallet::bitcoin::absolute::LockTime;
    use bdk_wallet::bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
    use bdk_wallet::bitcoin::psbt;
    use bdk_wallet::bitcoin::psbt::Psbt;
    use bdk_wallet::bitcoin::secp256k1::{All, PublicKey, Secp256k1};
    use bdk_wallet::bitcoin::transaction::Version;
    use bdk_wallet::bitcoin::{
        Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, Sequence, Transaction,
        TxIn, TxOut, Txid, Witness,
    };
    use ngwallet::psbt::{Error, validate};
    use std::str::FromStr;

    const TEST_MASTER_XPRIV: &str = "tprv8ZgxMBicQKsPeLx4U7UmbcYU5VhS4BRxv86o1gNqNqxEEJL47F9ZZhvBi1EVbKPmmFYnTEZ6uArarK6zZyrZf7mSyWZRAuNKQp4dHfxBdMM";

    fn test_secp() -> Secp256k1<All> {
        Secp256k1::new()
    }

    fn test_master_key() -> Xpriv {
        Xpriv::from_str(TEST_MASTER_XPRIV).unwrap()
    }

    fn derive_test_key(
        secp: &Secp256k1<All>,
        path_str: &str,
    ) -> (PublicKey, DerivationPath, Fingerprint) {
        let master = test_master_key();
        let fp = master.fingerprint(secp);
        let path: DerivationPath = path_str.parse().unwrap();
        let child = master.derive_priv(secp, &path).unwrap();
        let xpub = Xpub::from_priv(secp, &child);
        (xpub.public_key, path, fp)
    }

    fn dummy_txin(txid: Txid) -> TxIn {
        TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    /// Build a minimal unsigned tx spending from `txid:0` with one OP_RETURN output.
    fn dummy_unsigned_tx(txid: Txid) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![dummy_txin(txid)],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: ScriptBuf::new_op_return([]),
            }],
        }
    }

    /// Build a previous transaction whose output[0] is `txout`, and return
    /// the (prev_tx, computed_txid) pair.
    fn prev_tx_with_output(txout: TxOut) -> (Transaction, Txid) {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![txout],
        };
        let txid = tx.compute_txid();
        (tx, txid)
    }

    //witness_utxo/non_witness_utxo consistency

    #[test]
    fn psbt_rejects_forged_witness_utxo_value() {
        // The on-chain output pays 1 000 sat, but witness_utxo claims 999 999.
        let secp = test_secp();
        let master = test_master_key();
        let (pk, path, fp) = derive_test_key(&secp, "m/84'/1'/0'/0/0");

        let address = Address::p2wpkh(&CompressedPublicKey(pk), Network::Testnet);
        let real_txout = TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: address.script_pubkey(),
        };
        let forged_txout = TxOut {
            value: Amount::from_sat(999_999), // inflated
            script_pubkey: address.script_pubkey(),
        };

        let (prev_tx, txid) = prev_tx_with_output(real_txout);
        let unsigned_tx = dummy_unsigned_tx(txid);
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

        let mut inp = psbt::Input {
            non_witness_utxo: Some(prev_tx),
            witness_utxo: Some(forged_txout),
            ..Default::default()
        };
        inp.bip32_derivation.insert(pk, (fp, path));
        psbt.inputs = vec![inp];

        assert!(
            matches!(
                validate(&secp, &master, &psbt, Network::Testnet),
                Err(Error::FraudulentInput { index: 0 })
            ),
            "forged witness_utxo value must be rejected"
        );
    }

    #[test]
    fn psbt_rejects_forged_witness_utxo_script() {
        // The on-chain output pays to our address, but witness_utxo uses a
        // different script at the same value.
        let secp = test_secp();
        let master = test_master_key();
        let (pk, path, fp) = derive_test_key(&secp, "m/84'/1'/0'/0/0");

        let address = Address::p2wpkh(&CompressedPublicKey(pk), Network::Testnet);
        let real_txout = TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: address.script_pubkey(),
        };
        let forged_txout = TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new_op_return([0x42]), // wrong script
        };

        let (prev_tx, txid) = prev_tx_with_output(real_txout);
        let unsigned_tx = dummy_unsigned_tx(txid);
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

        let mut inp = psbt::Input {
            non_witness_utxo: Some(prev_tx),
            witness_utxo: Some(forged_txout),
            ..Default::default()
        };
        inp.bip32_derivation.insert(pk, (fp, path));
        psbt.inputs = vec![inp];

        assert!(
            matches!(
                validate(&secp, &master, &psbt, Network::Testnet),
                Err(Error::FraudulentInput { index: 0 })
            ),
            "forged witness_utxo script must be rejected"
        );
    }

    #[test]
    fn psbt_accepts_consistent_funding_pair() {
        // When witness_utxo and non_witness_utxo agree, validate must not
        let secp = test_secp();
        let master = test_master_key();
        let (pk, path, fp) = derive_test_key(&secp, "m/84'/1'/0'/0/0");

        let address = Address::p2wpkh(&CompressedPublicKey(pk), Network::Testnet);
        let txout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: address.script_pubkey(),
        };

        let (prev_tx, txid) = prev_tx_with_output(txout.clone());
        let unsigned_tx = dummy_unsigned_tx(txid);
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

        let mut inp = psbt::Input {
            non_witness_utxo: Some(prev_tx),
            witness_utxo: Some(txout), // identical — consistent
            ..Default::default()
        };
        inp.bip32_derivation.insert(pk, (fp, path));
        psbt.inputs = vec![inp];

        let result = validate(&secp, &master, &psbt, Network::Testnet);
        assert!(
            !matches!(result, Err(Error::FraudulentInput { index: 0 })),
            "consistent funding pair must not be rejected as fraudulent, got: {result:?}"
        );
    }

    //legacy P2PKH requires non_witness_utxo

    #[test]
    fn psbt_rejects_p2pkh_without_non_witness_utxo() {
        let secp = test_secp();
        let master = test_master_key();
        let (pk, path, fp) = derive_test_key(&secp, "m/44'/1'/0'/0/0");

        let address = Address::p2pkh(CompressedPublicKey(pk), Network::Testnet);
        let funding_out = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: address.script_pubkey(),
        };

        let fake_txid =
            Txid::from_str("abababababababababababababababababababababababababababababababab")
                .unwrap();
        let unsigned_tx = dummy_unsigned_tx(fake_txid);
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

        let mut inp = psbt::Input {
            witness_utxo: Some(funding_out), // no non_witness_utxo
            ..Default::default()
        };
        inp.bip32_derivation.insert(pk, (fp, path));
        psbt.inputs = vec![inp];

        assert!(
            matches!(
                validate(&secp, &master, &psbt, Network::Testnet),
                Err(Error::MissingInputFundingUtxo { index: 0 })
            ),
            "P2PKH input without non_witness_utxo must be rejected"
        );
    }

    //P2WSH script hash binding

    #[test]
    fn psbt_rejects_p2wsh_wrong_witness_script_hash() {
        let secp = test_secp();
        let master = test_master_key();
        let (pk, path, fp) = derive_test_key(&secp, "m/48'/1'/0'/2'/0/0");

        let real_witness_script = {
            use bdk_wallet::bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_1};
            use bdk_wallet::bitcoin::script::Builder;
            Builder::new()
                .push_opcode(OP_PUSHNUM_1)
                .push_key(&bdk_wallet::bitcoin::PublicKey::new(pk))
                .push_opcode(OP_PUSHNUM_1)
                .push_opcode(OP_CHECKMULTISIG)
                .into_script()
        };
        let real_spk = ScriptBuf::new_p2wsh(&real_witness_script.wscript_hash());

        let fake_txid =
            Txid::from_str("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
                .unwrap();
        let unsigned_tx = dummy_unsigned_tx(fake_txid);
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

        let mut inp = psbt::Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: real_spk,
            }),
            witness_script: Some(ScriptBuf::new()), // wrong — empty script
            ..Default::default()
        };
        inp.bip32_derivation.insert(pk, (fp, path));
        psbt.inputs = vec![inp];

        assert!(
            matches!(
                validate(&secp, &master, &psbt, Network::Testnet),
                Err(Error::FraudulentInput { index: 0 })
            ),
            "P2WSH witness_script hash mismatch must be rejected"
        );
    }

    // P2SH-P2WSH script hash binding

    #[test]
    fn psbt_rejects_p2sh_wrong_redeem_script_hash() {
        let secp = test_secp();
        let master = test_master_key();
        let (pk, path, fp) = derive_test_key(&secp, "m/48'/1'/0'/1'/0/0");

        let witness_script = {
            use bdk_wallet::bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_1};
            use bdk_wallet::bitcoin::script::Builder;
            Builder::new()
                .push_opcode(OP_PUSHNUM_1)
                .push_key(&bdk_wallet::bitcoin::PublicKey::new(pk))
                .push_opcode(OP_PUSHNUM_1)
                .push_opcode(OP_CHECKMULTISIG)
                .into_script()
        };
        let real_redeem_script = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
        let real_p2sh_spk = ScriptBuf::new_p2sh(&real_redeem_script.script_hash());
        let forged_redeem_script = ScriptBuf::new_p2wsh(&ScriptBuf::new().wscript_hash()); // different hash

        let fake_txid =
            Txid::from_str("efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef")
                .unwrap();
        let unsigned_tx = dummy_unsigned_tx(fake_txid);
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

        let mut inp = psbt::Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: real_p2sh_spk,
            }),
            redeem_script: Some(forged_redeem_script),
            witness_script: Some(witness_script),
            ..Default::default()
        };
        inp.bip32_derivation.insert(pk, (fp, path));
        psbt.inputs = vec![inp];

        assert!(
            matches!(
                validate(&secp, &master, &psbt, Network::Testnet),
                Err(Error::FraudulentInput { index: 0 })
            ),
            "P2SH redeem_script hash mismatch must be rejected"
        );
    }

    #[test]
    fn psbt_rejects_p2sh_p2wsh_wrong_witness_script_hash() {
        let secp = test_secp();
        let master = test_master_key();
        let (pk, path, fp) = derive_test_key(&secp, "m/48'/1'/0'/1'/0/0");

        let real_witness_script = {
            use bdk_wallet::bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_1};
            use bdk_wallet::bitcoin::script::Builder;
            Builder::new()
                .push_opcode(OP_PUSHNUM_1)
                .push_key(&bdk_wallet::bitcoin::PublicKey::new(pk))
                .push_opcode(OP_PUSHNUM_1)
                .push_opcode(OP_CHECKMULTISIG)
                .into_script()
        };
        let real_redeem_script = ScriptBuf::new_p2wsh(&real_witness_script.wscript_hash());
        let real_p2sh_spk = ScriptBuf::new_p2sh(&real_redeem_script.script_hash());

        let fake_txid =
            Txid::from_str("0101010101010101010101010101010101010101010101010101010101010101")
                .unwrap();
        let unsigned_tx = dummy_unsigned_tx(fake_txid);
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

        let mut inp = psbt::Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: real_p2sh_spk,
            }),
            redeem_script: Some(real_redeem_script), // correct outer binding
            witness_script: Some(ScriptBuf::new()),  // wrong inner — empty
            ..Default::default()
        };
        inp.bip32_derivation.insert(pk, (fp, path));
        psbt.inputs = vec![inp];

        assert!(
            matches!(
                validate(&secp, &master, &psbt, Network::Testnet),
                Err(Error::FraudulentInput { index: 0 })
            ),
            "P2SH-P2WSH witness_script hash mismatch must be rejected"
        );
    }
}

#[cfg(test)]
#[cfg(feature = "envoy")]
mod spend_tests {
    use crate::utils::tests_util;
    use bdk_wallet::rusqlite::Connection;
    use ngwallet::account::NgAccount;
    use ngwallet::rbf::BumpFeeError;
    use ngwallet::send::{
        DraftTransaction, FeeRateSatPerKvb, TransactionComposeError, TransactionParams,
    };

    use crate::utils::tests_util::get_ng_hot_wallet;

    #[test]
    fn test_max_fee_calc() {
        let mut account = get_ng_hot_wallet();
        tests_util::add_funds_to_wallet(&mut account);
        let params = TransactionParams {
            address: "tb1pspfcrvz538vvj9f9gfkd85nu5ty98zw9y5e302kha6zurv6vg07s8z7a8w".to_string(),
            amount: 2003,
            fee_rate: FeeRateSatPerKvb(1000), // 1 sat/vB in sat/kvB
            selected_outputs: vec![],
            note: Some("not a note".to_string()),
            tag: Some("hello".to_string()),
            do_not_spend_change: false,
        };
        let draft = account.get_max_fee(params.clone()).unwrap();
        assert_eq!(draft.max_fee_rate, FeeRateSatPerKvb(553_828)); // 138_457 sat/kwu * 4 = sat/kvB
        assert_eq!(draft.min_fee_rate, FeeRateSatPerKvb(1000)); // 1 sat/vB in sat/kvB
        check_draft_tx_match_params(draft.draft_transaction.clone(), params.clone());
    }

    #[test]
    fn test_compose_psbt() {
        let mut account = get_ng_hot_wallet();
        tests_util::add_funds_to_wallet(&mut account);
        let params = TransactionParams {
            address: "tb1pspfcrvz538vvj9f9gfkd85nu5ty98zw9y5e302kha6zurv6vg07s8z7a8w".to_string(),
            amount: 4000,
            fee_rate: FeeRateSatPerKvb(2000), // 2 sat/vB in sat/kvB
            selected_outputs: vec![],
            note: Some("not a note".to_string()),
            tag: Some("hello".to_string()),
            do_not_spend_change: false,
        };
        let draft = account.compose_psbt(params.clone()).unwrap();
        check_draft_tx_match_params(draft, params.clone());
    }

    #[test]
    #[cfg(feature = "envoy")]
    fn test_check_compose_increment_index() {
        let mut account = get_ng_hot_wallet();
        tests_util::add_funds_to_wallet(&mut account);
        let initial_indexes = account.get_derivation_index();
        let params = TransactionParams {
            address: "tb1pspfcrvz538vvj9f9gfkd85nu5ty98zw9y5e302kha6zurv6vg07s8z7a8w".to_string(),
            amount: 1000,
            fee_rate: FeeRateSatPerKvb(2000), // 2 sat/vB in sat/kvB
            selected_outputs: vec![],
            note: Some("not a note".to_string()),
            tag: Some("hello".to_string()),
            do_not_spend_change: false,
        };
        let draft = account.compose_psbt(params.clone()).unwrap();
        check_draft_tx_match_params(draft, params.clone());
        let draft = account.compose_psbt(params.clone()).unwrap();
        check_draft_tx_match_params(draft, params.clone());
        account.persist().unwrap();
        let post_compose_indexes = account.get_derivation_index();
        assert_eq!(initial_indexes, post_compose_indexes);
    }

    #[test]
    fn test_address_formats() {
        let mut account = get_ng_hot_wallet();
        tests_util::add_funds_to_wallet(&mut account);

        let test_addresses = vec![
            "TB1QG6EPY90XX0HVHEGETCX7T8PMWA5YDP4SEEAN6Q", // uppercase bech32
            "tb1qg6epy90xx0hvhegetcx7t8pmwa5ydp4seean6q", // lowercase bech32
            "mxq7YK9GRJ5HjB9JqTThpAaJqwZ5D6KYtP",         // legacy P2PKH
            "tb1pspfcrvz538vvj9f9gfkd85nu5ty98zw9y5e302kha6zurv6vg07s8z7a8w", // taproot
            "2N3pSqDGfk16FrS91bXZi63Ns4VoeWnzQQf",        // p2sh
        ];

        for address in test_addresses {
            test_address_compose(&mut account, address);
        }
    }

    fn test_address_compose(account: &mut NgAccount<Connection>, address: &str) {
        let initial_indexes = account.get_derivation_index();
        let params = TransactionParams {
            address: address.to_string(),
            amount: 1000,
            fee_rate: FeeRateSatPerKvb(2000), // 2 sat/vB in sat/kvB
            selected_outputs: vec![],
            note: Some("not a note".to_string()),
            tag: Some("hello".to_string()),
            do_not_spend_change: false,
        };

        let draft = account.compose_psbt(params.clone()).unwrap();
        let transaction = draft.transaction.clone();
        check_draft_tx_match_params(draft, params.clone());

        let draft = account.compose_psbt(params.clone()).unwrap();
        check_draft_tx_match_params(draft, params.clone());

        account.persist().unwrap();
        let post_compose_indexes = account.get_derivation_index();

        // Verify derivation indexes remain unchanged,
        assert_eq!(initial_indexes, post_compose_indexes);

        // verify transaction properties
        assert_eq!(transaction.amount, -1000);
        assert_eq!(transaction.address, address);
        assert_eq!(transaction.note, params.note);
        assert_eq!(transaction.get_change_tag(), params.tag);
    }

    #[test]
    #[cfg(feature = "envoy")]
    fn test_rbf() {
        let mut account = get_ng_hot_wallet();
        tests_util::add_funds_wallet_with_unconfirmed(&mut account);
        let transactions = account.transactions().unwrap();
        let unconfirmed_tx = transactions
            .iter()
            .find(|tx| tx.confirmations == 0)
            .unwrap();
        let rbf_max_result = account
            .get_max_bump_fee(vec![], unconfirmed_tx.clone())
            .expect("Failed to get max bump fee");

        assert_eq!(rbf_max_result.max_fee_rate, FeeRateSatPerKvb(126_896)); // 31_724 sat/kwu * 4 = sat/kvB
        assert!(unconfirmed_tx.fee_rate < rbf_max_result.min_fee_rate);
        //
    }

    //
    fn check_draft_tx_match_params(draft_transaction: DraftTransaction, params: TransactionParams) {
        let transaction = draft_transaction.transaction.clone();
        assert_eq!(transaction.address, params.address);
        assert_eq!(transaction.amount, -(params.amount as i64));
        assert_eq!(transaction.note, params.note);
        assert_eq!(transaction.get_change_tag(), params.tag);
    }

    // Audit P2-01: a UTXO marked do_not_spend must never be spent, even when
    // the caller passes it explicitly in `selected_outputs`. Both the send
    // and RBF paths share this policy and must surface a dedicated error.

    #[test]
    fn test_compose_psbt_rejects_locked_selected_utxo() {
        let mut account = get_ng_hot_wallet();
        tests_util::add_funds_to_wallet(&mut account);

        let locked = account.utxos().unwrap()[0].clone();
        account
            .set_do_not_spend(locked.get_id().as_str(), true)
            .unwrap();
        let locked_live = account
            .utxos()
            .unwrap()
            .into_iter()
            .find(|o| o.get_id() == locked.get_id())
            .expect("locked utxo should still exist");
        assert!(locked_live.do_not_spend);

        let params = TransactionParams {
            address: "tb1pspfcrvz538vvj9f9gfkd85nu5ty98zw9y5e302kha6zurv6vg07s8z7a8w".to_string(),
            amount: 4000,
            fee_rate: FeeRateSatPerKvb(2000),
            selected_outputs: vec![locked_live.clone()],
            note: None,
            tag: None,
            do_not_spend_change: false,
        };
        match account.compose_psbt(params) {
            Err(TransactionComposeError::LockedUtxoSelected(ids)) => {
                assert_eq!(ids, vec![locked_live.get_id()]);
            }
            other => panic!("expected LockedUtxoSelected, got {other:?}"),
        }
    }

    // A caller cannot bypass the lock by zeroing `do_not_spend` on the
    // Output values it passes in `selected_outputs`. The wallet's live UTXO
    // set is the source of truth.
    #[test]
    fn test_compose_psbt_rejects_stale_unlocked_selected_utxo() {
        let mut account = get_ng_hot_wallet();
        tests_util::add_funds_to_wallet(&mut account);

        let locked_id = {
            let utxo = account.utxos().unwrap()[0].clone();
            account
                .set_do_not_spend(utxo.get_id().as_str(), true)
                .unwrap();
            utxo.get_id()
        };

        let mut stale = account
            .utxos()
            .unwrap()
            .into_iter()
            .find(|o| o.get_id() == locked_id)
            .unwrap();
        // Simulate a compromised caller forging do_not_spend=false.
        stale.do_not_spend = false;

        let params = TransactionParams {
            address: "tb1pspfcrvz538vvj9f9gfkd85nu5ty98zw9y5e302kha6zurv6vg07s8z7a8w".to_string(),
            amount: 4000,
            fee_rate: FeeRateSatPerKvb(2000),
            selected_outputs: vec![stale],
            note: None,
            tag: None,
            do_not_spend_change: false,
        };
        match account.compose_psbt(params) {
            Err(TransactionComposeError::LockedUtxoSelected(ids)) => {
                assert_eq!(ids, vec![locked_id]);
            }
            other => panic!("expected LockedUtxoSelected, got {other:?}"),
        }
    }

    #[test]
    fn test_get_max_fee_rejects_locked_selected_utxo() {
        let mut account = get_ng_hot_wallet();
        tests_util::add_funds_to_wallet(&mut account);

        let locked = account.utxos().unwrap()[0].clone();
        account
            .set_do_not_spend(locked.get_id().as_str(), true)
            .unwrap();
        let locked_live = account
            .utxos()
            .unwrap()
            .into_iter()
            .find(|o| o.get_id() == locked.get_id())
            .unwrap();

        let params = TransactionParams {
            address: "tb1pspfcrvz538vvj9f9gfkd85nu5ty98zw9y5e302kha6zurv6vg07s8z7a8w".to_string(),
            amount: 2003,
            fee_rate: FeeRateSatPerKvb(1000),
            selected_outputs: vec![locked_live.clone()],
            note: None,
            tag: None,
            do_not_spend_change: false,
        };
        match account.get_max_fee(params) {
            Err(TransactionComposeError::LockedUtxoSelected(ids)) => {
                assert_eq!(ids, vec![locked_live.get_id()]);
            }
            other => panic!("expected LockedUtxoSelected, got {other:?}"),
        }
    }

    #[test]
    fn test_rbf_rejects_locked_selected_utxo() {
        let mut account = get_ng_hot_wallet();
        tests_util::add_funds_wallet_with_unconfirmed(&mut account);

        // Lock a confirmed mature UTXO (one of the funding outputs) so the
        // RBF builder will see it as a candidate input.
        let mature = account
            .utxos()
            .unwrap()
            .into_iter()
            .find(|o| o.is_confirmed)
            .expect("at least one confirmed utxo");
        account
            .set_do_not_spend(mature.get_id().as_str(), true)
            .unwrap();
        let locked_live = account
            .utxos()
            .unwrap()
            .into_iter()
            .find(|o| o.get_id() == mature.get_id())
            .unwrap();

        let unconfirmed_tx = account
            .transactions()
            .unwrap()
            .into_iter()
            .find(|tx| tx.confirmations == 0)
            .expect("expected an unconfirmed tx for RBF");

        match account.get_max_bump_fee(vec![locked_live.clone()], unconfirmed_tx) {
            Err(BumpFeeError::LockedUtxoSelected(ids)) => {
                assert_eq!(ids, vec![locked_live.get_id()]);
            }
            other => panic!("expected LockedUtxoSelected, got {other:?}"),
        }
    }
}

// fn pretty_print<T: serde::Serialize>(value: &T) -> String {
//     serde_json::to_string_pretty(value).unwrap()
// }

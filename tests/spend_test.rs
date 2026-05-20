mod utils;

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

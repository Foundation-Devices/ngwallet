mod ng_test_utils;

#[cfg(test)]
#[cfg(feature = "envoy")]
mod spend_tests {
    use bdk_wallet::bitcoin::Network;
    use std::sync::{Arc, Mutex};

    use ngwallet::send::{DraftTransaction, TransactionParams};
    use {
        crate::*, bdk_wallet::rusqlite::Connection, ngwallet::account::Descriptor,
        ngwallet::account::NgAccount, ngwallet::config::AddressType, redb::backends::FileBackend,
    };

    #[test]
    fn test_max_fee_calc() {
        let mut account = get_ng_account();
        ng_test_utils::add_funds_to_wallet(&mut account);
        let params = TransactionParams {
            address: "tb1pspfcrvz538vvj9f9gfkd85nu5ty98zw9y5e302kha6zurv6vg07s8z7a8w".to_string(),
            amount: 2003,
            fee_rate: 1,
            selected_outputs: vec![],
            note: Some("not a note".to_string()),
            tag: Some("hello".to_string()),
            do_not_spend_change: false,
        };
        let draft = account.get_max_fee(params.clone()).unwrap();
        assert_eq!(draft.max_fee_rate, 553);
        assert_eq!(draft.min_fee_rate, 1);
        check_draft_tx_match_params(draft.draft_transaction.clone(), params.clone());
    }

    #[test]
    fn test_compose_psbt() {
        let mut account = get_ng_account();
        ng_test_utils::add_funds_to_wallet(&mut account);
        let params = TransactionParams {
            address: "tb1pspfcrvz538vvj9f9gfkd85nu5ty98zw9y5e302kha6zurv6vg07s8z7a8w".to_string(),
            amount: 4000,
            fee_rate: 2,
            selected_outputs: vec![],
            note: Some("not a note".to_string()),
            tag: Some("hello".to_string()),
            do_not_spend_change: false,
        };
        let draft = account.compose_psbt(params.clone()).unwrap();
        check_draft_tx_match_params(draft, params.clone());
    }

    #[test]
    fn test_check_compose_increment_index() {
        let mut account = get_ng_account();
        ng_test_utils::add_funds_to_wallet(&mut account);
        let initial_indexes = account.get_derivation_index();
        let params = TransactionParams {
            address: "tb1pspfcrvz538vvj9f9gfkd85nu5ty98zw9y5e302kha6zurv6vg07s8z7a8w".to_string(),
            amount: 1000,
            fee_rate: 2,
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

    //
    #[test]
    fn test_rbf() {
        let mut account = get_ng_account();
        ng_test_utils::add_funds_wallet_with_unconfirmed(&mut account);
        let transactions = account.transactions().unwrap();
        let unconfirmed_tx = transactions
            .iter()
            .find(|tx| tx.confirmations == 0)
            .unwrap();
        let rbf_max_result = account
            .get_max_bump_fee(vec![], unconfirmed_tx.clone())
            .expect("Failed to get max bump fee");

        assert_eq!(rbf_max_result.max_fee_rate, 658);
        assert!(unconfirmed_tx.fee_rate < rbf_max_result.min_fee_rate);
        //
    }

    //
    fn check_draft_tx_match_params(draft_transaction: DraftTransaction, params: TransactionParams) {
        let transaction = draft_transaction.transaction.clone();
        assert_eq!(transaction.address, params.address);
        assert_eq!(transaction.amount, -(params.amount as i64));
        assert_eq!(transaction.fee_rate, params.fee_rate);
        assert_eq!(transaction.note, params.note);
        assert_eq!(transaction.get_change_tag(), params.tag);
    }

    //creates a new account with the descriptors,in memory db's
    fn get_ng_account() -> NgAccount<Connection> {
        const CHANGE_DESCRIPTOR: &str = "sh(wpkh(tprv8ZgxMBicQKsPeLx4U7UmbcYU5VhS4BRxv86o1gNqNqxEEJL47F9ZZhvBi1EVbKPmmFYnTEZ6uArarK6zZyrZf7mSyWZRAuNKQp4dHfxBdMM/49'/1'/0'/1/*))#ehhlgts8";
        const DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPeLx4U7UmbcYU5VhS4BRxv86o1gNqNqxEEJL47F9ZZhvBi1EVbKPmmFYnTEZ6uArarK6zZyrZf7mSyWZRAuNKQp4dHfxBdMM/86'/1'/0'/0/*)#uw0tj973";

        const CHANGE_DESCRIPTOR_2: &str = "sh(wpkh(tprv8ZgxMBicQKsPeLx4U7UmbcYU5VhS4BRxv86o1gNqNqxEEJL47F9ZZhvBi1EVbKPmmFYnTEZ6uArarK6zZyrZf7mSyWZRAuNKQp4dHfxBdMM/49'/1'/0'/1/*))#ehhlgts8";
        const DESCRIPTOR_2: &str = "wpkh(tprv8ZgxMBicQKsPeLx4U7UmbcYU5VhS4BRxv86o1gNqNqxEEJL47F9ZZhvBi1EVbKPmmFYnTEZ6uArarK6zZyrZf7mSyWZRAuNKQp4dHfxBdMM/84'/1'/0'/0/*)#gksznsj0";

        let descriptors = vec![
            Descriptor {
                internal: CHANGE_DESCRIPTOR.to_string(),
                external: Some(DESCRIPTOR.to_string()),
                bdk_persister: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
            },
            Descriptor {
                internal: CHANGE_DESCRIPTOR_2.to_string(),
                external: Some(DESCRIPTOR_2.to_string()),
                bdk_persister: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
            },
        ];

        let account: NgAccount<Connection> = NgAccount::new_from_descriptors(
            "Envoy".to_string(),
            "red".to_string(),
            None,
            None,
            Network::Signet,
            AddressType::P2tr,
            descriptors,
            0,
            None,
            //uses in memory meta db
            None::<FileBackend>,
            "".to_string(),
            None,
        );
        account
    }
}

// fn pretty_print<T: serde::Serialize>(value: &T) -> String {
//     serde_json::to_string_pretty(value).unwrap()
// }

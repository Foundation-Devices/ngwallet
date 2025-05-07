const INTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPeLx4U7UmbcYU5VhS4BRxv86o1gNqNqxEEJL47F9ZZhvBi1EVbKPmmFYnTEZ6uArarK6zZyrZf7mSyWZRAuNKQp4dHfxBdMM/84'/1'/0'/0/*)#gksznsj0";
const INTERNAL_DESCRIPTOR_2: &str = "tr(tprv8ZgxMBicQKsPeLx4U7UmbcYU5VhS4BRxv86o1gNqNqxEEJL47F9ZZhvBi1EVbKPmmFYnTEZ6uArarK6zZyrZf7mSyWZRAuNKQp4dHfxBdMM/86'/1'/0'/0/*)#uw0tj973";
#[cfg(feature = "envoy")]
const ELECTRUM_SERVER: &str = "ssl://mempool.space:60602";
mod ng_test_utils;
// TODO: make this unique to the descriptor
#[cfg(test)]
mod spend_tests {
    use std::sync::{Arc, Mutex};
    use ngwallet::send::TransactionParams;
    use ng_test_utils;
    #[cfg(feature = "envoy")]
    use {
        crate::*, bdk_wallet::Update, bdk_wallet::bitcoin::Network,
        bdk_wallet::rusqlite::Connection, ngwallet::account::Descriptor,
        ngwallet::account::NgAccount, ngwallet::config::AddressType, ngwallet::ngwallet::NgWallet,
        redb::backends::FileBackend,

    };

    #[test]
    #[cfg(feature = "envoy")]
    fn max_fee_and_compose() {
        let descriptors = vec![
            Descriptor {
                internal: INTERNAL_DESCRIPTOR_2.to_string(),
                external: None,
                bdk_persister: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
            },
            Descriptor {
                internal: INTERNAL_DESCRIPTOR.to_string(),
                external: None,
                bdk_persister: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
            },
        ];

        let mut account: NgAccount<Connection> = NgAccount::new_from_descriptors(
            "Passport Prime".to_string(),
            "red".to_string(),
            None,
            None,
            Network::Signet,
            AddressType::P2tr,
            descriptors,
            0,
            None,
            None::<FileBackend>,
            "".to_string(),
            None,
        );

        ng_test_utils::get_account_with_confirmed_unconfirmed(&mut account);


        //
        // let request = account.full_scan_request();
        //
        // for (index, request) in account.full_scan_request().into_iter().enumerate() {
        //     let update = NgWallet::<Connection>::scan(request, ELECTRUM_SERVER, None).unwrap();
        //     account.apply(Update::from(update)).unwrap();
        // }
        //
        let address = account.next_address().unwrap();
        address.iter().for_each(|address| {
            println!(
                "Generated address {} at index {}",
                address.address, address.index
            );
        });
        //
        let balance = account.wallet_balances().unwrap();
        println!("Wallet balance: {:?} sat\n", balance);
        //
        // let transactions = account.transactions().unwrap();
        // for tx in transactions {
        //     println!(
        //         "Transaction: {},{},{}",
        //         tx.address, tx.amount, tx.is_confirmed
        //     );
        // }
        //
        // let utxos = account.utxos();
        // utxos.unwrap().iter().for_each(|utxo| {
        //     println!("Utxo: {:?}", utxo);
        // });
        //
        // let transactions = account.transactions().unwrap();
        // //
        // // if !transactions.is_empty() {
        // //     let message = "Test Message".to_string();
        // //     println!("\nSetting note: {:?}", message);
        // //     account
        // //         .set_note(&transactions[0].tx_id, &message.clone())
        // //         .unwrap();
        // //     let transactions = account.transactions().unwrap();
        // //     let firs_tx = transactions[0].note.clone().unwrap_or("".to_string());
        // //     println!("Transaction note: {:?}", firs_tx);
        // //     assert_eq!(firs_tx, message);
        // // }
        // //
        // let utxos = account.utxos().unwrap_or(vec![]);
        // println!("Utxos: {}", serde_json::to_string_pretty(&utxos).unwrap());
        //
        // println!("Balance {:?}", balance);
        //
        let get_max = account
            .get_max_fee(TransactionParams {
                address: "tb1peljxqsyc45d7c3zr00u5f78w9v0uj57dc56e66cszr9qg94lchmqc2fcvp"
                    .to_string(),
                amount: 8000,
                fee_rate: 2,
                selected_outputs: vec![],
                note: Some("not a note".to_string()),
                tag: Some("hello".to_string()),
                do_not_spend_change: false,
            })
            .unwrap();
        //
        println!("get_max fee {}", pretty_print(&get_max));
        // //
        // // match NgAccount::<Connection>::broadcast_psbt(get_max.draft_transaction.clone(), ELECTRUM_SERVER, None) {
        // //     Ok(_) => {
        // //         println!("Transaction broadcasted successfully");
        // //     }
        // //     Err(cx) => {
        // //         println!("Failed to broadcast transaction: {:?}", cx);
        // //     }
        // // }
        //
        // account.persist().unwrap();
    }
}

fn pretty_print<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap()
}

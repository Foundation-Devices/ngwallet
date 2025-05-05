#[cfg(feature = "envoy")]
const EXTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAjWytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/0/*)#g9xn7wf9";

#[cfg(feature = "envoy")]
const INTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAjWytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/1/*)#e3rjrmea";
#[cfg(feature = "envoy")]
const ELECTRUM_SERVER: &str = "ssl://mempool.space:60602";

// TODO: make this unique to the descriptor
#[cfg(test)]
mod tests {
    use ngwallet::bip39;

    #[cfg(feature = "envoy")]
    use {
        crate::*,
        bdk_wallet::bitcoin::Network,
        bdk_wallet::rusqlite::Connection,
        bdk_wallet::{AddressInfo, Update},
        ngwallet::account::Descriptor,
        ngwallet::account::NgAccount,
        ngwallet::config::AddressType,
        ngwallet::ngwallet::NgWallet,
        redb::backends::FileBackend,
        std::sync::{Arc, Mutex},
    };

    #[test]
    #[cfg(feature = "envoy")]
    fn new_wallet() {
        let connection = Connection::open_in_memory().unwrap();

        let descriptors = vec![Descriptor {
            internal: INTERNAL_DESCRIPTOR.to_string(),
            external: Some(EXTERNAL_DESCRIPTOR.to_string()),
        }];

        let mut account = NgAccount::new_from_descriptor(
            "Passport Prime".to_string(),
            "red".to_string(),
            None,
            None,
            Network::Signet,
            AddressType::P2tr,
            descriptors,
            0,
            None,
            Arc::new(Mutex::new(connection)),
            None::<FileBackend>,
            "".to_string(),
            None,
        );
        let address = account.next_address().unwrap();
        println!(
            "Generated address {} at index {}",
            address[0].address, address[0].index
        );

        let request = account.full_scan_request();

        for request in request {
            let update = NgWallet::<Connection>::scan(request, ELECTRUM_SERVER, None).unwrap();
            account.apply(Update::from(update)).unwrap();
        }

        let balance = account.balance().unwrap();
        println!("Wallet balance: {} sat\n", balance.total().to_sat());

        let transactions = account.transactions().unwrap();
        for tx in transactions {
            println!("Transaction: {:?}", tx);
        }

        let utxos = account.utxos();
        utxos.unwrap().iter().for_each(|utxo| {
            println!("Utxo: {:?}", utxo);
        });

        let transactions = account.transactions().unwrap();
        //
        if !transactions.is_empty() {
            let message = "Test Message".to_string();
            println!("\nSetting note: {:?}", message);
            account
                .set_note(&transactions[0].tx_id, &message.clone())
                .unwrap();
            let transactions = account.transactions().unwrap();
            let firs_tx = transactions[0].note.clone().unwrap_or("".to_string());
            println!("Transaction note: {:?}", firs_tx);
            assert_eq!(firs_tx, message);
        }
        //
        let utxos = account.utxos().unwrap_or(vec![]);
        if !utxos.is_empty() {
            let tag = "Test Tag".to_string();
            println!("\nSetting tag: {:?}", tag);
            let first_utxo = &utxos[0];
            account.set_tag(first_utxo, tag.as_str()).unwrap();
            let utxos = account.utxos().unwrap_or(vec![]);
            let utxo_tag = utxos[0].tag.clone().unwrap_or("".to_string());
            println!("Utxo tag: {:?}", utxo_tag);
            assert_eq!(utxo_tag, tag);

            println!("\nSetting do not spend : {:?}", false);
            account.set_do_not_spend(first_utxo, true).unwrap();

            let utxos = account.utxos().unwrap_or(vec![]);
            let utxo_tag = &utxos[0];
            assert_eq!(utxo_tag.do_not_spend, true);
            println!("Utxo After Do not Spend: {:?}", utxo_tag);
        }
        // println!("Balance {:?}", balance);
        // account.wallet.persist().unwrap();
    }
    //
    // //noinspection RsExternalLinter
    // #[test]
    // #[cfg(feature = "envoy")]
    // fn open_wallet() {
    //     let wallet_file = "wallet.sqlite".to_string();
    //     println!("Opening database at: {}", wallet_file);
    //
    //     let connection = Connection::open(wallet_file).unwrap();
    //     // let connection = Connection::open_in_memory().unwrap();
    //
    //     let mut account = NgAccount::open_account(
    //         "./".to_string(),
    //         Arc::new(Mutex::new(connection)),
    //         None::<FileBackend>,
    //     );
    //     //
    //     let sync = account.wallet.sync_request();
    //     let syncr = NgWallet::<Connection>::sync(sync, ELECTRUM_SERVER, None).unwrap();
    //     account.wallet.apply(Update::from(syncr)).unwrap();
    //
    //     let address: AddressInfo = account.wallet.next_address().unwrap();
    //     println!(
    //         "Generated address {} at index {}",
    //         address.address, address.index
    //     );
    //     let balance = account.wallet.balance().unwrap();
    //     println!("Wallet balance: {} sat\n", balance.total().to_sat());
    //
    //     let balance = account.wallet.balance().unwrap();
    //
    //     assert!(balance.total().to_sat() > 0);
    //     let transactions = account.wallet.transactions().unwrap();
    //     let utxos = account.wallet.unspend_outputs().unwrap_or_default();
    //
    //     assert!(!transactions.is_empty());
    //     assert!(!utxos.is_empty());
    //     // transactions.iter().for_each(|tx| {
    //     //     println!(
    //     //         "\nTx: --> {:?} | Amount:{} | Note:{:?} |  ",
    //     //         tx.address, tx.amount, tx.note
    //     //     );
    //     //     tx.outputs.iter().for_each(|utxo| {
    //     //         println!(
    //     //             "Utxo: --> {:?} | Amount:{:?} | Tag:{:?} | DnS{:?}",
    //     //             utxo.address, utxo.amount, utxo.tag, utxo.do_not_spend
    //     //         );
    //     //     });
    //     // });
    //     // for utxo in utxos {
    //     //     account
    //     //         .wallet
    //     //         .set_tag(&utxo, format!("Tag {}", utxo.vout).as_str())
    //     //         .unwrap();
    //     // }
    //     // let utxos = account.wallet.unspend_outputs().unwrap();
    //     //
    //     // for utxo in utxos {
    //     //     println!("Utxo: {} {:?}", utxo.amount, utxo.tag);
    //     // }
    //     // if !utxos.is_empty() {
    //     //     let tag = "Test Tag".to_string();
    //     //     println!("\nSetting tag: {:?}", tag);
    //     //     let first_utxo = &utxos[0];
    //     //     account.wallet.set_tag(first_utxo, tag.as_str()).unwrap();
    //     //     let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
    //     //     let utxo_tag = utxos[0].tag.clone().unwrap_or("".to_string());
    //     //     println!("Utxo tag: {:?}", utxo_tag);
    //     //     assert_eq!(utxo_tag, tag);
    //     //
    //     //     println!("\nSetting do not spend : {:?}", true);
    //     //
    //     //     account.wallet.set_do_not_spend(first_utxo, true).unwrap();
    //     //
    //     //     let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
    //     //     let utxo_tag = &utxos[0];
    //     //     println!("Utxo After Do not Spend: {:?}", utxo_tag);
    //     //     let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
    //     //     let utxo_tag = &utxos[0];
    //     //     println!("Utxo After Do not Spend: {:?}", utxo_tag);
    //     // }
    //     // println!("Balance {:?}", balance);
    //     //
    //     // let param = TransactionParams {
    //     //     address: "tb1phc8m8vansnl4utths947mjquprw20puwrrdfrwx8akeeu2tqwkls7l62u4".to_string(),
    //     //     amount: 800,
    //     //     fee_rate: 2,
    //     //     selected_outputs: vec![],
    //     //     note: Some("not a note".to_string()),
    //     //     tag: Some("hello".to_string()),
    //     //     do_not_spend_change: true,
    //     // };
    //     //
    //     // match account.wallet.get_max_fee(param.clone()) {
    //     //     Ok(tx_fee_calc) => {
    //     //         println!(
    //     //             "max fee calculated {:?}",
    //     //             tx_fee_calc.draft_transaction.transaction.fee
    //     //         );
    //     //     }
    //     //     Err(er) => {
    //     //         println!("max fee error {} ", er)
    //     //     }
    //     // };
    //     // //
    //     // match account.wallet.compose_psbt(param.clone()) {
    //     //     Ok(spend) => {
    //     //         println!("Spend note: {:?}", spend.transaction.note);
    //     //         match  NgWallet::<Connection>::broadcast_psbt(spend.clone(), ELECTRUM_SERVER, None)
    //     //         {
    //     //             Ok(tx_id) => {
    //     //                 let tx = spend.transaction.clone();
    //     //                 if tx.note.is_some() {
    //     //                     account.wallet.set_note_unchecked(&tx.tx_id.to_string(), &tx.note.unwrap()).unwrap();
    //     //                 }
    //     //                 for output in tx.outputs.iter() {
    //     //                     if output.tag.is_some() {
    //     //                         account.wallet.set_tag(output, &output.tag.clone().unwrap()).unwrap();
    //     //                     }
    //     //                 }
    //     //                 let sync = account.wallet.sync_request();
    //     //                 let syncr = NgWallet::<Connection>::sync(sync, ELECTRUM_SERVER, None).unwrap();
    //     //                 account.wallet.apply(Update::from(syncr)).unwrap();
    //     //                 assert_eq!(tx_id.clone(), spend.transaction.clone().tx_id);
    //     //                 println!("broadcast success tx_id {:?} ", tx_id);
    //     //                 println!("broadcast success {:?} ", spend)
    //     //             }
    //     //             Err(error) => {
    //     //                 println!("Spend error {:?} ", error)
    //     //             }
    //     //         }
    //     //     }
    //     //     Err(er) => {
    //     //         println!("Spend error {} ", er)
    //     //     }
    //     // };
    //
    //     // let transactions = account.wallet.transactions().unwrap();
    //     // transactions.iter().for_each(|tx| {
    //     //     println!(
    //     //         "\nTx: --> {:?} | Amount:{} | Note:{:?} |  ",
    //     //         tx.address, tx.amount, tx.note
    //     //     );
    //     //     tx.outputs.iter().for_each(|utxo| {
    //     //         println!(
    //     //             "Utxo: --> {:?} | Amount:{:?} | Tag:{:?} | DnS{:?}",
    //     //             utxo.address, utxo.amount, utxo.tag, utxo.do_not_spend
    //     //         );
    //     //     });
    //     // });
    //     //
    //     // account.wallet.persist().expect("Wallet persisted");
    //
    //     let tx = transactions
    //         .iter()
    //         .find(|tx| {
    //             tx.tx_id == "91b4047c62a7b8b183ed8e71ebcefdad622f4f5063905cb80f63c1f2e99033d9"
    //         })
    //         .unwrap();
    //
    //     let cancel_draft = account.wallet.compose_cancellation_tx(tx.clone()).unwrap();
    //
    //     let cancel_tx = cancel_draft.transaction;
    //     for input in cancel_tx.inputs {
    //         println!(
    //             "\n\nCancel tx input \n {:?} {:?}",
    //             input.tx_id, input.amount
    //         );
    //     }
    //
    //     for output in cancel_tx.outputs.clone() {
    //         println!(
    //             "\n\nCancel tx outs\n {:?} {:?}",
    //             output.address, output.amount
    //         );
    //     }
    //     //cancel tx only has one output
    //     assert_eq!(cancel_tx.outputs.len(), 1);
    //
    //     drop(account)
    // }

    #[test]
    fn autocomplete_seedword() {
        let suggestions = bip39::get_seedword_suggestions("fa", 3);
        assert_eq!(suggestions, ["fabric", "face", "faculty"]);

        let suggestions = bip39::get_seedword_suggestions("xy", 3);
        assert_eq!(suggestions, Vec::<&str>::new());
    }
}

#[cfg(feature = "envoy")]
const EXTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAjWytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/0/*)#g9xn7wf9";

#[cfg(feature = "envoy")]
const INTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAjWytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/1/*)#e3rjrmea";
#[cfg(feature = "envoy")]
const ELECTRUM_SERVER: &str = "ssl://mempool.space:60602";

// TODO: make this unique to the descriptor
#[cfg(test)]
mod tests {
    use bdk_wallet::{ChangeSet, KeychainKind, Wallet};
    use ngwallet::bip39;

    #[cfg(feature = "envoy")]
    use {
        crate::*,
        bdk_wallet::bitcoin::{Address, Network, OutPoint},
        bdk_wallet::rusqlite::Connection,
        bdk_wallet::{AddressInfo, Update},
        ngwallet::account::NgAccount,
        ngwallet::config::AddressType,
        ngwallet::ngwallet::NgWallet,
        ngwallet::send::SpendParams,
        redb::backends::FileBackend,
        std::sync::{Arc, Mutex},
    };

    #[test]
    #[cfg(feature = "envoy")]
    fn new_wallet() {
        let wallet_file = "wallet.sqlite".to_string();
        println!("Creating database at: {}", wallet_file);

        let connection = Connection::open(wallet_file).unwrap();
        // let connection = Connection::open_in_memory().unwrap();
        let mut account = NgAccount::new_from_descriptor(
            "Passport Prime".to_string(),
            "red".to_string(),
            None,
            None,
            Network::Signet,
            AddressType::P2tr,
            INTERNAL_DESCRIPTOR.to_string(),
            Some(EXTERNAL_DESCRIPTOR.to_string()),
            0,
            None,
            Arc::new(Mutex::new(connection)),
            None::<FileBackend>,
            "".to_string(),
            None,
        );
        let address: AddressInfo = account.wallet.next_address().unwrap();
        println!(
            "Generated address {} at index {}",
            address.address, address.index
        );

        let request = account.wallet.full_scan_request();
        let update = NgWallet::<Connection>::scan(request, ELECTRUM_SERVER, None).unwrap();
        account.wallet.apply(Update::from(update)).unwrap();

        let balance = account.wallet.balance().unwrap();
        println!("Wallet balance: {} sat\n", balance.total().to_sat());

        let transactions = account.wallet.transactions();
        for tx in transactions {
            println!("Transaction: {:?}", tx);
        }

        let utxos = account.wallet.unspend_outputs();
        utxos.unwrap().iter().for_each(|utxo| {
            println!("Utxo: {:?}", utxo);
        });

        let transactions = account.wallet.transactions().unwrap();

        if !transactions.is_empty() {
            let message = "Test Message".to_string();
            println!("\nSetting note: {:?}", message);
            account
                .wallet
                .set_note(&transactions[0].tx_id, &message.clone())
                .unwrap();
            let transactions = account.wallet.transactions().unwrap();
            let firs_tx = transactions[0].note.clone().unwrap_or("".to_string());
            println!("Transaction note: {:?}", firs_tx);
            assert_eq!(firs_tx, message);
        }

        let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
        if !utxos.is_empty() {
            let tag = "Test Tag".to_string();
            println!("\nSetting tag: {:?}", tag);
            let first_utxo = &utxos[0];
            account.wallet.set_tag(first_utxo, tag.as_str()).unwrap();
            let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
            let utxo_tag = utxos[0].tag.clone().unwrap_or("".to_string());
            println!("Utxo tag: {:?}", utxo_tag);
            assert_eq!(utxo_tag, tag);

            println!("\nSetting do not spend : {:?}", false);

            account.wallet.set_do_not_spend(first_utxo, false).unwrap();

            let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
            let utxo_tag = &utxos[0];
            println!("Utxo After Do not Spend: {:?}", utxo_tag);

            println!("\nSetting do not spend : {:?}", true);
            account.wallet.set_do_not_spend(first_utxo, false).unwrap();

            let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
            let utxo_tag = &utxos[0];
            println!("Utxo After Do not Spend: {:?}", utxo_tag);
        }
        println!("Balance {:?}", balance);
        account.wallet.persist().unwrap();
    }

    // #[test]
    #[cfg(feature = "envoy")]
    fn open_wallet() {
        let wallet_file = "wallet.sqlite".to_string();
        println!("Opening database at: {}", wallet_file);

        let connection = Connection::open(wallet_file).unwrap();
        // let connection = Connection::open_in_memory().unwrap();

        let mut account = NgAccount::open_wallet(
            "./".to_string(),
            Arc::new(Mutex::new(connection)),
            None::<FileBackend>,
        );

        let sync = account.wallet.sync_request();
        let syncr = NgWallet::<Connection>::sync(sync, ELECTRUM_SERVER, None).unwrap();
        account.wallet.apply(Update::from(syncr)).unwrap();

        let address: AddressInfo = account.wallet.next_address().unwrap();
        println!(
            "Generated address {} at index {}",
            address.address, address.index
        );
        let balance = account.wallet.balance().unwrap();
        println!("Wallet balance: {} sat\n", balance.total().to_sat());

        let balance = account.wallet.balance().unwrap();
        let transactions = account.wallet.transactions();

        let utxos = account.wallet.unspend_outputs();
        let transactions = account.wallet.transactions().unwrap();
        let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
        transactions.iter().for_each(|tx| {
            println!(
                "\nTx: --> {:?} | Amount:{} | Note:{:?} |  ",
                tx.address, tx.amount, tx.note
            );
            tx.outputs.iter().for_each(|utxo| {
                println!(
                    "Utxo: --> {:?} | Amount:{:?} | Tag:{:?} | DnS{:?}",
                    utxo.address, utxo.amount, utxo.tag, utxo.do_not_spend
                );
            });
        });
        if !utxos.is_empty() {
            let tag = "Test Tag".to_string();
            println!("\nSetting tag: {:?}", tag);
            let first_utxo = &utxos[0];
            account.wallet.set_tag(first_utxo, tag.as_str()).unwrap();
            let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
            let utxo_tag = utxos[0].tag.clone().unwrap_or("".to_string());
            println!("Utxo tag: {:?}", utxo_tag);
            assert_eq!(utxo_tag, tag);

            println!("\nSetting do not spend : {:?}", true);

            account.wallet.set_do_not_spend(first_utxo, true).unwrap();

            let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
            let utxo_tag = &utxos[0];
            println!("Utxo After Do not Spend: {:?}", utxo_tag);
            let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
            let utxo_tag = &utxos[0];
            println!("Utxo After Do not Spend: {:?}", utxo_tag);
        }
        println!("Balance {:?}", balance);
        //
        //
        // let max_fee = match account
        //     .wallet
        //     .get_max_fee(
        //         "tb1pzvynlely05x82u40cts3znctmvyskue74xa5zwy0t5ueuv92726s0cz8g8".to_string(),
        //         5000,
        //         vec![],
        //     ) {
        //     Ok(max_fee) => {
        //         println!("max fee calculated {}", max_fee)
        //     }
        //     Err(er) => {
        //         println!("max fee error {} ", er.to_string())
        //     }
        // };

        match account.wallet.compose_psbt(SpendParams {
            address: "tb1phc8m8vansnl4utths947mjquprw20puwrrdfrwx8akeeu2tqwkls7l62u4".to_string(),
            amount: 699,
            fee_rate: 1,
            selected_outputs: vec![],
            note: Some("not a note".to_string()),
            tag: Some("Tag dis".to_string()),
            do_not_spend_change: true,
        }) {
            Ok(spend) => {
                match account
                    .wallet
                    .broadcast_psbt(spend.clone(), ELECTRUM_SERVER, None)
                {
                    Ok(tx_id) => {
                        assert_eq!(tx_id, spend.transaction.tx_id);
                        println!("broadcast success {:?} ", spend)
                    }
                    Err(error) => {
                        println!("Spend error {:?} ", error)
                    }
                }
            }
            Err(er) => {
                println!("Spend error {} ", er.to_string())
            }
        };

        let transactions = account.wallet.transactions().unwrap();
        transactions.iter().for_each(|tx| {
            println!(
                "\nTx: --> {:?} | Amount:{} | Note:{:?} |  ",
                tx.address, tx.amount, tx.note
            );
            tx.outputs.iter().for_each(|utxo| {
                println!(
                    "Utxo: --> {:?} | Amount:{:?} | Tag:{:?} | DnS{:?}",
                    utxo.address, utxo.amount, utxo.tag, utxo.do_not_spend
                );
            });
        });

        account.wallet.persist().expect("Wallet persisted");
        drop(account)
    }

    #[test]
    fn autocomplete_seedword() {
        let suggestions = bip39::get_seedword_suggestions("fa", 3);
        assert_eq!(suggestions, ["fabric", "face", "faculty"]);

        let suggestions = bip39::get_seedword_suggestions("xy", 3);
        assert_eq!(suggestions, Vec::<&str>::new());
    }
}

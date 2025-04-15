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
        bdk_wallet::bitcoin::{Address, Network, OutPoint},
        bdk_wallet::rusqlite::Connection,
        bdk_wallet::{AddressInfo, Update},
        ngwallet::account::NgAccount,
        ngwallet::config::AddressType,
        ngwallet::ngwallet::NgWallet,
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
            EXTERNAL_DESCRIPTOR.to_string(),
            None,
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

    #[test]
    #[cfg(feature = "envoy")]
    // fn open_wallet() {
    //     let wallet_file = "wallet.sqlite".to_string();
    //     println!("Opening database at: {}", wallet_file);
    //
    //     let connection = Connection::open(wallet_file).unwrap();
    //     // let connection = Connection::open_in_memory().unwrap();
    //
    //     let mut account = NgAccount::open_wallet(
    //         "./".to_string(),
    //         Arc::new(Mutex::new(connection)),
    //         None::<FileBackend>,
    //     );
    //
    //     let address: AddressInfo = account.wallet.next_address().unwrap();
    //     println!(
    //         "Generated address {} at index {}",
    //         address.address, address.index
    //     );
    //     let balance = account.wallet.balance().unwrap();
    //     println!("Wallet balance: {} sat\n", balance.total().to_sat());
    //     // let request = account.wallet.full_scan_request();
    //     // let update = NgWallet::<Connection>::scan(request, ELECTRUM_SERVER, None).unwrap();
    //     // account.wallet.apply(Update::from(update)).unwrap();
    //
    //     let balance = account.wallet.balance().unwrap();
    //     let transactions = account.wallet.transactions();
    //
    //     let utxos = account.wallet.unspend_outputs();
    //
    //     let transactions = account.wallet.transactions().unwrap();
    //
    //     let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
    //     if !utxos.is_empty() {
    //         let tag = "Test Tag".to_string();
    //         println!("\nSetting tag: {:?}", tag);
    //         let first_utxo = &utxos[0];
    //         account.wallet.set_tag(first_utxo, tag.as_str()).unwrap();
    //         let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
    //         let utxo_tag = utxos[0].tag.clone().unwrap_or("".to_string());
    //         println!("Utxo tag: {:?}", utxo_tag);
    //         assert_eq!(utxo_tag, tag);
    //
    //         println!("\nSetting do not spend : {:?}", true);
    //
    //         account.wallet.set_do_not_spend(first_utxo, true).unwrap();
    //
    //         let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
    //         let utxo_tag = &utxos[0];
    //         println!("Utxo After Do not Spend: {:?}", utxo_tag);
    //         let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
    //         let utxo_tag = &utxos[0];
    //         println!("Utxo After Do not Spend: {:?}", utxo_tag);
    //     }
    //     println!("Balance {:?}", balance);
    //
    //
    //     match account
    //         .wallet
    //         .get_max_fee(
    //             "tb1pffsyra2t3nut94yvdae9evz3feg7tel843pfcv76vt5cwewavtesl3gsph".to_string(),
    //             30000,
    //             vec![],
    //         ) {
    //         Ok(max_fee) => {
    //             println!("max fee calculated {}", max_fee)
    //         }
    //         Err(er) => {
    //             println!("max fee error {} ", er.to_string())
    //         }
    //     }
    //
    //     account.wallet.persist().expect("Wallet persisted");
    //     drop(account)
    // }

    #[test]
    fn autocomplete_seedword() {
        let suggestions = bip39::get_seedword_suggestions("fa", 3);
        assert_eq!(suggestions, ["fabric", "face", "faculty"]);

        let suggestions = bip39::get_seedword_suggestions("xy", 3);
        assert_eq!(suggestions, Vec::<&str>::new());
    }

    // #[test]
    // #[cfg(feature = "envoy")]
    // fn check_watch_only() {
    //     // let mut wallet = NgWallet::new_from_descriptor(Some(DB_PATH.to_string()), EXTERNAL_DESCRIPTOR.to_string()).unwrap_or(NgWallet::load(DB_PATH).unwrap());
    //     //
    //     // let address: AddressInfo = wallet.next_address().unwrap();
    //     // println!(
    //     //     "Generated address {} at index {}",
    //     //     address.address, address.index
    //     // );
    //     //
    //     // let request = wallet.scan_request();
    //     // let update = NgWallet::scan(request).unwrap();
    //     // wallet.apply(Update::from(update)).unwrap();
    //     //
    //     // let balance = wallet.balance().unwrap().total().to_sat();
    //     // println!("Wallet balance: {} sat", balance);
    //     //
    //     // let transactions = wallet.transactions();
    //     //
    //     // for tx in transactions {
    //     //     println!("Transaction: {:?}", tx);
    //     // }
    //     // let unspends = wallet.unspend_outputs();
    //     //
    //     // for utxo in unspends {
    //     //     println!("Utxo: {:?}", utxo);
    //     // }
    //
    //     //println!("Wallet balance: {:?} sat", wallet.transactions());
    // }
}

// #[cfg(feature = "envoy")]
// const EXTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPeLx4U7UmbcYU5VhS4BRxv86o1gNqNqxEEJL47F9ZZhvBi1EVbKPmmFYnTEZ6uArarK6zZyrZf7mSyWZRAuNKQp4dHfxBdMM/84'/1'/0'/0/*)#gksznsj0";
#[cfg(feature = "envoy")]
const INTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPeLx4U7UmbcYU5VhS4BRxv86o1gNqNqxEEJL47F9ZZhvBi1EVbKPmmFYnTEZ6uArarK6zZyrZf7mSyWZRAuNKQp4dHfxBdMM/84'/1'/0'/0/*)#gksznsj0";
const INTERNAL_DESCRIPTOR_2: &str = "tr(tprv8ZgxMBicQKsPeLx4U7UmbcYU5VhS4BRxv86o1gNqNqxEEJL47F9ZZhvBi1EVbKPmmFYnTEZ6uArarK6zZyrZf7mSyWZRAuNKQp4dHfxBdMM/86'/1'/0'/0/*)#uw0tj973";
#[cfg(feature = "envoy")]
const ELECTRUM_SERVER: &str = "ssl://mempool.space:60602";

// TODO: make this unique to the descriptor
// #[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use redb::backends::FileBackend;

    #[cfg(feature = "envoy")]
    use {
        bdk_wallet::bitcoin::Network, bdk_wallet::rusqlite::Connection, bdk_wallet::Update,
        crate::*, ngwallet::account::Descriptor
        , ngwallet::config::AddressType, ngwallet::ngwallet::NgWallet,
    };
    use ngwallet::bip39;
    use ngwallet::config::NgAccountBuilder;

    #[test]
    #[cfg(feature = "envoy")]
    fn new_wallet() {
        let descriptors = vec![
            Descriptor {
                internal: INTERNAL_DESCRIPTOR.to_string(),
                external: None,
                bdk_persister: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
            },
            Descriptor {
                internal: INTERNAL_DESCRIPTOR_2.to_string(),
                external: None,
                bdk_persister: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
            },
        ];

        let mut account = NgAccountBuilder::default()
            .name("Passport Prime".to_string())
            .color("red".to_string())
            .seed_has_passphrase(false)
            .device_serial(None)
            .date_added(None)
            .preferred_address_type(AddressType::P2wpkh)
            .index(0)
            .descriptors(descriptors)
            .date_synced(None)
            .db_path(None)
            .network(Network::Signet)
            .id("1234567890".to_string())
            .open_in_memory()
            .build(None::<FileBackend>);


        // Let's imagine we are applying updates remotely
        let mut updates = vec![];

        for wallet in account.wallets.iter() {
            let (address_type, request) = account.full_scan_request(wallet.address_type).unwrap();
            let update = NgWallet::<Connection>::scan(request, ELECTRUM_SERVER, None).unwrap();
            account.apply((address_type, Update::from(update))).unwrap();
        }

        let payload = NgAccount::<Connection>::serialize_updates(None, updates).unwrap();
        account.update(payload).unwrap();

        let address = account.next_address().unwrap();
        address.iter().for_each(|(address, address_type)| {
            println!(
                "Generated address {} at index {} of type {:?}",
                address.address, address.index, address_type
            );
        });

        let balance = account.balance().unwrap();
        println!("Wallet balance: {} sat\n", balance.total().to_sat());

        let transactions = account.transactions().unwrap();
        for tx in transactions {
            println!(
                "Transaction: {},{},{}",
                tx.address, tx.amount, tx.is_confirmed
            );
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

        let utxos = account.utxos().unwrap_or_default();
        println!("Utxos: {}", serde_json::to_string_pretty(&utxos).unwrap());
        if !utxos.is_empty() {
            let tag = "Test Tag".to_string();
            println!("\nSetting tag: {:?}", tag);
            let first_utxo = &utxos[0];
            account.set_tag(first_utxo, tag.as_str()).unwrap();
            let utxos = account.utxos().unwrap_or_default();
            let utxo_tag = utxos[0].tag.clone().unwrap_or("".to_string());
            println!("Utxo tag: {:?}", utxo_tag);
            assert_eq!(utxo_tag, tag);

            println!("\nSetting do not spend : {:?}", false);
            account.set_do_not_spend(first_utxo, true).unwrap();

            let utxos = account.utxos().unwrap_or_default();
            let utxo_tag = &utxos[0];
            assert!(utxo_tag.do_not_spend);
            println!("Utxo After Do not Spend: {:?}", utxo_tag);
        }
        account.persist().unwrap();
    }

    //noinspection RsExternalLinter
    // #[test]
    // #[cfg(feature = "envoy")]
    // fn open_wallet() {
    //     let wallet_file = get_persister_file_name(INTERNAL_DESCRIPTOR, Some(EXTERNAL_DESCRIPTOR));
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
    //
    //     for request in account.full_scan_request().into_iter() {
    //         let update = NgWallet::<Connection>::scan(request, ELECTRUM_SERVER, None).unwrap();
    //         account.apply(Update::from(update)).unwrap();
    //     }
    //
    //     let addresses = account.next_address().unwrap();
    //     println!(
    //         "Generated address {} at index {}",
    //         addresses[0].address, addresses[0].index
    //     );
    //     let balance = account.balance().unwrap();
    //     println!("Wallet balance: {} sat\n", balance.total().to_sat());
    //
    //     let balance = account.balance().unwrap();
    //
    //     assert!(balance.total().to_sat() > 0);
    //     let transactions = account.transactions().unwrap();
    //     let utxos = account.utxos().unwrap_or_default();
    //
    //     assert!(!transactions.is_empty());
    //     assert!(!utxos.is_empty());
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

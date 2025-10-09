#[cfg(feature = "envoy")]
const INTERNAL_DESCRIPTOR: &str = "wpkh(tprv8ZgxMBicQKsPeLx4U7UmbcYU5VhS4BRxv86o1gNqNqxEEJL47F9ZZhvBi1EVbKPmmFYnTEZ6uArarK6zZyrZf7mSyWZRAuNKQp4dHfxBdMM/84'/1'/0'/0/*)#gksznsj0";
const INTERNAL_DESCRIPTOR_2: &str = "tr(tprv8ZgxMBicQKsPeLx4U7UmbcYU5VhS4BRxv86o1gNqNqxEEJL47F9ZZhvBi1EVbKPmmFYnTEZ6uArarK6zZyrZf7mSyWZRAuNKQp4dHfxBdMM/86'/1'/0'/0/*)#uw0tj973";

// Descriptors with balance for testing
const FUNDED_INTERNAL_DESCRIPTOR: &str = "wpkh([b032ef5f/84'/1'/0']tpubDCk2z9cyYbR3FGusMkYB5aSLTHuLNkkZuz9whR7x4JDh34rjD64bMhSXBns5qKf5QArdU5DK1Q6zLLg34SRqSV2EXutfgySyq3gZGsmYDT8/0/*)#csckd05z";
const FUNDED_EXTERNAL_DESCRIPTOR: &str = "wpkh([b032ef5f/84'/1'/0']tpubDCk2z9cyYbR3FGusMkYB5aSLTHuLNkkZuz9whR7x4JDh34rjD64bMhSXBns5qKf5QArdU5DK1Q6zLLg34SRqSV2EXutfgySyq3gZGsmYDT8/1/*)#fyahs6y6";
const FUNDED_INTERNAL_DESCRIPTOR_TR: &str = "tr([b032ef5f/86'/1'/0']tpubDCYjw9j1fst87iV3Mep6c3jUWe6JwCqLArZv7uZMEfa4VyXjU5uHZrWAMdokfsvm2HisA8Ym5Zbp4o5iCS3UARP6SxDdR2SvmSsSBAzvZMZ/0/*)#5ujy5gry";
const FUNDED_EXTERNAL_DESCRIPTOR_TR: &str = "tr([b032ef5f/86'/1'/0']tpubDCYjw9j1fst87iV3Mep6c3jUWe6JwCqLArZv7uZMEfa4VyXjU5uHZrWAMdokfsvm2HisA8Ym5Zbp4o5iCS3UARP6SxDdR2SvmSsSBAzvZMZ/1/*)#9gh9fanu";

#[cfg(feature = "envoy")]
const ELECTRUM_SERVER: &str = "ssl://mempool.space:60602";
const ELECTRUM_SERVER_T4: &str = "ssl://testnet4.foundation.xyz:50002";

#[cfg(feature = "envoy")]
mod utils;

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::Psbt;
    use bdk_wallet::bitcoin::key::Secp256k1;
    use bdk_wallet::keys::bip39::Mnemonic;
    use bdk_wallet::miniscript::psbt::PsbtExt;
    use bdk_wallet::{KeychainKind, SignOptions};
    use ngwallet::account::NgAccount;
    use ngwallet::account::RemoteUpdate;
    use ngwallet::bip39;
    use ngwallet::bip39::get_descriptors;
    use ngwallet::config::{AddressType, NgAccountBackup, NgAccountBuilder};
    use ngwallet::send::TransactionParams;
    use std::sync::{Arc, Mutex};

    #[cfg(feature = "envoy")]
    use {
        crate::*, bdk_wallet::Update, bdk_wallet::bitcoin::Network,
        bdk_wallet::rusqlite::Connection, ngwallet::account::Descriptor,
        ngwallet::ngwallet::NgWallet,
    };

    #[test]
    #[cfg(feature = "envoy")]
    fn new_wallet_test_scan() {
        let descriptors = vec![
            Descriptor {
                internal: FUNDED_INTERNAL_DESCRIPTOR.to_string(),
                external: Some(FUNDED_EXTERNAL_DESCRIPTOR.to_string()),
                bdk_persister: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
            },
            Descriptor {
                internal: FUNDED_INTERNAL_DESCRIPTOR_TR.to_string(),
                external: Some(FUNDED_EXTERNAL_DESCRIPTOR_TR.to_string()),
                bdk_persister: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
            },
        ];

        let account = NgAccountBuilder::default()
            .name("Passport Prime".to_string())
            .color("red".to_string())
            .seed_has_passphrase(false)
            .device_serial(None)
            .date_added(None)
            .preferred_address_type(AddressType::P2tr)
            .index(0)
            .descriptors(descriptors)
            .date_synced(None)
            .account_path(None)
            .network(Network::Signet)
            .id("1234567890".to_string())
            .build_in_memory()
            .unwrap();

        // Let's imagine we are applying updates remotely
        let mut updates = vec![];

        for wallet in account.wallets.read().unwrap().iter() {
            let (address_type, request) = account.full_scan_request(wallet.address_type).unwrap();
            let update = NgWallet::<Connection>::scan(request, ELECTRUM_SERVER, None).unwrap();
            updates.push((address_type, Update::from(update)));
        }

        let payload = RemoteUpdate::new(None, updates).serialize();
        account.update(payload).unwrap();

        let address = account.next_address().unwrap();
        address.iter().for_each(|(address, address_type)| {
            println!(
                "Generated address {} at index {} of type {:?}",
                address.address, address.index, address_type
            );
        });

        let balance = account.balance().unwrap();
        assert!(balance.total().to_sat() > 0);

        let transactions = account.transactions().unwrap();
        assert!(!transactions.is_empty());
        for tx in transactions {
            println!(
                "Transaction: {},{},{},{}",
                tx.address, tx.amount, tx.is_confirmed, tx.tx_id
            );
        }

        let utxos = account.utxos().unwrap();
        assert!(!utxos.is_empty());

        let transactions = account.transactions().unwrap();
        //
        if !transactions.is_empty() {
            let message = "Test Message".to_string();
            println!("\nSetting note: {message:?}");
            account
                .set_note(&transactions[0].tx_id, &message.clone())
                .unwrap();
            let transactions = account.transactions().unwrap();
            let firs_tx = transactions[0].note.clone().unwrap_or("".to_string());
            println!("Transaction note: {firs_tx:?}");
            assert_eq!(firs_tx, message);
        }

        let utxos = account.utxos().unwrap_or_default();
        println!("Utxos: {}", serde_json::to_string_pretty(&utxos).unwrap());
        if !utxos.is_empty() {
            let tag = "Test Tag".to_string();
            println!("\nSetting tag: {tag:?}");
            let first_utxo = &utxos[0];
            account
                .set_tag(first_utxo.get_id().as_str(), tag.as_str())
                .unwrap();
            let utxos = account.utxos().unwrap_or_default();
            let utxo_tag = utxos[0].tag.clone().unwrap_or("".to_string());
            println!("Utxo tag: {utxo_tag:?}");
            assert_eq!(utxo_tag, tag);

            println!("\nSetting do not spend ");
            account
                .set_do_not_spend(first_utxo.get_id().as_str(), true)
                .unwrap();

            let utxos = account.utxos().unwrap_or_default();
            let utxo_tag = &utxos[0];
            assert!(utxo_tag.do_not_spend);
            let new_tag = "New Tag".to_string();
            account
                .remove_tag(tag.as_str(), Some(new_tag.as_str()))
                .expect("rename failed");
            let tags = account.list_tags();
            assert_eq!(tags.unwrap().first().unwrap(), new_tag.as_str());
            account
                .remove_tag(new_tag.as_str(), None)
                .expect("remove tag should not fail");
            let tags = account.list_tags();
            assert!(tags.unwrap().is_empty());
        }
        account.persist().unwrap();

        //test fee electrum fee fetching
        let first_tx = account.transactions().unwrap()[0].clone();
        let fee = NgAccount::<Connection>::fetch_fee_from_electrum(
            &first_tx.tx_id,
            ELECTRUM_SERVER,
            None,
        );
        assert!(fee.is_some());
        assert!(fee.unwrap() > 0);
        account
            .update_fee(&first_tx.tx_id, fee.expect("Failed to fetch fee"))
            .expect("Failed to update fee");
        account.persist().unwrap();
        let transactions = account.transactions().unwrap();
        let tx_fee = transactions[0].fee;
        assert_eq!(tx_fee, fee.unwrap());
    }

    #[test]
    #[cfg(feature = "envoy")]
    fn test_input_mis_match() {
        let seed = Mnemonic::parse(
            "addict hold sand engage ostrich cousin swarm away puzzle huge rookie fancy",
        )
        .unwrap()
        .to_seed("");

        let descriptors = get_descriptors(&seed, Network::Testnet4, 0)
            .map(|descriptors| {
                descriptors
                    .into_iter()
                    .map(|d| Descriptor {
                        internal: d.descriptor_xpub(),
                        external: Some(d.change_descriptor_xpub()),
                        bdk_persister: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap();

        let descriptors_xprv = get_descriptors(&seed, Network::Testnet4, 0)
            .map(|descriptors| {
                descriptors
                    .into_iter()
                    .map(|d| Descriptor {
                        internal: d.descriptor_xprv(),
                        external: Some(d.change_descriptor_xprv()),
                        bdk_persister: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap();

        let account = NgAccountBuilder::default()
            .name("Passport Prime".to_string())
            .color("red".to_string())
            .seed_has_passphrase(false)
            .device_serial(None)
            .date_added(None)
            .preferred_address_type(AddressType::P2wpkh)
            .index(0)
            .descriptors(descriptors)
            .date_synced(None)
            .account_path(None)
            .network(Network::Testnet4)
            .id("1234567890".to_string())
            .build_in_memory()
            .unwrap();

        let account_with_prv = NgAccountBuilder::default()
            .name("Passport Prime".to_string())
            .color("red".to_string())
            .seed_has_passphrase(false)
            .device_serial(None)
            .date_added(None)
            .preferred_address_type(AddressType::P2wpkh)
            .index(0)
            .descriptors(descriptors_xprv)
            .date_synced(None)
            .account_path(None)
            .network(Network::Testnet4)
            .id("1234567890".to_string())
            .build_in_memory()
            .unwrap();

        // Let's imagine we are applying updates remotely
        let mut updates = vec![];

        for wallet in account.wallets.read().unwrap().iter() {
            let (address_type, request) = account.full_scan_request(wallet.address_type).unwrap();
            let update = NgWallet::<Connection>::scan(request, ELECTRUM_SERVER_T4, None).unwrap();
            updates.push((address_type, Update::from(update)));
        }

        let payload = RemoteUpdate::new(None, updates).serialize();
        account.update(payload).unwrap();

        let address = account.next_address().unwrap();
        address.iter().for_each(|(address, address_type)| {
            println!(
                "Generated address {} at index {} of type {:?}",
                address.address, address.index, address_type
            );
        });
        //
        let balance = account.balance().unwrap();

        println!("Wallet balance: {} sat", balance.total().to_sat());

        let compose_tx = account
            .compose_psbt(TransactionParams {
                address: "tb1qydjtc47ru9c055gv7adpfs8uzw8dhy0p52fj3y".to_string(),
                amount: 1000,
                fee_rate: 1,
                selected_outputs: vec![],
                note: None,
                tag: None,
                do_not_spend_change: false,
            })
            .unwrap();
        let base = compose_tx.psbt.clone();
        let psbt = Psbt::deserialize(&base).unwrap();
        println!(
            "Original PSBT is ok ? : {:?}",
            psbt.clone()
                .extract(&Secp256k1::verification_only())
                .is_ok()
        );
        let signed_psbt = account_with_prv
            .sign(&compose_tx.psbt.clone(), SignOptions::default())
            .unwrap();
        let _ = Psbt::deserialize(&signed_psbt.clone()).unwrap();
        NgAccount::<Connection>::decode_psbt(compose_tx, &signed_psbt.clone()).unwrap();
        account.persist().unwrap();
    }

    #[test]
    #[cfg(feature = "envoy")]
    fn add_new_descriptor_to_existing() {
        let second_descriptor = Descriptor {
            internal: INTERNAL_DESCRIPTOR_2.to_string(),
            external: None,
            bdk_persister: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
        };
        let descriptors = vec![Descriptor {
            internal: INTERNAL_DESCRIPTOR.to_string(),
            external: None,
            bdk_persister: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
        }];

        let account = NgAccountBuilder::default()
            .name("Passport Prime".to_string())
            .color("#fafafa".to_string())
            .seed_has_passphrase(false)
            .device_serial(None)
            .date_added(None)
            .preferred_address_type(AddressType::P2wpkh)
            .index(0)
            .descriptors(descriptors)
            .date_synced(None)
            .account_path(None)
            .network(Network::Signet)
            .id("1234567890".to_string())
            .build_in_memory()
            .unwrap();

        account.add_new_descriptor(&second_descriptor).unwrap();

        assert_eq!(account.wallets.read().unwrap().len(), 2);

        assert_eq!(account.config.read().unwrap().descriptors.len(), 2);

        //expect error when adding duplicate descriptor
        assert!(account.add_new_descriptor(&second_descriptor).is_err());
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
    #[cfg(feature = "envoy")]
    fn check_hot_wallet_backup() {
        let note = "This is a test note".to_string();
        let tag = "Test Tag".to_string();
        let mut account = utils::tests_util::get_ng_hot_wallet();
        //add funds to the wallet to increment the index
        utils::tests_util::add_funds_to_wallet(&mut account);
        utils::tests_util::add_funds_to_wallet(&mut account);
        account.persist().unwrap();
        let first_tx = account.transactions().unwrap()[0].clone();
        let first_utxo = account.utxos().unwrap()[0].clone();

        account.set_note(&first_tx.tx_id, &note).unwrap();
        account.set_tag(first_utxo.get_id().as_str(), &tag).unwrap();
        account
            .set_do_not_spend(first_utxo.get_id().as_str(), true)
            .unwrap();

        let config = account.config.clone();
        assert!(account.is_hot());
        let backup = account.get_backup_json().unwrap();
        println!("backup: {backup}");
        let account_backup = serde_json::from_str::<NgAccountBackup>(&backup).unwrap();
        let config_from_backup = account_backup.ng_account_config;

        assert_eq!(config_from_backup.name, config.read().unwrap().name);
        assert_eq!(config_from_backup.network, config.read().unwrap().network);
        //hot wallet doesnt export descriptors, since they contain xprv
        assert_eq!(config_from_backup.descriptors.len(), 0);
        let last_used_index = account_backup.last_used_index;

        let note_from_backup = account_backup.notes.get(&first_tx.tx_id);
        let tag_from_backup = account_backup.tags.get(&first_utxo.get_id());
        let do_not_spend_from_backup = account_backup.do_not_spend.get(&first_utxo.get_id());
        assert_eq!(note_from_backup, Some(&note));
        assert_eq!(tag_from_backup, Some(&tag));
        assert_eq!(do_not_spend_from_backup, Some(&true));

        for &index in last_used_index.iter() {
            if index.1 == KeychainKind::External {
                assert_eq!(index.2, 1);
            }
        }
    }

    #[test]
    #[cfg(feature = "envoy")]
    fn check_watch_only_backup() {
        let account = utils::tests_util::get_ng_watch_only_account();
        assert!(!account.is_hot());
        let config = account.config.clone();
        let backup = account.get_backup_json().unwrap();
        let account_backup = serde_json::from_str::<NgAccountBackup>(&backup).unwrap();
        let config_from_backup = account_backup.ng_account_config;
        let last_used_index = account_backup.last_used_index;
        println!("last_used_index: {last_used_index:?}");
        assert_eq!(config_from_backup.name, config.read().unwrap().name);
        assert_eq!(config_from_backup.network, config.read().unwrap().network);
        //watch only must export public descriptors
        assert_eq!(
            config_from_backup.descriptors,
            config.read().unwrap().descriptors
        );
    }

    #[test]
    #[cfg(feature = "envoy")]
    fn check_psbt_parsing() {
        let mut account = utils::tests_util::get_ng_watch_only_account();
        utils::tests_util::add_funds_to_wallet(&mut account);
        assert!(!account.is_hot());
        let params = TransactionParams {
            address: "tb1pspfcrvz538vvj9f9gfkd85nu5ty98zw9y5e302kha6zurv6vg07s8z7a8w".to_string(),
            amount: 4000,
            fee_rate: 2,
            selected_outputs: vec![],
            note: Some("not a note".to_string()),
            tag: Some("hello".to_string()),
            do_not_spend_change: false,
        };

        println!("params: {params:?}");
        let compose_transaction = account.compose_psbt(params.clone());
        if let Ok(transaction) = compose_transaction {
            let parsed = account.get_bitcoin_tx_from_psbt(&transaction.psbt).unwrap();
            assert_eq!(parsed.address, params.clone().address);
            assert_eq!(parsed.fee, transaction.transaction.fee);
            assert_eq!(parsed.amount as u64, params.amount);
            assert_eq!(parsed.fee_rate, params.fee_rate);
        } else {
            panic!("Failed to compose transaction: {compose_transaction:?}");
        }
    }

    #[test]
    #[cfg(feature = "envoy")]
    fn change_address_type() {
        let account = utils::tests_util::get_ng_hot_wallet();
        let wallet = account.get_coordinator_wallet();
        assert_eq!(
            account.config.read().unwrap().preferred_address_type,
            AddressType::P2tr
        );
        assert_eq!(wallet.address_type, AddressType::P2tr);

        account
            .set_preferred_address_type(AddressType::P2wpkh)
            .unwrap();
        let wallet = account.get_coordinator_wallet();
        assert_eq!(
            account.config.read().unwrap().preferred_address_type,
            AddressType::P2wpkh
        );
        assert_eq!(wallet.address_type, AddressType::P2wpkh);
    }

    #[test]
    #[cfg(feature = "envoy")]
    fn verify_address() {
        let account = utils::tests_util::get_ng_hot_wallet();

        // testnet segwit receive address 0
        let result = account
            .verify_address(
                String::from("tb1qp3s35d5579w9mtx4vkx2lngfpnwyjx8jxhveym"),
                0,
                50,
            )
            .unwrap();
        assert_eq!(result.found_index, Some(0));
        assert_eq!(result.change_lower, 0);
        assert_eq!(result.change_upper, 0);
        assert_eq!(result.receive_lower, 0);
        assert_eq!(result.receive_upper, 0);

        // testnet segwit receive address 5
        let result = account
            .verify_address(
                String::from("tb1qttqxp75y56gvnrr6cy9p8ynvgyjf683ce6d9c4"),
                0,
                50,
            )
            .unwrap();
        assert_eq!(result.found_index, Some(5));
        assert_eq!(result.change_lower, 0);
        assert_eq!(result.change_upper, 4);
        assert_eq!(result.receive_lower, 0);
        assert_eq!(result.receive_upper, 5);

        // ensure the optimization to validate repeat addresses work
        let result = account
            .verify_address(
                String::from("tb1qttqxp75y56gvnrr6cy9p8ynvgyjf683ce6d9c4"),
                0,
                50,
            )
            .unwrap();
        assert_eq!(result.found_index, Some(5));
        assert_eq!(result.change_lower, 0);
        assert_eq!(result.change_upper, 0);
        assert_eq!(result.receive_lower, 5);
        assert_eq!(result.receive_upper, 5);

        // testnet segwit receive address 0, reset for next tests
        let result = account
            .verify_address(
                String::from("tb1qp3s35d5579w9mtx4vkx2lngfpnwyjx8jxhveym"),
                0,
                50,
            )
            .unwrap();
        assert_eq!(result.found_index, Some(0));
        assert_eq!(result.change_lower, 0);
        assert_eq!(result.change_upper, 0);
        assert_eq!(result.receive_lower, 0);
        assert_eq!(result.receive_upper, 0);

        // testnet segwit receive address 30
        let result = account
            .verify_address(
                String::from("tb1qsqtlt0q4why79qmf9jddp53nncyrutv90wdjkz"),
                0,
                50,
            )
            .unwrap();
        assert_eq!(result.found_index, None);
        assert_eq!(result.change_lower, 0);
        assert_eq!(result.change_upper, 25);
        assert_eq!(result.receive_lower, 0);
        assert_eq!(result.receive_upper, 25);

        let result = account
            .verify_address(
                String::from("tb1qsqtlt0q4why79qmf9jddp53nncyrutv90wdjkz"),
                1,
                50,
            )
            .unwrap();
        assert_eq!(result.found_index, Some(30));
        assert_eq!(result.change_lower, 0);
        assert_eq!(result.change_upper, 29);
        assert_eq!(result.receive_lower, 0);
        assert_eq!(result.receive_upper, 30);

        // test that we resume the search from the last verified address, and the downward search
        // works
        // testnet segwit receive address 5
        let result = account
            .verify_address(
                String::from("tb1qttqxp75y56gvnrr6cy9p8ynvgyjf683ce6d9c4"),
                0,
                50,
            )
            .unwrap();
        assert_eq!(result.found_index, None);
        assert_eq!(result.change_lower, 0);
        assert_eq!(result.change_upper, 25);
        assert_eq!(result.receive_lower, 6);
        assert_eq!(result.receive_upper, 55);

        let result = account
            .verify_address(
                String::from("tb1qttqxp75y56gvnrr6cy9p8ynvgyjf683ce6d9c4"),
                1,
                50,
            )
            .unwrap();
        assert_eq!(result.found_index, Some(5));
        assert_eq!(result.change_lower, 0);
        assert_eq!(result.change_upper, 25);
        assert_eq!(result.receive_lower, 5);
        assert_eq!(result.receive_upper, 55);

        // testnet segwit change address 0
        let result = account
            .verify_address(
                String::from("tb1qm2rus4zu75exrlu9rrk0l3ctktkujtetqrjd88"),
                0,
                50,
            )
            .unwrap();
        assert_eq!(result.found_index, None);

        // mainnet segwit receive address 0, should fail network requirement
        assert!(
            account
                .verify_address(
                    String::from("bc1q99mxpdle2pqs3pkaxcz2wmk8l0avgskyuuc6pl"),
                    0,
                    50,
                )
                .is_err()
        );

        // testnet taproot receive address 0
        let result = account
            .verify_address(
                String::from("tb1phv4spu4u6uakttj3mqqcr77la4u6a28j943d3cxjh02a6ny78d0s7tupl5"),
                0,
                50,
            )
            .unwrap();
        assert_eq!(result.found_index.unwrap(), 0);
    }

    #[test]
    #[cfg(feature = "envoy")]
    fn verify_address_2() {
        let account = utils::tests_util::get_ng_hot_wallet();

        // multi-attempt address verification (address 30 fails on first attempt, succeeds on second)
        let result = account
            .verify_address(
                String::from("tb1qsqtlt0q4why79qmf9jddp53nncyrutv90wdjkz"),
                0,
                50,
            )
            .unwrap();
        assert_eq!(result.found_index, None);
        assert_eq!(result.change_lower, 0);
        assert_eq!(result.change_upper, 25);
        assert_eq!(result.receive_lower, 0);
        assert_eq!(result.receive_upper, 25);

        let result = account
            .verify_address(
                String::from("tb1qsqtlt0q4why79qmf9jddp53nncyrutv90wdjkz"),
                1,
                50,
            )
            .unwrap();
        assert_eq!(result.found_index, Some(30));
        assert_eq!(result.change_lower, 0);
        assert_eq!(result.change_upper, 29);
        assert_eq!(result.receive_lower, 0);
        assert_eq!(result.receive_upper, 30);

        // change address verification
        let result = account
            .verify_address(
                String::from("tb1qm2rus4zu75exrlu9rrk0l3ctktkujtetqrjd88"),
                0,
                50,
            )
            .unwrap();
        assert_eq!(result.found_index, None);

        // network validation (mainnet address should fail on testnet account)
        assert!(
            account
                .verify_address(
                    String::from("bc1q99mxpdle2pqs3pkaxcz2wmk8l0avgskyuuc6pl"),
                    0,
                    50,
                )
                .is_err()
        );
    }

    #[test]
    fn autocomplete_seedword() {
        let suggestions = bip39::get_seedword_suggestions("fa", 3);
        assert_eq!(suggestions, ["fabric", "face", "faculty"]);

        let suggestions = bip39::get_seedword_suggestions("xy", 3);
        assert_eq!(suggestions, Vec::<&str>::new());
    }

    #[test]
    #[cfg(feature = "envoy")]
    fn get_external_pubkey() {
        let account = utils::tests_util::get_ng_hot_wallet();
        let descriptors = account.get_external_public_descriptors();
        assert_eq!(descriptors[0],
            (AddressType::P2tr, "tr([20a6ab53/86'/1'/0']tpubDC8wiq86H9ZMiscQMoG1LcvQayTKs9Ef32n4fpVV8JR2FfCDgbTE2yECxi2Bgtkb7UEUheRyeprMtWRFdMXWQq8bx6ugwdTaMp6s2bNYjSV/0/*)#taglzc2a".to_string())
        );

        assert_eq!(descriptors[1],
                   (AddressType::P2wpkh, "wpkh([20a6ab53/84'/1'/0']tpubDC4BKZc39XVBnaTSKLw9ks63KuuEFKdRB17PZMx6GfgxaMHhV79e3zSoVT2TDe9yxwyzm1YHMS8JFNQYWoTvkLJNHa5mTyA5Gkx8NwWVkvU/0/*)#m2myh9ws".to_string())
        );
    }
    #[test]
    #[cfg(feature = "envoy")]
    fn test_bip329_entries_have_valid_structure() {
        let account = utils::tests_util::get_ng_hot_wallet();

        let result = account.get_bip329_data().unwrap();
        assert!(!result.is_empty());

        for entry in &result {
            let json: serde_json::Value = serde_json::from_str(entry).unwrap();

            // All types should have "type" and "ref"
            assert!(json.get("type").is_some());
            assert!(json.get("ref").is_some());

            match json.get("type").unwrap().as_str().unwrap() {
                "xpub" => {
                    assert!(
                        json.get("ref")
                            .unwrap()
                            .as_str()
                            .unwrap()
                            .starts_with("tpub")
                    );
                    assert!(json.get("label").is_some() || json.get("label").is_none());
                }
                "output" => {
                    assert!(json.get("ref").unwrap().as_str().unwrap().contains(':'));
                    assert!(json.get("spendable").is_some());
                }
                "tx" => {
                    assert!(json.get("origin").is_some());
                }
                other => panic!("Unexpected BIP329 type: {other}"),
            }
        }
    }

    #[test]
    #[cfg(feature = "envoy")]
    fn test_bip329_contains_expected_testnet_xpub() {
        let account = utils::tests_util::get_ng_hot_wallet();
        let data = account.get_bip329_data().expect("should export BIP-329");

        let expected_xpub = "tpubDC8wiq86H9ZMiscQMoG1LcvQayTKs9Ef32n4fpVV8JR2FfCDgbTE2yECxi2Bgtkb7UEUheRyeprMtWRFdMXWQq8bx6ugwdTaMp6s2bNYjSV";

        let maybe_entry = data.iter().find(|entry| {
            let json: serde_json::Value = serde_json::from_str(entry).unwrap();
            json.get("type") == Some(&serde_json::Value::String("xpub".to_string()))
                && json.get("ref") == Some(&serde_json::Value::String(expected_xpub.to_string()))
        });

        assert!(
            maybe_entry.is_some(),
            "Expected hardcoded xpub not found in BIP-329 export"
        );
    }
    #[test]
    #[cfg(feature = "envoy")]
    fn test_bip329_export_contains_tx_and_output_notes() {
        let mut account = utils::tests_util::get_ng_hot_wallet();
        utils::tests_util::add_funds_to_wallet(&mut account);

        let txid = account.transactions().unwrap()[0].tx_id.clone();

        // Simulate adding notes
        account.set_note(&txid, "Funding tx").unwrap();

        let output_id = format!("{}:{}", txid, 0); // assuming vout = 0

        // Set a tag for the output
        account.set_tag(&output_id, "important").unwrap();

        let bip329_data = account.get_bip329_data().unwrap();

        let has_tx_note = bip329_data.iter().any(|entry| {
            let json: serde_json::Value = serde_json::from_str(entry).unwrap();
            json.get("type") == Some(&"tx".into())
                && json.get("label") == Some(&"Funding tx".into())
        });

        let has_output_note = bip329_data.iter().any(|entry| {
            let json: serde_json::Value = serde_json::from_str(entry).unwrap();
            json.get("type") == Some(&"output".into())
                && json.get("label") == Some(&"important".into())
        });

        assert!(has_tx_note, "Missing tx note in BIP-329 export");
        assert!(has_output_note, "Missing output note in BIP-329 export");
    }
}

#[cfg(feature = "envoy")]
const EXTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAjWytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/0/*)#g9xn7wf9";

#[cfg(feature = "envoy")]
const INTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAjWytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/1/*)#e3rjrmea";
#[cfg(feature = "envoy")]
const ELECTRUM_SERVER: &str = "ssl://mempool.space:60602";

// TODO: make this unique to the descriptor
#[cfg(test)]
mod tests {
    use {
        bdk_wallet::bitcoin::Network,
        bdk_wallet::WalletPersister,
        bdk_wallet::ChangeSet,
        ngwallet::account::NgAccount,
        ngwallet::bip39,
        ngwallet::config::AddressType,
        ngwallet::ngwallet::{ExportMode, ExportTarget},
        redb::backends::FileBackend,
        std::sync::{Arc, Mutex},
    };

    struct MockPersister;

    impl WalletPersister for MockPersister {
        type Error = ();

        fn initialize(_persister: &mut Self) -> Result<ChangeSet, Self::Error> {
            Ok(ChangeSet::default())
        }

        fn persist(
            _persister: &mut Self,
            _changeset: &ChangeSet,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[cfg(feature = "envoy")]
    use {
        crate::*,
        bdk_wallet::{AddressInfo, Update},
        bdk_wallet::rusqlite::Connection,
        ngwallet::ngwallet::NgWallet,
        ngwallet::send::TransactionParams,
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

        let transactions = account.wallet.transactions().unwrap();
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

    //noinspection RsExternalLinter
    #[test]
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

        let transactions = account.wallet.transactions().unwrap();
        let utxos = account.wallet.unspend_outputs().unwrap_or_default();

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
        for utxo in utxos {
            account
                .wallet
                .set_tag(&utxo, format!("Tag {}", utxo.vout).as_str())
                .unwrap();
        }
        let utxos = account.wallet.unspend_outputs().unwrap();

        for utxo in utxos {
            println!("Utxo: {} {:?}", utxo.amount, utxo.tag);
        }
        // if !utxos.is_empty() {
        //     let tag = "Test Tag".to_string();
        //     println!("\nSetting tag: {:?}", tag);
        //     let first_utxo = &utxos[0];
        //     account.wallet.set_tag(first_utxo, tag.as_str()).unwrap();
        //     let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
        //     let utxo_tag = utxos[0].tag.clone().unwrap_or("".to_string());
        //     println!("Utxo tag: {:?}", utxo_tag);
        //     assert_eq!(utxo_tag, tag);
        //
        //     println!("\nSetting do not spend : {:?}", true);
        //
        //     account.wallet.set_do_not_spend(first_utxo, true).unwrap();
        //
        //     let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
        //     let utxo_tag = &utxos[0];
        //     println!("Utxo After Do not Spend: {:?}", utxo_tag);
        //     let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
        //     let utxo_tag = &utxos[0];
        //     println!("Utxo After Do not Spend: {:?}", utxo_tag);
        // }
        println!("Balance {:?}", balance);

        let param = TransactionParams {
            address: "tb1phc8m8vansnl4utths947mjquprw20puwrrdfrwx8akeeu2tqwkls7l62u4".to_string(),
            amount: 105117,
            fee_rate: 2,
            selected_outputs: vec![],
            note: Some("not a note".to_string()),
            tag: Some("hello".to_string()),
            do_not_spend_change: true,
        };

        match account.wallet.get_max_fee(param.clone()) {
            Ok(tx_fee_calc) => {
                println!(
                    "max fee calculated {:?}",
                    tx_fee_calc.prepared_transaction.transaction.fee
                );
            }
            Err(er) => {
                println!("max fee error {} ", er)
            }
        };

        match account.wallet.compose_psbt(param.clone()) {
            Ok(spend) => {
                println!("Spend note: {:?}", spend.transaction.note);
                // match account
                //     .wallet
                //     .broadcast_psbt(spend.clone(), ELECTRUM_SERVER, None)
                // {
                //     Ok(tx_id) => {
                //         assert_eq!(tx_id, spend.transaction.tx_id);
                //         println!("broadcast success {:?} ", spend)
                //     }
                //     Err(error) => {
                //         println!("Spend error {:?} ", error)
                //     }
                // }
            }
            Err(er) => {
                println!("Spend error {} ", er)
            }
        };

        // let transactions = account.wallet.transactions().unwrap();
        // transactions.iter().for_each(|tx| {
        //     println!(
        //         "\nTx: --> {:?} | Amount:{} | Note:{:?} |  ",
        //         tx.address, tx.amount, tx.note
        //     );
        //     tx.outputs.iter().for_each(|utxo| {
        //         println!(
        //             "Utxo: --> {:?} | Amount:{:?} | Tag:{:?} | DnS{:?}",
        //             utxo.address, utxo.amount, utxo.tag, utxo.do_not_spend
        //         );
        //     });
        // });
        //
        // account.wallet.persist().expect("Wallet persisted");
        drop(account)
    }

    #[test]
    fn autocomplete_seedword() {
        let suggestions = bip39::get_seedword_suggestions("fa", 3);
        assert_eq!(suggestions, ["fabric", "face", "faculty"]);

        let suggestions = bip39::get_seedword_suggestions("xy", 3);
        assert_eq!(suggestions, Vec::<&str>::new());
    }

    const SEGWIT_EXTERNAL: &str = "wpkh([ab88de89/84h/0h/0h]xpub6CikkQWpo5GK4aDK8KCkmZcHKdANfNorMPfVz2QoS4x6FMg38SeTahR8i666uEUk1ZoZhyM5uctHf1Rpddbbf4YpoaVcieYvZWRG6UU7gzN/0/*)#rru0km0r";

    const SEGWIT_INTERNAL: &str = "wpkh([ab88de89/84h/0h/0h]xpub6CikkQWpo5GK4aDK8KCkmZcHKdANfNorMPfVz2QoS4x6FMg38SeTahR8i666uEUk1ZoZhyM5uctHf1Rpddbbf4YpoaVcieYvZWRG6UU7gzN/1/*)#jhewtwlm";

    #[test]
    fn connection_export() {
        let connection = MockPersister;
        let account = NgAccount::new_from_descriptor(
            "Passport Prime".to_string(),
            "red".to_string(),
            None,
            None,
            Network::Bitcoin,
            AddressType::P2tr,
            SEGWIT_INTERNAL.to_string(),
            Some(SEGWIT_EXTERNAL.to_string()),
            0,
            None,
            Arc::new(Mutex::new(connection)),
            None::<FileBackend>,
            "".to_string(),
            None,
        );

        assert_eq!(String::from("AB88DE89"), account.wallet.get_xfp());
        assert_eq!(String::from("84'/0'/0'/0"), account.wallet.get_derivation_path());

        assert_eq!(String::from("# Bitcoin Core Wallet Import File\n\n## For wallet with master key fingerprint: AB88DE89\n\nWallet operates on blockchain: bitcoin\n\n## Bitcoin Core RPC\n\nThe following command can be entered after opening Window -> Console\nin Bitcoin Core, or using bitcoin-cli:\n\nimportmulti '[{\"desc\":\"wpkh([ab88de89/84h/0h/0h]xpub6CikkQWpo5GK4aDK8KCkmZcHKdANfNorMPfVz2QoS4x6FMg38SeTahR8i666uEUk1ZoZhyM5uctHf1Rpddbbf4YpoaVcieYvZWRG6UU7gzN/0/*)#rru0km0r\",\"internal\":false,\"keypool\":true,\"range\":[0,1000],\"timestamp\":\"now\",\"watchonly\":true},{\"desc\":\"wpkh([ab88de89/84h/0h/0h]xpub6CikkQWpo5GK4aDK8KCkmZcHKdANfNorMPfVz2QoS4x6FMg38SeTahR8i666uEUk1ZoZhyM5uctHf1Rpddbbf4YpoaVcieYvZWRG6UU7gzN/1/*)#jhewtwlm\",\"internal\":true,\"keypool\":true,\"range\":[0,1000],\"timestamp\":\"now\",\"watchonly\":true}]'\n\n## Resulting Addresses (first 3)\n\nm/84'/0'/0'/0/0 => bc1qm6aw3ek0jvsngylhu3rnw66wv9g67ukah2lenl\nm/84'/0'/0'/0/1 => bc1qagpt03nf6ffhaps7lhs88m25l5sxhu3np602dy\nm/84'/0'/0'/0/2 => bc1qtjq8fhatmu8f4u2tp5kqx3n5964npj4pku5fsx"), account.wallet.connection_export(ExportMode::File, ExportTarget::BitcoinCore).unwrap());
    }
}

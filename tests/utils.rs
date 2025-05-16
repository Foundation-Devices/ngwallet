#[allow(dead_code)]
pub mod tests_util {
    use bdk_electrum::bdk_core::bitcoin::{
        Address, Amount, BlockHash, FeeRate, Network, Transaction, TxOut,
    };
    use bdk_electrum::bdk_core::{BlockId, ConfirmationBlockTime};
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::rusqlite::Connection;
    use bdk_wallet::test_utils::{insert_seen_at, new_tx};
    use bdk_wallet::{KeychainKind, WalletPersister};
    use ngwallet::account::{Descriptor, NgAccount};
    use ngwallet::config::{AddressType, NgAccountBuilder};
    use ngwallet::ngwallet::NgWallet;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn get_ng_hot_wallet() -> NgAccount<Connection> {
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

        NgAccountBuilder::default()
            .name("Passport Prime".to_string())
            .color("red".to_string())
            .seed_has_passphrase(false)
            .device_serial(None)
            .date_added(None)
            .preferred_address_type(AddressType::P2tr)
            .index(0)
            .descriptors(descriptors)
            .date_synced(None)
            .db_path(None)
            .network(Network::Signet)
            .id("1234567890".to_string())
            .build_in_memory()
            .unwrap()
    }

    //creates a new account with the descriptors,in memory db's
    pub fn get_ng_watch_only_account() -> NgAccount<Connection> {
        const CHANGE_DESCRIPTOR: &str = "sh(wpkh([b32cb478/49'/1'/0']tpubDCe1VCD4yuxQxY6XUT1v7K2vLpfHNoVosUTwfRrkxetL5ADh7DsdiVSGfyCEy13jvrYZJVKNXeTRTDqYUL9PfPwRF1o9jFmaucj5WH34rZ6/1/*))#wpq5kysn";
        const DESCRIPTOR: &str = "tr([b32cb478/86'/1'/0']tpubDDoYQrzVMLsiAyHic7ddJ4wbPVTmgMrP2VqJKxotZRZbzShPfTK1mdyxUzWdtrEgGm3xeMaWkPMnyFG3TVb4zbPgUizD8prMGteYHAT8V9o/0/*)#pjg8jh2k";

        const CHANGE_DESCRIPTOR_2: &str = "sh(wpkh([b32cb478/49'/1'/0']tpubDCe1VCD4yuxQxY6XUT1v7K2vLpfHNoVosUTwfRrkxetL5ADh7DsdiVSGfyCEy13jvrYZJVKNXeTRTDqYUL9PfPwRF1o9jFmaucj5WH34rZ6/1/*))#wpq5kysn";
        const DESCRIPTOR_2: &str = "wpkh([b32cb478/84'/1'/0']tpubDC5rRpwGYWMofEkdcFH18PuxhjyUtQe4brjrkcG1qvyKRyDeSYCdRKTFVEfDn3sAwEmM2LYGK9oi15BRu8Wb6nDNex5jhDauPLztkR56KQ8/0/*)#t587tjpy";

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

        NgAccountBuilder::default()
            .name("Passport Prime".to_string())
            .color("red".to_string())
            .seed_has_passphrase(false)
            .device_serial(None)
            .date_added(None)
            .preferred_address_type(AddressType::P2tr)
            .index(0)
            .descriptors(descriptors)
            .date_synced(None)
            .db_path(None)
            .network(Network::Signet)
            .id("1234567890".to_string())
            .build_in_memory()
            .unwrap()
    }

    pub fn add_funds_to_wallet<P: WalletPersister>(account: &mut NgAccount<P>) {
        for (index, ngwallet) in account.wallets.iter().enumerate() {
            fill_with_txes(index, &ngwallet)
        }
    }

    pub fn add_funds_wallet_with_unconfirmed<P: WalletPersister>(account: &mut NgAccount<P>) {
        for (index, ngwallet) in account.wallets.iter().enumerate() {
            fill_with_txes(index, &ngwallet);
        }
        fill_with_unconfirmed(&account.get_coordinator_wallet());
    }

    fn fill_with_unconfirmed<P: WalletPersister>(ngwallet: &&NgWallet<P>) {
        let mut wallet = ngwallet.bdk_wallet.lock().unwrap();
        let to_address =
            Address::from_str("tb1pspfcrvz538vvj9f9gfkd85nu5ty98zw9y5e302kha6zurv6vg07s8z7a8w")
                .unwrap()
                .require_network(Network::Signet)
                .unwrap();
        let mut psbt = {
            let mut builder = wallet.build_tx();
            builder
                .add_recipient(to_address.script_pubkey(), Amount::from_sat(800))
                .fee_rate(FeeRate::from_sat_per_vb(1).unwrap());
            builder.finish().unwrap()
        };

        wallet
            .sign(&mut psbt, Default::default())
            .expect("Failed to sign PSBT");

        let transaction = psbt.extract_tx().unwrap();
        // Insert the transaction into the wallet
        let txid = transaction.compute_txid();
        bdk_wallet::test_utils::insert_tx(&mut wallet, transaction.clone());

        // Mark the transaction as unconfirmed in the mempool
        let last_seen = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("")
            .as_secs();
        insert_seen_at(&mut wallet, txid, last_seen)
    }

    fn fill_with_txes<P: WalletPersister>(index: usize, ngwallet: &&NgWallet<P>) {
        let amounts = [76_000, 25_000];
        let mut wallet = ngwallet.bdk_wallet.lock().unwrap();
        let receive_address = wallet.next_unused_address(KeychainKind::External).address;

        let tx0 = Transaction {
            output: vec![TxOut {
                value: Amount::from_sat(amounts[index]),
                script_pubkey: receive_address.script_pubkey(),
            }],
            ..new_tx(0)
        };
        bdk_wallet::test_utils::insert_checkpoint(
            &mut wallet,
            BlockId {
                height: 42,
                hash: BlockHash::all_zeros(),
            },
        );
        bdk_wallet::test_utils::insert_checkpoint(
            &mut wallet,
            BlockId {
                height: 1_000,
                hash: BlockHash::all_zeros(),
            },
        );
        bdk_wallet::test_utils::insert_checkpoint(
            &mut wallet,
            BlockId {
                height: 2_000,
                hash: BlockHash::all_zeros(),
            },
        );

        bdk_wallet::test_utils::insert_tx(&mut wallet, tx0.clone());
        bdk_wallet::test_utils::insert_anchor(
            &mut wallet,
            tx0.compute_txid(),
            ConfirmationBlockTime {
                block_id: BlockId {
                    height: 1_000,
                    hash: BlockHash::all_zeros(),
                },
                confirmation_time: 100,
            },
        );
    }
}
//creates a new account with the descriptors,in memory db's

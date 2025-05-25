#[allow(dead_code)]
#[cfg(feature = "envoy")]
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
        const CHANGE_DESCRIPTOR: &str = "sh(wpkh(tprv8ZgxMBicQKsPeF3suFMx4YnZMeEemCKLTmTCWDzg92YSB2tLhmWmyvmCXn8anZ4XuZAuwiGB9Q4UkZKcEHFZFy792UtGSRtAqaHWc64QH2q/49'/1'/0'/1/*))#ncxfs3tl";
        const DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPeF3suFMx4YnZMeEemCKLTmTCWDzg92YSB2tLhmWmyvmCXn8anZ4XuZAuwiGB9Q4UkZKcEHFZFy792UtGSRtAqaHWc64QH2q/86'/1'/0'/0/*)#fx8l3ud5";

        const CHANGE_DESCRIPTOR_2: &str = "sh(wpkh(tprv8ZgxMBicQKsPeF3suFMx4YnZMeEemCKLTmTCWDzg92YSB2tLhmWmyvmCXn8anZ4XuZAuwiGB9Q4UkZKcEHFZFy792UtGSRtAqaHWc64QH2q/49'/1'/0'/1/*))#ncxfs3tl";
        const DESCRIPTOR_2: &str = "wpkh(tprv8ZgxMBicQKsPeF3suFMx4YnZMeEemCKLTmTCWDzg92YSB2tLhmWmyvmCXn8anZ4XuZAuwiGB9Q4UkZKcEHFZFy792UtGSRtAqaHWc64QH2q/84'/1'/0'/0/*)#kqma4m73";

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
            .account_path(None)
            .network(Network::Signet)
            .id("1234567890".to_string())
            .build_in_memory()
            .unwrap()
    }

    //creates a new account with the descriptors,in memory db's
    pub fn get_ng_watch_only_account() -> NgAccount<Connection> {
        const CHANGE_DESCRIPTOR: &str = "sh(wpkh([20a6ab53/49'/1'/0']tpubDCSHQvE5xErAQFkY7WuQLpVJJmhbcLf6R3711p4oG32ojtn8SGM48bQ6bkHorT117BKGEorR3MJJVk4mrRLyG41g1kEfRbVAthRVoLi43Dq/1/*))#4p50dftv";
        const DESCRIPTOR: &str = "tr([20a6ab53/86'/1'/0']tpubDC8wiq86H9ZMiscQMoG1LcvQayTKs9Ef32n4fpVV8JR2FfCDgbTE2yECxi2Bgtkb7UEUheRyeprMtWRFdMXWQq8bx6ugwdTaMp6s2bNYjSV/0/*)#taglzc2a";

        const CHANGE_DESCRIPTOR_2: &str = "sh(wpkh([20a6ab53/49'/1'/0']tpubDCSHQvE5xErAQFkY7WuQLpVJJmhbcLf6R3711p4oG32ojtn8SGM48bQ6bkHorT117BKGEorR3MJJVk4mrRLyG41g1kEfRbVAthRVoLi43Dq/1/*))#4p50dftv";
        const DESCRIPTOR_2: &str = "wpkh([20a6ab53/84'/1'/0']tpubDC4BKZc39XVBnaTSKLw9ks63KuuEFKdRB17PZMx6GfgxaMHhV79e3zSoVT2TDe9yxwyzm1YHMS8JFNQYWoTvkLJNHa5mTyA5Gkx8NwWVkvU/0/*)#m2myh9ws";

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
            .account_path(None)
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
            Address::from_str("tb1phv4spu4u6uakttj3mqqcr77la4u6a28j943d3cxjh02a6ny78d0s7tupl5")
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

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::{Address, Amount, BlockHash, FeeRate, Network, Transaction, TxOut};
use bdk_wallet::chain::{BlockId, ConfirmationBlockTime};
use bdk_wallet::test_utils::{insert_seen_at, new_tx};
use bdk_wallet::{KeychainKind, WalletPersister};

use ngwallet::account::NgAccount;
use ngwallet::ngwallet::NgWallet;

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

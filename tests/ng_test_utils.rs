use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};
use bdk_wallet::{PersistedWallet, Update};
use bdk_wallet::bitcoin::{Address, Network,Transaction,Txid,TxOut,TxIn,OutPoint,Amount,BlockHash};
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::chain::{BlockId, ConfirmationBlockTime, tx_graph, TxUpdate};
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::test_utils::new_tx;
use ngwallet::account::NgAccount;


pub fn get_account_with_confirmed_unconfirmed(mut account:  &mut NgAccount<Connection>) {
    let receive_address = {
        account.next_address().unwrap()
    };
    let sendto_address = Address::from_str("tb1qr6lmcexy6285f3a04j2a75d39qvcdek739g8cz")
        .expect("address")
        .require_network(Network::Signet)
        .unwrap();

    {
        for (index,ngwallet) in account.wallets.iter().enumerate() {
            let mut wallet = ngwallet.bdk_wallet.lock().unwrap();
            let tx0 = Transaction {
                output: vec![TxOut {
                    value: Amount::from_sat(76_000),
                    script_pubkey: receive_address[index].script_pubkey(),
                }],
                ..new_tx(0)
            };

            let tx0 = Transaction {
                output: vec![TxOut {
                    value: Amount::from_sat(76_000),
                    script_pubkey: receive_address[index].script_pubkey(),
                }],
                ..new_tx(0)
            };

            let tx1 = Transaction {
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: tx0.compute_txid(),
                        vout: 0,
                    },
                    ..Default::default()
                }],
                output: vec![
                    TxOut {
                        value: Amount::from_sat(50_000),
                        script_pubkey: receive_address[index].script_pubkey(),
                    },
                    TxOut {
                        value: Amount::from_sat(25_000),
                        script_pubkey: sendto_address.script_pubkey(),
                    },
                ],
                ..new_tx(0)
            };

            insert_checkpoint(
                &mut wallet,
                BlockId {
                    height: 42,
                    hash: BlockHash::all_zeros(),
                },
            );
            insert_checkpoint(
                &mut wallet,
                BlockId {
                    height: 1_000,
                    hash: BlockHash::all_zeros(),
                },
            );
            insert_checkpoint(
                &mut wallet,
                BlockId {
                    height: 2_000,
                    hash: BlockHash::all_zeros(),
                },
            );
            //
            insert_tx(&mut wallet,tx0.clone());
            insert_anchor(
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
            //
            insert_tx(&mut wallet, tx1.clone());
            insert_anchor(
                &mut wallet,
                tx1.compute_txid(),
                ConfirmationBlockTime {
                    block_id: BlockId {
                        height: 0,
                        hash: BlockHash::all_zeros(),
                    },
                    confirmation_time: 0,
                },
            );
        }

    }

    // let update = NgWallet::<Connection>::scan(request, ELECTRUM_SERVER, None).unwrap();
    // account.wallet.apply(Update::from(update)).unwrap();
}

pub fn insert_tx(wallet: &mut MutexGuard<PersistedWallet<Connection>>, tx: Transaction) {
    wallet
        .apply_update(Update {
            tx_update: TxUpdate {
                txs: vec![Arc::new(tx)],
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
}

pub fn insert_anchor(wallet: &mut MutexGuard<PersistedWallet<Connection>>, txid: Txid, anchor: ConfirmationBlockTime) {
    wallet
        .apply_update(Update {
            tx_update: tx_graph::TxUpdate {
                anchors: [(anchor, txid)].into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
}

pub fn insert_checkpoint(wallet: &mut MutexGuard<PersistedWallet<Connection>>, block: BlockId) {
    let mut cp = wallet.latest_checkpoint();
    cp = cp.insert(block);
    wallet
        .apply_update(Update {
            chain: Some(cp),
            ..Default::default()
        })
        .unwrap();
}

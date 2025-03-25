use std::fmt::Debug;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{Ok, Result};
use bdk_wallet::{bitcoin, KeychainKind, WalletPersister};
use bdk_wallet::bitcoin::{Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Txid};
use bdk_wallet::chain::ChainPosition::{Confirmed, Unconfirmed};
use bdk_wallet::chain::spk_client::FullScanRequest;
use bdk_wallet::{AddressInfo, PersistedWallet, SignOptions};
use bdk_wallet::{Update, Wallet};

#[cfg(feature = "envoy")]
use {
    bdk_electrum::BdkElectrumClient, bdk_electrum::bdk_core::spk_client::FullScanResponse,
    bdk_electrum::electrum_client::Client, bdk_wallet::rusqlite::Connection,
};

use crate::store::MetaStorage;
use crate::transaction::{BitcoinTransaction, Input, Output};
use crate::{BATCH_SIZE, STOP_GAP};

#[derive(Debug)]
pub struct NgWallet<P: WalletPersister> {
    pub wallet: Arc<Mutex<PersistedWallet<P>>>,
    meta_storage: Arc<Mutex<dyn MetaStorage>>,
    bdk_persister: Arc<Mutex<P>>,
}

impl<P: WalletPersister> NgWallet<P> {
    pub fn new_from_descriptor(
        internal_descriptor: String,
        external_descriptor: Option<String>,
        network: Network,
        meta_storage: Arc<Mutex<dyn MetaStorage>>,
        mut bdk_persister: Arc<Mutex<P>>,
    ) -> Result<NgWallet<P>> {
        let wallet = match external_descriptor {
            None => Wallet::create_single(internal_descriptor.to_string()),
            Some(external_descriptor) => {
                Wallet::create(internal_descriptor.to_string(), external_descriptor)
            }
        }
            .network(network)
            .create_wallet(&mut *bdk_persister.lock().unwrap())
            .map_err(|e| anyhow::anyhow!("Couldn't create wallet"))
            .unwrap();

        Ok(Self {
            wallet: Arc::new(Mutex::new(wallet)),
            bdk_persister,
            meta_storage,
        })
    }

    pub fn persist(&mut self) -> Result<bool> {
        self.wallet
            .lock()
            .unwrap()
            .persist(&mut self.bdk_persister.lock().unwrap())
            .map_err(|_| anyhow::anyhow!("Could not persist wallet"))
    }

    pub fn load(meta_storage: Arc<Mutex<dyn MetaStorage>>, mut bdk_persister: Arc<Mutex<P>>,) -> Result<NgWallet<P>> where <P as WalletPersister>::Error: Debug {
        // #[cfg(feature = "envoy")]
        //     let mut persister = Connection::open(format!("{}/wallet.sqlite",db_path))?;


        let wallet_opt = Wallet::load().load_wallet(&mut *bdk_persister.lock().unwrap()).unwrap();

        match wallet_opt {
            Some(wallet) => {
                Ok(Self {
                    wallet: Arc::new(Mutex::new(wallet)),
                    bdk_persister,
                    meta_storage,
                })
            }
            None => Err(anyhow::anyhow!("Failed to load wallet database.")),
        }
    }

    pub fn next_address(&mut self) -> Result<AddressInfo> {
        let address: AddressInfo = self
            .wallet
            .lock()
            .unwrap()
            .reveal_next_address(KeychainKind::External);
        self.persist()?;
        Ok(address)
    }

    pub fn transactions(&self) -> Result<Vec<BitcoinTransaction>> {
        let wallet = self.wallet.lock().unwrap();
        let mut transactions: Vec<BitcoinTransaction> = vec![];
        let tip_height = wallet.latest_checkpoint().height();
        let storage = self.meta_storage.lock().unwrap();

        for canonical_tx in wallet.transactions() {
            let tx = canonical_tx.tx_node.tx;
            let tx_id = canonical_tx.tx_node.txid.to_string();
            let (sent, received) = wallet.sent_and_received(tx.as_ref());
            let fee = wallet.calculate_fee(tx.as_ref()).unwrap().to_sat();
            let block_height = match canonical_tx.chain_position {
                Confirmed { anchor, .. } => {
                    let block_height = anchor.block_id.height;
                    if block_height > 0 { block_height } else { 0 }
                }
                Unconfirmed { .. } => 0,
            };
            let confirmations = if block_height > 0 {
                tip_height - block_height + 1
            } else {
                0
            };

            let inputs = tx
                .input
                .clone()
                .iter()
                .map(|input| {
                    let tx_id = input.previous_output.txid.to_string();
                    let vout = input.previous_output.vout;
                    Input { tx_id, vout }
                })
                .collect::<Vec<Input>>();

            let outputs = tx
                .output
                .clone()
                .iter()
                .enumerate()
                .map(|(index, output)| {
                    let amount = output.value;
                    Output {
                        tx_id: tx_id.clone(),
                        vout: index as u32,
                        amount: amount.to_sat(),
                        tag: storage.get_tag(&tx_id).unwrap(),
                        do_not_spend: storage.get_do_not_spend(&tx_id).unwrap(),
                    }
                })
                .collect::<Vec<Output>>();

            let amount = if sent.to_sat() > 0 {
                sent.to_sat()
            } else {
                received.to_sat()
            };

            transactions.push(BitcoinTransaction {
                tx_id: tx_id.clone(),
                block_height,
                confirmations,
                fee,
                amount,
                inputs,
                outputs,
                note: storage.get_note(&tx_id).unwrap(),
            })
        }

        Ok(transactions)
    }

    pub fn scan_request(&self) -> FullScanRequest<KeychainKind> {
        self.wallet.lock().unwrap().start_full_scan().build()
    }

    #[cfg(feature = "envoy")]
    pub fn scan(request: FullScanRequest<KeychainKind>,electrum_server:&str) -> Result<FullScanResponse<KeychainKind>> {
        let client: BdkElectrumClient<Client> =
            BdkElectrumClient::new(Client::new(electrum_server)?);
        let update = client.full_scan(request, STOP_GAP, BATCH_SIZE, true)?;
        Ok(update)
    }

    pub fn unspend_outputs(&self) -> Result<Vec<Output>> {
        let wallet = self.wallet.lock().unwrap();
        let mut unspents: Vec<Output> = vec![];
        let mut meta_storage = self.meta_storage.lock().unwrap();
        for local_output in wallet.list_unspent() {
            let out_put_id = format!(
                "{}:{}",
                local_output.outpoint.txid.to_string(),
                local_output.outpoint.vout,
            );
            unspents.push(Output {
                tx_id: local_output.outpoint.txid.to_string(),
                vout: local_output.outpoint.vout,
                amount: local_output.txout.value.to_sat(),
                tag: meta_storage.get_tag(out_put_id.clone().as_str()).unwrap(),
                do_not_spend: meta_storage.get_do_not_spend(out_put_id.as_str()).unwrap(),
            });
        }
        Ok(unspents)
    }

    pub fn apply(&mut self, update: Update) -> Result<()> {
        self.wallet
            .lock()
            .unwrap()
            .apply_update(update)
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub fn balance(&self) -> Result<bdk_wallet::Balance> {
        Ok(self.wallet.lock().unwrap().balance())
    }

    //TODO: fix, check descriptor
    pub fn is_hot(&self) -> bool {
        true
    }

    pub fn create_send(&mut self, address: String, amount: u64) -> Result<Psbt> {
        let mut wallet = self.wallet.lock().unwrap();
        let address = Address::from_str(&address)?.require_network(wallet.network())?;
        let script: ScriptBuf = address.into();
        let mut builder = wallet.build_tx();
        builder.add_recipient(script.clone(), Amount::from_sat(amount));

        let psbt = builder.finish()?;
        Ok(psbt)
    }

    pub fn sign(&self, psbt: &str) -> Result<String> {
        let mut psbt = Psbt::from_str(psbt)?;
        self.wallet
            .lock()
            .unwrap()
            .sign(&mut psbt, SignOptions::default())?;
        Ok(psbt.serialize_hex())
    }

    #[cfg(feature = "envoy")]
    pub fn broadcast(&mut self, psbt: Psbt,electrum_server: &str) -> Result<()> {
        let client: BdkElectrumClient<Client> =
            BdkElectrumClient::new(Client::new(electrum_server)?);

        let tx = psbt.extract_tx()?;
        client.transaction_broadcast(&tx)?;

        Ok(())
    }

    pub fn set_note(
        &mut self,
        tx_id: &str,
        note: &str,
    ) -> Result<bool> {
        self.wallet
            .lock()
            .unwrap()
            .get_tx(Txid::from_str(&tx_id).unwrap())
            .map(|tx| tx.tx_node.tx.compute_txid())
            .map(|tx| {
                self.meta_storage
                    .lock().unwrap().set_note(&tx.to_string(), note).map_err(|e| {
                    anyhow::anyhow!("Could not set note {:?}", e.to_string())
                })
            });
        Ok(true)
    }

    pub fn set_tag(
        &mut self,
        output: &Output,
        tag: &str,
    ) -> Result<bool> {
        self.meta_storage.lock().unwrap()
            .set_tag(output.get_id().as_str(), tag)
            .map_err(|_| anyhow::anyhow!("Could not set tag "))
            .unwrap();
        Ok(true)
    }

    pub fn set_do_not_spend(
        &mut self,
        output: &Output,
        state: bool,
    ) -> Result<bool> {
        let out_point = OutPoint::new(Txid::from_str(&output.tx_id).unwrap(), output.vout);
        self.wallet.lock().unwrap().get_utxo(out_point).map(|_| {
            self.meta_storage
                .lock().unwrap()
                .set_do_not_spend(output.get_id().as_str(), state)
                .map_err(|_| anyhow::anyhow!("Could not set do not spend"))
                .unwrap();
            Ok(true)
        }).unwrap_or(Ok(false))
    }
}

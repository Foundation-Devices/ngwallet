use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{Ok, Result};
use bdk_wallet::{AddressInfo, PersistedWallet, SignOptions};
use bdk_wallet::{Update, Wallet};
use bdk_wallet::bitcoin::{Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Txid};
use bdk_wallet::chain::ChainPosition::{Confirmed, Unconfirmed};
use bdk_wallet::chain::spk_client::FullScanRequest;
use bdk_wallet::KeychainKind;
use crate::keyos::KeyOsPersister;

#[cfg(feature = "envoy")]
use {
    bdk_electrum::bdk_core::spk_client::FullScanResponse,
    bdk_electrum::BdkElectrumClient,
    bdk_electrum::electrum_client::Client,
    bdk_wallet::rusqlite::Connection,
};

use crate::{BATCH_SIZE, ELECTRUM_SERVER, EXTERNAL_DESCRIPTOR, INTERNAL_DESCRIPTOR, STOP_GAP};
use crate::store::MetaStorage;
use crate::transaction::{BitcoinTransaction, Input, Output};

#[derive(Debug)]
pub struct NgWallet {
    #[cfg(feature = "envoy")]
    pub wallet: Arc<Mutex<PersistedWallet<Connection>>>,
    #[cfg(feature = "envoy")]
    persister: Arc<Mutex<Connection>>,

    #[cfg(not(feature = "envoy"))]
    pub wallet: Arc<Mutex<PersistedWallet<KeyOsPersister>>>,
    #[cfg(not(feature = "envoy"))]
    persister: Arc<Mutex<KeyOsPersister>>,
    pub descriptors: Vec<String>,
    meta_storage: Box<dyn MetaStorage>,
}

impl NgWallet {
    pub fn new(db_path: Option<String>, meta_storage: Box<dyn MetaStorage>) -> Result<NgWallet> {

        #[cfg(feature = "envoy")]
            let mut persister = match db_path.clone() {
            None => Connection::open_in_memory(),
            Some(path) => Connection::open(path),
        }?;

        #[cfg(not(feature = "envoy"))]
            let mut persister = KeyOsPersister {};

        let wallet = Wallet::create(EXTERNAL_DESCRIPTOR, INTERNAL_DESCRIPTOR)
            .network(Network::Signet)
            .create_wallet(&mut persister)
            .map_err(|_| anyhow::anyhow!("Couldn't create wallet"))?;

        Ok(Self {
            wallet: Arc::new(Mutex::new(wallet)),
            persister: Arc::new(Mutex::new(persister)),
            descriptors: vec![
                EXTERNAL_DESCRIPTOR.to_string(),
                INTERNAL_DESCRIPTOR.to_string(),
            ],
            meta_storage,
        })
    }

    pub fn new_from_descriptor(
        db_path: Option<String>,
        descriptor: String,
        meta_storage: Box<dyn MetaStorage>,
    ) -> Result<NgWallet> {
       
        #[cfg(feature = "envoy")]
            let mut persister = match db_path.clone() {
            None => Connection::open_in_memory(),
            Some(path) => Connection::open(path),
        }?;
        
        #[cfg(not(feature = "envoy"))]
            let mut persister = KeyOsPersister {};

        let wallet = Wallet::create_single(descriptor)
            .network(Network::Signet)
            .create_wallet(&mut persister)
            .map_err(|_| anyhow::anyhow!("Couldn't create a single descriptor wallet"))?;

        Ok(Self {
            wallet: Arc::new(Mutex::new(wallet)),
            persister: Arc::new(Mutex::new(persister)),
            descriptors: vec![
                EXTERNAL_DESCRIPTOR.to_string(),
                INTERNAL_DESCRIPTOR.to_string(),
            ],
            meta_storage,
        }) 
    }

    pub fn persist(&mut self) -> Result<bool> {
        self.wallet
            .lock()
            .unwrap()
            .persist(&mut self.persister.lock().unwrap()).map_err(|_| anyhow::anyhow!("Could not persist wallet"))
    }

    pub fn load(db_path: &str, meta_storage: Box<dyn MetaStorage>) -> Result<NgWallet> {


        #[cfg(feature = "envoy")]
            let mut persister = Connection::open(db_path)?;

        #[cfg(not(feature = "envoy"))]
            let mut persister = KeyOsPersister {};

        let wallet_opt = Wallet::load()
            .load_wallet(&mut persister).unwrap();

        match wallet_opt {
            Some(wallet) => {
                println!("Loaded existing wallet database.");
                Ok(Self {
                    wallet: Arc::new(Mutex::new(wallet)),
                    descriptors: vec![
                        EXTERNAL_DESCRIPTOR.to_string(),
                        INTERNAL_DESCRIPTOR.to_string(),
                    ],
                    meta_storage,
                    persister: Arc::new(Mutex::new(persister)),
                })
            }
            None => Err(anyhow::anyhow!("Failed to load wallet database .")),
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
                        tag: self.meta_storage.get_tag(&tx_id),
                        do_not_spend: self.meta_storage.get_do_not_spend(&tx_id),
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
                note: self.meta_storage.get_note(&tx_id),
            })
        }

        Ok(transactions)
    }

    pub fn scan_request(&self) -> FullScanRequest<KeychainKind> {
        self.wallet.lock().unwrap().start_full_scan().build()
    }

    #[cfg(feature = "envoy")]
    pub fn scan(request: FullScanRequest<KeychainKind>) -> Result<FullScanResponse<KeychainKind>> {
        let client: BdkElectrumClient<Client> =
            BdkElectrumClient::new(Client::new(ELECTRUM_SERVER)?);
        let update = client.full_scan(request, STOP_GAP, BATCH_SIZE, true)?;

        Ok(update)
    }

    pub fn unspend_outputs(&self) -> Result<Vec<Output>> {
        let wallet = self.wallet.lock().unwrap();
        let mut unspents: Vec<Output> = vec![];
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
                tag: self.meta_storage.get_tag(out_put_id.clone().as_str()),
                do_not_spend: self.meta_storage.get_do_not_spend(out_put_id.as_str()),
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

    pub fn sign(&self, psbt: &Psbt) -> Result<Psbt> {
        let mut psbt = psbt.to_owned();
        self.wallet
            .lock()
            .unwrap()
            .sign(&mut psbt, SignOptions::default())?;
        Ok(psbt)
    }

    #[cfg(feature = "envoy")]
    pub fn broadcast(&mut self, psbt: Psbt) -> Result<()> {
        let client: BdkElectrumClient<Client> =
            BdkElectrumClient::new(Client::new(ELECTRUM_SERVER)?);

        let tx = psbt.extract_tx()?;
        client.transaction_broadcast(&tx)?;

        Ok(())
    }

    pub fn set_note(&mut self, tx_id: String, note: String) -> Option<bool> {
        self.wallet
            .lock()
            .unwrap()
            .get_tx(Txid::from_str(&tx_id).unwrap())
            .map(|tx| tx.tx_node.tx.compute_txid())
            .map(|tx| {
                self.meta_storage.set_note(tx.to_string(), note);
                true
            })
    }

    pub fn set_tag(&mut self, output: &Output, tag: String) -> Option<bool> {
        let out_point = OutPoint::new(Txid::from_str(&output.tx_id).unwrap(), output.vout);
        self.wallet.lock().unwrap().get_utxo(out_point).map(|_| {
            self.meta_storage.set_tag(output.get_id().as_str(), tag);
            true
        })
    }

    pub fn set_do_not_spend(&mut self, output: &Output, state: bool) -> Option<bool> {
        let out_point = OutPoint::new(Txid::from_str(&output.tx_id).unwrap(), output.vout);
        self.wallet.lock().unwrap().get_utxo(out_point).map(|_| {
            self.meta_storage
                .set_do_not_spend(output.get_id().as_str(), state);
            true
        })
    }
}

use std::str::FromStr;
use anyhow::{Ok, Result};

use bdk_wallet::bitcoin::{Address, Amount, Network, Psbt, ScriptBuf, Transaction, TxIn, TxOut};
use bdk_wallet::rusqlite::{Connection, Error};
use bdk_wallet::{AddressInfo, PersistedWallet, SignOptions};
use bdk_wallet::{KeychainKind, WalletTx};
use bdk_wallet::{Update, Wallet};
use flutter_rust_bridge::frb;
use std::sync::{Arc, Mutex};

#[cfg(feature = "electrum")]
use {bdk_electrum::bdk_core::bitcoin::absolute, bdk_electrum::bdk_core::bitcoin::block::Version,
 bdk_electrum::bdk_core::{BlockId},
 bdk_electrum::bdk_core::spk_client::FullScanResponse,
 bdk_electrum::electrum_client::Client,
 bdk_electrum::BdkElectrumClient};

use bdk_wallet::chain::spk_client::FullScanRequest;
use bdk_wallet::miniscript::miniscript::types::Input::Any;

const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;

const EXTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAjWytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/0/*)#g9xn7wf9";
const INTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAjWytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/1/*)#e3rjrmea";

// TODO: make this unique to the descriptor
const DB_PATH: &str = "test_wallet.sqlite3";

const ELECTRUM_SERVER: &str = "ssl://mempool.space:60602";

pub struct NgWallet {
    pub wallet: Arc<Mutex<PersistedWallet<Connection>>>,
    db_path: Option<String>,
    connection: Arc<Mutex<Connection>>,
}

#[derive(Debug)]
pub struct NgTransaction {
    pub output: Vec<TxOut>,
}

impl NgWallet {
    pub fn new(db_path: Option<String>) -> Result<NgWallet> {
        let mut conn = match db_path.clone() {
            None => {
                Connection::open_in_memory()
            }
            Some(path) => {
                Connection::open(path)
            }
        }?;
        let wallet: PersistedWallet<Connection> =
            Wallet::create(EXTERNAL_DESCRIPTOR, INTERNAL_DESCRIPTOR)
                .network(Network::Signet)
                .create_wallet(&mut conn)?;

        Ok(Self {
            wallet: Arc::new(Mutex::new(wallet)),
            db_path,
            connection: Arc::new(Mutex::new(conn)),
        })
    }


    pub fn new_from_descriptor(db_path: Option<String>,descriptor: String) -> Result<NgWallet> {
        let mut conn = match db_path.clone() {
            None => {
                Connection::open_in_memory()
            }
            Some(path) => {
                Connection::open(path)
            }
        }?;
        let wallet: PersistedWallet<Connection> =
            Wallet::create_single(descriptor)
                .network(Network::Signet)
                .create_wallet(&mut conn)?;

        Ok(Self {
            wallet: Arc::new(Mutex::new(wallet)),
            db_path,
            connection: Arc::new(Mutex::new(conn)),
        })
    }

    
    
    pub fn persist(&mut self) -> Result<bool> {
        self.wallet.lock().unwrap().persist(&mut self.connection.lock().unwrap())
            .map_err(|e| anyhow::anyhow!(e)
            )
    }

    pub fn load(db_path: &str) -> Result<NgWallet> {
        let mut conn = Connection::open(db_path)?;
        let wallet_opt = Wallet::load().load_wallet(&mut conn)?;
        match wallet_opt {
            Some(wallet) => {
                println!("Loaded existing wallet database.");
                Ok(Self {
                    wallet: Arc::new(Mutex::new(wallet)),
                    db_path: Some(db_path.to_owned()),
                    connection: Arc::new(Mutex::new(conn)),
                })
            }
            None => {
                Err(anyhow::anyhow!("Failed to load wallet database ."))
            }
        }
    }

    pub fn next_address(&mut self) -> Result<AddressInfo> {
        let address: AddressInfo = self.wallet.lock().unwrap().reveal_next_address(KeychainKind::External);
        self.persist()?;
        Ok(address)
    }

    pub fn transactions(&self) -> Result<Vec<NgTransaction>> {
        let wallet = self.wallet.lock().unwrap();
        let mut transactions: Vec<NgTransaction> = vec![];

        for tx in wallet.transactions() {
            transactions.push(NgTransaction {
                output: tx.tx_node.output.clone(),
            });
        }

        Ok(transactions)
    }

    pub fn scan_request(&self) -> FullScanRequest<KeychainKind> {
        self.wallet.lock().unwrap().start_full_scan().build()
    }

    #[cfg(feature = "electrum")]
    pub fn scan(request: FullScanRequest<KeychainKind>) -> Result<FullScanResponse<KeychainKind>> {
        let client: BdkElectrumClient<Client> =
            BdkElectrumClient::new(Client::new(ELECTRUM_SERVER)?);
        let update = client.full_scan(request, STOP_GAP, BATCH_SIZE, true)?;

        Ok(update)
    }

    pub fn apply(&mut self, update: Update) -> Result<()> {
        self.wallet
            .lock().unwrap().apply_update(update)
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub fn balance(&self) -> Result<bdk_wallet::Balance> {
        Ok(self.wallet.lock().unwrap().balance())
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
        self.wallet.lock().unwrap().sign(&mut psbt, SignOptions::default())?;
        Ok(psbt)
    }

    #[cfg(feature = "electrum")]
    pub fn broadcast(&mut self, psbt: Psbt) -> Result<()> {
        let client: BdkElectrumClient<Client> =
            BdkElectrumClient::new(Client::new(ELECTRUM_SERVER)?);

        let tx = psbt.extract_tx()?;
        client.transaction_broadcast(&tx)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    #[cfg(feature = "electrum")]
    fn it_works() {
        let mut wallet = NgWallet::new(Some(DB_PATH.to_string())).unwrap_or(NgWallet::load(DB_PATH).unwrap());

        let address: AddressInfo = wallet.next_address().unwrap();
        println!(
            "Generated address {} at index {}",
            address.address, address.index
        );

        let request = wallet.scan_request();
        let update = NgWallet::scan(request).unwrap();
        wallet.apply(Update::from(update)).unwrap();

        let balance = wallet.balance().unwrap();
        println!("Wallet balance: {} sat", balance.total().to_sat());

        let transactions = wallet.transactions();

        for tx in transactions {
            println!("Transaction: {:?}", tx);
        }

        //println!("Wallet balance: {:?} sat", wallet.transactions());
    }

    #[test]
    fn check_watch_only() {
        let mut wallet = NgWallet::new_from_descriptor(Some(DB_PATH.to_string()),EXTERNAL_DESCRIPTOR.to_string()).unwrap_or(NgWallet::load(DB_PATH).unwrap());

        let address: AddressInfo = wallet.next_address().unwrap();
        println!(
            "Generated address {} at index {}",
            address.address, address.index
        );

        let request = wallet.scan_request();
        let update = NgWallet::scan(request).unwrap();
        wallet.apply(Update::from(update)).unwrap();

        let balance = wallet.balance().unwrap().total().to_sat();
        println!("Wallet balance: {} sat", balance.total().to_sat());

        let transactions = wallet.transactions();

        for tx in transactions {
            println!("Transaction: {:?}", tx);
        }

        //println!("Wallet balance: {:?} sat", wallet.transactions());
    }
    
}

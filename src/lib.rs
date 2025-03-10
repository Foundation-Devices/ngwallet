use std::str::FromStr;
use anyhow::Result;
use bdk_electrum::bdk_core::spk_client::FullScanResponse;
use bdk_electrum::electrum_client::Client;
use bdk_electrum::BdkElectrumClient;
use bdk_wallet::bitcoin::{Address, Amount, Network, Psbt, ScriptBuf};
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{AddressInfo, PersistedWallet, SignOptions};
use bdk_wallet::{KeychainKind, WalletTx};
use bdk_wallet::{Update, Wallet};
use flutter_rust_bridge::frb;

const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;

const EXTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAjWytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/0/*)#g9xn7wf9";
const INTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAjWytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/1/*)#e3rjrmea";

// TODO: make this unique to the descriptor
const DB_PATH: &str = "test_wallet.sqlite3";

const ELECTRUM_SERVER: &str = "ssl://mempool.space:60602";

#[frb(non_opaque)]
pub struct NgWallet {
    wallet: PersistedWallet<Connection>,
}

impl NgWallet {
    pub fn new() -> Result<NgWallet> {
        let mut conn = Connection::open(DB_PATH)?;
        let wallet: PersistedWallet<Connection> =
            Wallet::create(EXTERNAL_DESCRIPTOR, INTERNAL_DESCRIPTOR)
                .network(Network::Signet)
                .create_wallet(&mut conn)?;

        Ok(Self { wallet })
    }

    pub fn persist(&mut self) -> Result<bool> {
        let mut conn = Connection::open(DB_PATH)?;
        Ok(self.wallet.persist(&mut conn)?)
    }

    pub fn load() -> Result<NgWallet> {
        let mut conn = Connection::open(DB_PATH)?;
        let wallet_opt = Wallet::load().load_wallet(&mut conn)?;

        match wallet_opt {
            Some(wallet) => {
                println!("Loaded existing wallet database.");
                Ok(Self { wallet })
            }
            None => {
                println!("Creating new wallet database.");
                Err(anyhow::anyhow!("Failed to load wallet database."))
            }
        }
    }

    pub fn next_address(&mut self) -> Result<AddressInfo> {
        let address: AddressInfo = self.wallet.reveal_next_address(KeychainKind::External);
        self.persist()?;
        Ok(address)
    }

    pub fn transactions(&self) -> Vec<WalletTx> {
        let transactions: Vec<WalletTx> = self.wallet.transactions().collect();
        transactions
    }

    pub fn scan(&self) -> Result<FullScanResponse<KeychainKind>> {
        let client: BdkElectrumClient<Client> =
            BdkElectrumClient::new(Client::new(ELECTRUM_SERVER)?);

        let full_scan_request = self.wallet.start_full_scan();
        let update = client.full_scan(full_scan_request, STOP_GAP, BATCH_SIZE, true)?;

        Ok(update)
    }

    pub fn apply(&mut self, update: Update) -> Result<()> {
        self.wallet
            .apply_update(update)
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub fn balance(&self) -> bdk_wallet::Balance {
        self.wallet.balance()
    }

    pub fn create_send(&mut self, address: String, amount: u64) -> Result<Psbt> {
        let address = Address::from_str(&address)?.require_network(self.wallet.network())?;
        let script: ScriptBuf = address.into();
        let mut builder = self.wallet.build_tx();
        builder.add_recipient(script.clone(), Amount::from_sat(amount));

        let psbt = builder.finish()?;
        Ok(psbt)
    }

    pub fn sign(&self, psbt: &Psbt) -> Result<Psbt> {
        let mut psbt = psbt.to_owned();
        self.wallet.sign(&mut psbt, SignOptions::default())?;
        Ok(psbt)
    }

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
    fn it_works() {
        let mut wallet = NgWallet::new().unwrap_or(NgWallet::load().unwrap());

        let address: AddressInfo = wallet.next_address().unwrap();
        println!(
            "Generated address {} at index {}",
            address.address, address.index
        );

        let update = wallet.scan().unwrap();
        wallet.apply(Update::from(update)).unwrap();

        let balance = wallet.balance();
        println!("Wallet balance: {} sat", balance.total().to_sat());

        let transactions = wallet.transactions();

        for tx in transactions {
            println!("Transaction: {:?}", tx);
        }

        //println!("Wallet balance: {:?} sat", wallet.transactions());
    }
}

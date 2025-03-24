use crate::db::RedbMetaStorage;
use crate::ngwallet::NgWallet;
use crate::store::MetaStorage;
use crate::transaction::{BitcoinTransaction, Output};
use bdk_wallet::bitcoin::Network;

#[derive(Debug)]
pub struct NgAccount {
    pub name: String,
    pub color: String,
    pub device_serial: Option<String>,
    pub date_added: Option<String>,
    pub index: u32,
    pub wallet: NgWallet,
    meta_storage: Box<dyn MetaStorage>,
}

impl NgAccount {
    pub fn new_from_descriptor(
        name: String,
        color: String,
        device_serial: Option<String>,
        date_added: Option<String>,
        network: String,
        internal_descriptor: String,
        external_descriptor: Option<String>,
        index: u32,
        db_path: Option<String>,
    ) -> Self {
        let wallet_db = db_path.clone().map(|p| format!("{:?}/wallet.sqlite", p));
        let meta_db = db_path.map(|p| format!("{:?}/wallet.meta", p));
        let network = match network.as_str() {
            "Signet" => Network::Signet,
            "Testnet" => Network::Testnet,
            _ => Network::Bitcoin,
        };
        let wallet = NgWallet::new_from_descriptor(
            wallet_db,
            internal_descriptor,
            external_descriptor,
            network,
        )
        .unwrap();

        Self {
            name,
            color,
            device_serial,
            date_added,
            index,
            wallet,
            meta_storage: Box::new(RedbMetaStorage::new(meta_db)),
        }
    }

    pub fn get_backup(&self) -> Vec<u8> {
        vec![]
    }

    pub fn transactions(&self) -> anyhow::Result<Vec<BitcoinTransaction>> {
        self.wallet.transactions(self.meta_storage.as_ref())
    }

    pub fn unspend_outputs(&self) -> anyhow::Result<Vec<Output>> {
        self.wallet.unspend_outputs(self.meta_storage.as_ref())
    }

    pub fn set_note(&mut self, tx_id: &str, note: &str) -> anyhow::Result<bool> {
        self.wallet
            .set_note(tx_id, note, self.meta_storage.as_mut())
    }
    pub fn set_tag(&mut self, output: &Output, tag: String) -> anyhow::Result<bool> {
        self.wallet.set_tag(output, tag, self.meta_storage.as_mut())
    }
    pub fn set_do_not_spend(&mut self, output: &Output, state: bool) -> anyhow::Result<bool> {
        self.wallet
            .set_do_not_spend(output, state, self.meta_storage.as_mut())
    }
}

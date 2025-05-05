use std::fmt::Debug;
use std::iter::Sum;
use std::sync::{Arc, Mutex};

use anyhow::Error;
use bdk_electrum::bdk_core::bitcoin::{OutPoint, Txid};
use bdk_electrum::bdk_core::spk_client::FullScanRequest;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::chain::local_chain::CannotConnectError;
use bdk_wallet::{AddressInfo, Balance, KeychainKind, Update, WalletPersister};
use redb::StorageBackend;

use crate::config::{AddressType, NgAccountConfig};
use crate::db::RedbMetaStorage;
use crate::ngwallet::NgWallet;
use crate::store::MetaStorage;
use crate::transaction::{BitcoinTransaction, Output};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct NgAccount<P: WalletPersister> {
    pub config: NgAccountConfig,
    pub wallets: Vec<NgWallet<P>>,
    meta_storage: Arc<Mutex<dyn MetaStorage>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Descriptor {
    pub internal: String,
    pub external: Option<String>,
}

impl<P: WalletPersister> NgAccount<P> {
    #![allow(clippy::too_many_arguments)]
    pub fn new_from_descriptor(
        name: String,
        color: String,
        device_serial: Option<String>,
        date_added: Option<String>,
        network: Network,
        address_type: AddressType,
        descriptors: Vec<Descriptor>,
        index: u32,
        db_path: Option<String>,
        bdk_persister: Arc<Mutex<P>>,
        meta_storage_backend: Option<impl StorageBackend>,
        id: String,
        date_synced: Option<String>,
    ) -> Self {
        let meta = Arc::new(Mutex::new(RedbMetaStorage::new(
            db_path.clone(),
            meta_storage_backend,
        )));

        let mut wallets = vec![];

        for descriptor in descriptors.clone() {
            let wallet = NgWallet::new_from_descriptor(
                descriptor.internal.clone(),
                descriptor.external.clone(),
                network,
                meta.clone(),
                bdk_persister.clone(),
            )
            .unwrap();

            wallets.push(wallet);
        }

        let account_config = NgAccountConfig {
            name,
            color,
            device_serial,
            date_added,
            index,
            descriptors,
            address_type,
            network,
            id,
            date_synced,
            wallet_path: db_path,
        };
        meta.lock()
            .unwrap()
            .set_config(account_config.serialize().as_str())
            .unwrap();
        Self {
            config: account_config,
            wallets,
            meta_storage: meta,
        }
    }

    pub fn open_account(
        db_path: String,
        bdk_persister: Arc<Mutex<P>>,
        meta_storage_backend: Option<impl StorageBackend>,
    ) -> Self
    where
        <P as WalletPersister>::Error: Debug,
    {
        let meta_storage = Arc::new(Mutex::new(RedbMetaStorage::new(
            Some(db_path.clone()),
            meta_storage_backend,
        )));

        let config = meta_storage.lock().unwrap().get_config().unwrap().unwrap();

        let mut wallets = vec![];
        let descriptors = config.clone().descriptors;

        for descriptor in descriptors {
            let wallet = NgWallet::load(
                descriptor.internal,
                descriptor.external,
                meta_storage.clone(),
                bdk_persister.clone(),
            )
            .unwrap();

            wallets.push(wallet);
        }

        Self {
            config,
            wallets,
            meta_storage,
        }
    }

    pub fn rename(&mut self, name: &str) -> Result<(), Error> {
        self.config.name = name.to_string();
        self.persist()
    }

    pub fn persist(&mut self) -> Result<(), Error> {
        for wallet in &mut self.wallets {
            wallet.persist().map_err(|e| anyhow::anyhow!(e))?;
        }

        self.meta_storage
            .lock()
            .unwrap()
            .set_config(self.config.serialize().as_str())
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub fn get_backup(&self) -> Vec<u8> {
        vec![]
    }

    pub fn next_address(&mut self) -> anyhow::Result<Vec<AddressInfo>> {
        let mut addresses = vec![];
        for wallet in self.wallets.iter_mut() {
            let address: AddressInfo = wallet
                .wallet
                .lock()
                .unwrap()
                .next_unused_address(KeychainKind::External);

            addresses.push(address);
        }

        self.persist()?;

        Ok(addresses)
    }

    #[cfg(feature = "envoy")]
    pub fn full_scan_request(&self) -> Vec<FullScanRequest<KeychainKind>> {
        let mut requests = vec![];

        for wallet in self.wallets.iter() {
            let request = wallet.wallet.lock().unwrap().start_full_scan().build();
            requests.push(request);
        }

        requests
    }

    pub fn apply(&mut self, update: Update) -> anyhow::Result<()> {
        for wallet in &self.wallets {
            match wallet.wallet.lock().unwrap().apply_update(update.clone()) {
                Ok(_) => {
                    println!("updated the wallet");
                    return Ok(());
                }
                Err(e) => {
                    println!("{:?}", e);
                }
            }
        }

        Ok(())
    }

    pub fn balance(&self) -> anyhow::Result<bdk_wallet::Balance> {
        let mut balance = Balance::default();

        for wallet in self.wallets.iter() {
            let wallet_balance = wallet.wallet.lock().unwrap().balance();

            balance.confirmed += wallet_balance.confirmed;
            balance.immature += wallet_balance.immature;
            balance.trusted_pending += wallet_balance.trusted_pending;
            balance.untrusted_pending += wallet_balance.untrusted_pending;
        }

        Ok(balance)
    }

    pub fn transactions(&self) -> anyhow::Result<Vec<BitcoinTransaction>> {
        let mut transactions = vec![];
        for wallet in self.wallets.iter() {
            transactions.extend(wallet.transactions()?);
        }

        Ok(transactions)
    }

    pub fn utxos(&self) -> anyhow::Result<Vec<Output>> {
        let mut utxos = vec![];
        for wallet in self.wallets.iter() {
            utxos.extend(wallet.utxos()?);
        }

        Ok(utxos)
    }

    pub fn set_note(&mut self, tx_id: &str, note: &str) -> anyhow::Result<bool> {
        self.meta_storage
            .lock()
            .unwrap()
            .set_note(&tx_id.to_string(), note)
            .map_err(|e| anyhow::anyhow!("Could not set note: {:?}", e))?;
        Ok(true)
    }

    pub fn set_tag(&mut self, output: &Output, tag: &str) -> anyhow::Result<bool> {
        self.meta_storage
            .lock()
            .unwrap()
            .set_tag(output.get_id().as_str(), tag)
            .map_err(|_| anyhow::anyhow!("Could not set tag "))
            .unwrap();
        self.meta_storage
            .lock()
            .unwrap()
            .add_tag(tag.to_string().as_str())
            .map_err(|_| anyhow::anyhow!("Could not set tag "))
            .unwrap();
        Ok(true)
    }

    pub fn set_do_not_spend(&mut self, output: &Output, state: bool) -> anyhow::Result<()> {
        self.meta_storage
            .lock()
            .unwrap()
            .set_do_not_spend(output.get_id().as_str(), state)
    }
}

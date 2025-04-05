use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use anyhow::Error;
use bdk_wallet::WalletPersister;
use bdk_wallet::bitcoin::Network;
use redb::StorageBackend;
use serde::Serialize;

use crate::config::{AddressType, NgAccountConfig};
use crate::db::RedbMetaStorage;
use crate::ngwallet::NgWallet;
use crate::store::MetaStorage;

#[derive(Debug)]
pub struct NgAccount<P: WalletPersister> {
    pub config: NgAccountConfig,
    pub wallet: NgWallet<P>,
    meta_storage: Arc<Mutex<dyn MetaStorage>>,
}

impl<P: WalletPersister> NgAccount<P> {
    pub fn new_from_descriptor(
        name: String,
        color: String,
        device_serial: Option<String>,
        date_added: Option<String>,
        network: Network,
        address_type: AddressType,
        internal_descriptor: String,
        external_descriptor: Option<String>,
        index: u32,
        db_path: Option<String>,
        bdk_persister: Arc<Mutex<P>>,
        meta_storage_backend: Option<impl StorageBackend>,
        id:String,
        date_synced: Option<String>,
    ) -> Self {
        let meta = Arc::new(Mutex::new(RedbMetaStorage::new(db_path.clone(), meta_storage_backend)));

        let wallet = NgWallet::new_from_descriptor(
            internal_descriptor.clone(),
            external_descriptor.clone(),
            network,
            meta.clone(),
            bdk_persister.clone(),
        )
        .unwrap();

        let account_config = NgAccountConfig::new(
            name,
            color,
            device_serial,
            date_added,
            index,
            internal_descriptor,
            external_descriptor,
            address_type,
            network,
            id,
            date_synced,
            db_path
        );
        meta.lock()
            .unwrap()
            .set_config(account_config.serialize().as_str())
            .unwrap();
        Self {
            config: account_config,
            wallet,
            meta_storage: meta,
        }
    }

    pub fn open_wallet(
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

        let config = meta_storage.lock().unwrap().get_config().unwrap().unwrap() ;

        let wallet = NgWallet::load(meta_storage.clone(), bdk_persister.clone()).unwrap();
        Self {
            config,
            wallet,
            meta_storage,
        }
    }

    pub fn rename(&mut self,name: &str ) -> Result<(), Error> {
        self.config.name  = name.to_string();
        self.persist()
    }

    pub fn persist(&mut self) -> Result<(), Error> {
        self.wallet.persist().map_err(|e| anyhow::anyhow!(e))?;
        self.meta_storage
            .lock()
            .unwrap()
            .set_config(self.config.serialize().as_str())
            .map_err(|e| anyhow::anyhow!(e))
    }
    pub fn get_backup(&self) -> Vec<u8> {
        vec![]
    }
}

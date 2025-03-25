use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use anyhow::Error;
use bdk_wallet::bitcoin::{Network};
use bdk_wallet::WalletPersister;
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
    ) -> Self {

        // #[cfg(feature = "envoy")]
        let meta = Arc::new(Mutex::new(RedbMetaStorage::new(db_path.clone())));
        //
        // #[cfg(not(feature = "envoy"))]
        //     let meta = Arc::new(Mutex::new(InMemoryMetaStorage::new()));

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
        );
        meta.lock().unwrap().set_config(
            account_config.serialize().as_str(),
        ).unwrap();
        Self {
            config: account_config,
            wallet,
            meta_storage: meta,
        }
    }

    pub fn open_wallet(
        db_path: String,
        bdk_persister: Arc<Mutex<P>>,
    ) -> Self where <P as WalletPersister>::Error: Debug {
        let meta_storage = Arc::new(Mutex::new(RedbMetaStorage::new(Some(db_path.clone()))));

        // #[cfg(not(feature = "envoy"))]
        //     let meta = InMemoryMetaStorage::new();

        let config = meta_storage.lock().unwrap().get_config().unwrap().unwrap();

        let wallet = NgWallet::load(
            meta_storage.clone(),
            bdk_persister.clone(),
        )
            .unwrap();
        Self {
            config,
            wallet,
            meta_storage,
        }
    }

    pub fn persist(&mut self) -> Result<bool, Error> {
        self.wallet
            .persist()
            .map_err(|e| anyhow::anyhow!(e))
    }
    pub fn get_backup(&self) -> Vec<u8> {
        vec![]
    }
}

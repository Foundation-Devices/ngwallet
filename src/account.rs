use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use crate::config::{AddressType, NgAccountConfig};
use crate::db::RedbMetaStorage;
use crate::ngwallet::NgWallet;
use crate::store::{InMemoryMetaStorage, MetaStorage};
use crate::transaction::{BitcoinTransaction, Output};
use crate::utils::get_address_type;
use anyhow::{Error, anyhow};
use bdk_wallet::bitcoin::Transaction;
use bdk_wallet::chain::spk_client::FullScanRequest;
use bdk_wallet::chain::spk_client::SyncRequest;
use bdk_wallet::{AddressInfo, Balance, KeychainKind, Update, WalletPersister};
use log::info;
use redb::StorageBackend;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct NgAccount<P: WalletPersister> {
    pub config: NgAccountConfig,
    pub wallets: Vec<NgWallet<P>>,
    meta_storage: Arc<Mutex<dyn MetaStorage>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Descriptor<P: WalletPersister> {
    pub internal: String,
    pub external: Option<String>,
    pub bdk_persister: Arc<Mutex<P>>,
}

#[derive(Serialize, Deserialize)]
pub struct RemoteUpdate {
    pub metadata: Option<NgAccountConfig>,
    pub wallet_update: Vec<(AddressType, Update)>,
}

pub fn get_persister_file_name(internal: &str, external: Option<&str>) -> String {
    fn get_last_eight_chars(s: &str) -> Option<String> {
        if s.chars().count() >= 6 {
            Some(s.chars().skip(s.chars().count() - 6).collect())
        } else {
            None
        }
    }
    let internal_id = get_last_eight_chars(internal).unwrap_or("".to_string());
    let external_id = get_last_eight_chars(external.unwrap_or("")).unwrap_or("".to_string());
    format!("{}_{}.sqlite", internal_id, external_id)
}

impl<P: WalletPersister> NgAccount<P> {
    pub(crate) fn new_from_descriptors(
        ng_account_config: NgAccountConfig,
        meta_storage_backend: Option<impl StorageBackend>,
        open_in_memory: bool,
        descriptors: Vec<Descriptor<P>>,
    ) -> Self {
        let account_config = ng_account_config.clone();
        let NgAccountConfig {
            wallet_path,
            preferred_address_type,
            network,
            ..
        } = ng_account_config;

        let meta: Arc<Mutex<dyn MetaStorage>> = if open_in_memory {
            Arc::new(Mutex::new(InMemoryMetaStorage::new()))
        } else {
            Arc::new(Mutex::new(RedbMetaStorage::new(
                wallet_path.clone(),
                meta_storage_backend,
            )))
        };

        let mut wallets: Vec<NgWallet<P>> = vec![];

        for descriptor in descriptors {
            let wallet = NgWallet::new_from_descriptor(
                descriptor.internal.clone(),
                descriptor.external.clone(),
                network,
                meta.clone(),
                descriptor.bdk_persister,
            )
            .unwrap();
            wallets.push(wallet);
        }

        let coordinator_wallet = wallets
            .iter()
            .find(|w| w.address_type == preferred_address_type);

        if coordinator_wallet.is_none() {
            panic!("No wallet found with the preferred address type");
        }

        meta.lock()
            .unwrap()
            .set_config(account_config.serialize().as_str())
            .unwrap();
        {
            meta.lock().unwrap().persist().unwrap();
        }
        Self {
            config: account_config,
            wallets,
            meta_storage: meta,
        }
    }

    pub fn open_account(
        db_path: String,
        descriptors: Vec<Descriptor<P>>,
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

        let mut wallets: Vec<NgWallet<P>> = vec![];

        for descriptor in descriptors {
            let wallet = NgWallet::load(
                descriptor.internal,
                descriptor.external,
                meta_storage.clone(),
                descriptor.bdk_persister.clone(),
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
            wallet.persist()?;
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

    pub fn next_address(&mut self) -> anyhow::Result<Vec<(AddressInfo, AddressType)>> {
        let mut addresses = vec![];
        for wallet in self.wallets.iter_mut() {
            let address: AddressInfo = wallet
                .bdk_wallet
                .lock()
                .unwrap()
                .next_unused_address(KeychainKind::External);

            addresses.push((address, wallet.address_type));
        }
        self.persist()?;
        Ok(addresses)
    }

    pub fn balance(&self) -> anyhow::Result<Balance> {
        let mut balance = Balance::default();

        for wallet in self.wallets.iter() {
            let wallet_balance = wallet.bdk_wallet.lock().unwrap().balance();
            balance.confirmed += wallet_balance.confirmed;
            balance.immature += wallet_balance.immature;
            balance.trusted_pending += wallet_balance.trusted_pending;
            balance.untrusted_pending += wallet_balance.untrusted_pending;
        }

        Ok(balance)
    }

    pub fn wallet_balances(&self) -> anyhow::Result<Vec<(AddressType, Balance)>> {
        let mut balances: Vec<(AddressType, Balance)> = vec![];
        for wallet in self.wallets.iter() {
            let wallet = wallet.bdk_wallet.lock().unwrap();
            let balance = wallet.balance();
            balances.push((
                get_address_type(&wallet.public_descriptor(KeychainKind::External).to_string()),
                balance,
            ));
        }
        Ok(balances)
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
            .set_note(tx_id, note)
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

    #[cfg(feature = "envoy")]
    pub fn full_scan_request(
        &self,
        address_type: AddressType,
    ) -> anyhow::Result<(AddressType, FullScanRequest<KeychainKind>), Error> {
        match self
            .wallets
            .iter()
            .find(|ng_wallet| ng_wallet.address_type == address_type)
        {
            None => Err(anyhow!("given address type doesnt exist in account")),
            Some(ng_wallet) => Ok((ng_wallet.address_type, ng_wallet.full_scan_request())),
        }
    }

    pub fn apply(&self, update: (AddressType, Update)) -> anyhow::Result<()> {
        match self
            .wallets
            .iter()
            .find(|ng_wallet| ng_wallet.address_type == update.0)
        {
            None => Err(anyhow!("given address type doesnt exist in account")),
            Some(ng_wallet) => {
                ng_wallet.apply_update(update.1)?;
                Ok(())
            }
        }
    }

    #[cfg(feature = "envoy")]
    pub fn sync_request(
        &self,
        address_type: AddressType,
    ) -> anyhow::Result<(AddressType, SyncRequest<(KeychainKind, u32)>)> {
        match self
            .wallets
            .iter()
            .find(|ng_wallet| ng_wallet.address_type == address_type)
        {
            None => Err(anyhow!("given address type doesnt exist in account")),
            Some(ng_wallet) => Ok((ng_wallet.address_type, ng_wallet.sync_request())),
        }
    }

    pub fn get_coordinator_wallet(&self) -> &NgWallet<P> {
        let address_type = self.config.preferred_address_type;
        let mut coordinator: &NgWallet<P> = self.wallets.first().unwrap();
        for wallet in &self.wallets {
            if wallet.address_type == address_type {
                coordinator = wallet;
            }
        }
        coordinator
    }

    pub fn non_coordinator_wallets(&self) -> Vec<&NgWallet<P>> {
        let address_type = self.config.preferred_address_type;
        self.wallets
            .iter()
            .filter(|wallet| wallet.address_type != address_type)
            .collect()
    }

    pub fn get_derivation_index(&self) -> Vec<(AddressType, KeychainKind, u32)> {
        let mut derivation_index = vec![];
        for wallet in self.wallets.iter() {
            let bdk_wallet = wallet.bdk_wallet.lock().unwrap();
            let external_index = bdk_wallet
                .derivation_index(KeychainKind::External)
                .unwrap_or(0);
            let internal_index = bdk_wallet
                .derivation_index(KeychainKind::Internal)
                .unwrap_or(0);
            derivation_index.push((wallet.address_type, KeychainKind::External, external_index));
            derivation_index.push((wallet.address_type, KeychainKind::Internal, internal_index));
        }
        derivation_index
    }

    pub fn sign(&self, psbt: &str) -> anyhow::Result<String> {
        let mut psbt = psbt.to_string();
        for wallet in self.wallets.iter() {
            psbt = wallet.sign(&psbt)?;
        }

        Ok(psbt)
    }

    pub fn is_hot(&self) -> bool {
        for wallet in self.wallets.iter() {
            if wallet.is_hot() {
                return true;
            }
        }
        false
    }

    pub fn list_tags(&self) -> anyhow::Result<Vec<String>> {
        self.meta_storage.lock().unwrap().list_tags()
    }

    pub fn mark_utxo_as_used(&self, transaction: Transaction) {
        for wallet in self.wallets.iter() {
            let mut wallet_mut = wallet.bdk_wallet.lock().unwrap();
            for txout in &transaction.output {
                if let Some((keychain, index)) =
                    wallet_mut.derivation_of_spk(txout.script_pubkey.clone())
                {
                    wallet_mut.unmark_used(keychain, index);
                }
            }
        }
    }
    /// Sets a note for a transaction without checking if the transaction existence.
    pub fn set_note_unchecked(&mut self, tx_id: &str, note: &str) -> anyhow::Result<bool> {
        self.meta_storage
            .lock()
            .unwrap()
            .set_note(tx_id, note)
            .map_err(|e| anyhow::anyhow!("Could not set note: {:?}", e))?;
        Ok(true)
    }

    pub fn get_tag(&self, output_id: &str) -> Option<String> {
        self.meta_storage
            .lock()
            .unwrap()
            .get_tag(output_id)
            .map_err(|_| anyhow::anyhow!("Could not set tag "))
            .unwrap()
    }

    pub fn remove_tag(&mut self, target_tag: &str, rename_to: Option<&str>) -> anyhow::Result<()> {
        self.meta_storage
            .lock()
            .unwrap()
            .remove_tag(target_tag)
            .map_err(|e| anyhow::anyhow!("Error {}", e))
            .unwrap();
        self.utxos()
            .map_err(|e| anyhow::anyhow!("Error {}", e))
            .unwrap()
            .iter()
            .for_each(|output: &Output| match output.clone().tag {
                None => {}
                Some(existing_tag) => {
                    let new_tag = rename_to.unwrap_or("");
                    if existing_tag.eq(target_tag) {
                        self.set_tag(output, new_tag)
                            .map_err(|e| anyhow::anyhow!("Error {}", e))
                            .unwrap();
                    }
                }
            });

        Ok(())
    }

    pub fn read_config(
        db_path: String,
        meta_storage_backend: Option<impl StorageBackend>,
    ) -> Option<NgAccountConfig> {
        let meta_storage = RedbMetaStorage::new(Some(db_path.clone()), meta_storage_backend);
        match meta_storage.get_config() {
            Ok(value) => value.clone(),
            Err(e) => {
                info!("Error reading config {:?}", e);
                None
            }
        }
    }

    pub fn serialize_updates(
        metadata: Option<NgAccountConfig>,
        wallet_updates: Vec<(AddressType, Update)>,
    ) -> anyhow::Result<Vec<u8>> {
        let update = RemoteUpdate {
            metadata,
            wallet_update: wallet_updates,
        };

        minicbor_serde::to_vec(&update).map_err(|_| anyhow::anyhow!("Could not serialize updates"))
    }

    pub fn update(&mut self, payload: Vec<u8>) -> anyhow::Result<()> {
        let update: RemoteUpdate = minicbor_serde::from_slice(&payload)?;

        for wallet_update in update.wallet_update {
            self.apply(wallet_update)?
        }

        match update.metadata {
            None => {}
            Some(m) => {
                self.config = m;
            }
        }

        self.persist()?;
        Ok(())
    }
}

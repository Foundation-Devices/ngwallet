use std::fmt::Debug;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use crate::config::{AddressType, NgAccountBackup, NgAccountConfig, NgDescriptor};
use crate::db::RedbMetaStorage;
use crate::ngwallet::NgWallet;
use crate::store::MetaStorage;
use crate::transaction::{BitcoinTransaction, Output};
use crate::utils::get_address_type;
use anyhow::{anyhow, Context, Error};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use bdk_wallet::bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bdk_wallet::bitcoin::{Address, AddressType as BdkAddressType, Psbt, Transaction};
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
    meta_storage: Arc<dyn MetaStorage>,
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
        meta: Arc<dyn MetaStorage>,
        descriptors: Vec<Descriptor<P>>,
    ) -> anyhow::Result<Self> {
        let account_config = ng_account_config.clone();
        let NgAccountConfig {
            preferred_address_type,
            network,
            ..
        } = ng_account_config;

        let mut wallets: Vec<NgWallet<P>> = vec![];

        for descriptor in descriptors {
            let wallet = NgWallet::new_from_descriptor(
                descriptor.internal.clone(),
                descriptor.external.clone(),
                network,
                meta.clone(),
                descriptor.bdk_persister,
            )
            .with_context(|| "Failed to create wallet")?;
            wallets.push(wallet);
        }

        let coordinator_wallet = wallets
            .iter()
            .find(|w| w.address_type == preferred_address_type);

        if coordinator_wallet.is_none() {
            anyhow::bail!("No wallet found with the preferred address type");
        }

        meta.set_config(account_config.serialize().as_str())
            .with_context(|| "Failed to set account config")?;
        meta.persist()
            .with_context(|| "Failed to persist account config")?;

        Ok(Self {
            config: account_config,
            wallets,
            meta_storage: meta,
        })
    }

    pub fn open_account_from_file(
        descriptors: Vec<Descriptor<P>>,
        db_path: Option<String>,
    ) -> anyhow::Result<Self>
    where
        <P as WalletPersister>::Error: Debug,
    {
        let meta_storage = RedbMetaStorage::from_file(db_path)?;
        Self::open_account_inner(descriptors, Arc::new(meta_storage))
    }

    pub fn open_account_from_backend(
        descriptors: Vec<Descriptor<P>>,
        backend: impl StorageBackend,
    ) -> anyhow::Result<Self>
    where
        <P as WalletPersister>::Error: Debug,
    {
        let meta_storage = RedbMetaStorage::from_backend(backend)?;
        Self::open_account_inner(descriptors, Arc::new(meta_storage))
    }

    pub fn rename(&mut self, name: &str) -> Result<(), Error> {
        self.config.name = name.to_string();
        self.persist()
    }

    pub fn set_preferred_address_type(&mut self, address_type: AddressType) -> Result<(), Error> {
        self.config.preferred_address_type = address_type;
        self.persist()
    }

    pub fn persist(&mut self) -> Result<(), Error> {
        for wallet in &mut self.wallets {
            wallet.persist()?;
        }

        self.meta_storage
            .set_config(self.config.serialize().as_str())
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub fn add_new_descriptor(&mut self, descriptor: &Descriptor<P>) -> Result<(), Error> {
        let address_type = get_address_type(&descriptor.internal);
        for wallet_descriptor in &mut self.config.descriptors {
            if wallet_descriptor.internal == descriptor.internal {
                return Err(anyhow::anyhow!("Descriptor already exists"));
            }
            if address_type == wallet_descriptor.address_type {
                return Err(anyhow::anyhow!("Address type already exists"));
            }
        }
        self.config.descriptors.push(NgDescriptor {
            internal: descriptor.internal.clone(),
            external: descriptor.external.clone(),
            address_type,
        });
        let wallet = NgWallet::new_from_descriptor(
            descriptor.internal.clone(),
            descriptor.external.clone(),
            self.config.network,
            self.meta_storage.clone(),
            descriptor.bdk_persister.clone(),
        )?;
        self.wallets.push(wallet);
        self.persist()?;
        Ok(())
    }

    pub fn get_backup_json(&self) -> Result<String, Error> {
        let config = {
            let mut config = self.config.clone();
            if self.is_hot() {
                config.descriptors = vec![];
            }
            let last_used_index = self.get_derivation_index();
            NgAccountBackup {
                ng_account_config: config,
                last_used_index,
            }
        };
        match serde_json::to_string(&config) {
            Ok(config) => Ok(config),
            Err(_) => Err(anyhow::anyhow!("Error serializing config")),
        }
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
            .set_note(tx_id, note)
            .with_context(|| "Could not set note")?;
        Ok(true)
    }

    pub fn set_tag(&mut self, output: &Output, tag: &str) -> anyhow::Result<bool> {
        self.meta_storage
            .set_tag(output.get_id().as_str(), tag)
            .with_context(|| "Could not set tag")?;
        self.meta_storage
            .add_tag(tag.to_string().as_str())
            .with_context(|| "Could not add tag")?;
        Ok(true)
    }

    pub fn set_do_not_spend(&mut self, output: &Output, state: bool) -> anyhow::Result<()> {
        self.meta_storage
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

    pub fn sign(&self, psbt: &str, options: bdk_wallet::SignOptions) -> anyhow::Result<String> {
        let tx = BASE64_STANDARD
            .decode(psbt)
            .with_context(|| "Failed to decode PSBT")?;

        let mut psbt = Psbt::deserialize(&tx).with_context(|| "Failed to deserialize PSBT")?;

        for wallet in self.wallets.iter() {
            wallet.sign_psbt(&mut psbt, options.clone())?;
        }

        let encoded_psbt = BASE64_STANDARD.encode(psbt.serialize());
        Ok(encoded_psbt)
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
        self.meta_storage.list_tags()
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
            .set_note(tx_id, note)
            .with_context(|| "Could not set note")?;
        Ok(true)
    }

    pub fn get_tag(&self, output_id: &str) -> anyhow::Result<Option<String>> {
        self.meta_storage
            .get_tag(output_id)
            .with_context(|| "Could not get tag ")
    }

    pub fn remove_tag(&mut self, target_tag: &str, rename_to: Option<&str>) -> anyhow::Result<()> {
        self.meta_storage.remove_tag(target_tag)?;
        let utxos = self.utxos()?;
        for output in utxos {
            match &output.tag {
                None => {}
                Some(existing_tag) => {
                    let new_tag = rename_to.unwrap_or("");
                    if existing_tag.eq(target_tag) {
                        self.set_tag(&output, new_tag)?;
                    }
                }
            }
        }

        Ok(())
    }

    pub fn read_config_from_file(db_path: Option<String>) -> Option<NgAccountConfig> {
        let meta_storage = RedbMetaStorage::from_file(db_path).ok()?;
        Self::read_config_inner(meta_storage)
    }

    pub fn read_config_from_backend(backend: impl StorageBackend) -> Option<NgAccountConfig> {
        let meta_storage = RedbMetaStorage::from_backend(backend).ok()?;
        Self::read_config_inner(meta_storage)
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

    pub fn get_address_script_type(&self, address: &str) -> anyhow::Result<AddressType> {
        let address: Address<NetworkUnchecked> =
            Address::from_str(address).map_err(|_| anyhow::anyhow!("Could not parse address"))?;
        let address: Address<NetworkChecked> =
            address.require_network(self.config.network).map_err(|_| {
                anyhow::anyhow!(
                    "Address is invalid for current network: {}",
                    self.config.network
                )
            })?;
        match address.address_type() {
            Some(t) => {
                // TODO: could we switch to just using BDK's address type?
                let res = match t {
                    BdkAddressType::P2pkh => AddressType::P2pkh,
                    BdkAddressType::P2sh => AddressType::P2sh,
                    BdkAddressType::P2wpkh => AddressType::P2wpkh,
                    BdkAddressType::P2wsh => AddressType::P2wsh,
                    BdkAddressType::P2tr => AddressType::P2tr,
                    _ => return Err(anyhow::anyhow!("New unsupported address type")),
                };
                Ok(res)
            }
            None => Err(anyhow::anyhow!("Unknown address type")),
        }
    }

    pub fn verify_address(
        &self,
        address: String,
        attempt_number: u32,
        chunk_size: u32,
    ) -> anyhow::Result<(Option<u32>, u32, u32, u32, u32)> {
        let address_type = self.get_address_script_type(&address)?;

        let wallet = self.wallets.iter().find(|w| w.address_type == address_type);

        let wallet = match wallet {
            Some(w) => w.bdk_wallet.lock().unwrap(),
            None => anyhow::bail!("No wallet found with the corresponding address type"),
        };

        // Optimization to always check address 0, which is often used during pairing
        if address == wallet.peek_address(KeychainKind::External, 0).to_string() {
            self.meta_storage
                .set_last_verified_address(address_type, KeychainKind::External, 0)?;
            return Ok((Some(0), 0, 0, 0, 0));
        }

        let receive_start = self
            .meta_storage
            .get_last_verified_address(address_type, KeychainKind::External)?;
        let change_start = self
            .meta_storage
            .get_last_verified_address(address_type, KeychainKind::Internal)?;
        let attempt_offset = attempt_number * (chunk_size / 2);

        let mut change_lower = change_start.saturating_sub(attempt_offset);
        let mut change_upper = change_start.saturating_add(attempt_offset);
        let mut receive_lower = receive_start.saturating_sub(attempt_offset);
        let mut receive_upper = receive_start.saturating_add(attempt_offset);

        for step in 0..(chunk_size / 2) {
            for (keychain, start) in [
                (KeychainKind::External, receive_start),
                (KeychainKind::Internal, change_start),
            ] {
                // Start higher index at 1, and the lower index at 0,
                // to search a total of chunk_size addresses
                if let Some(low_index) = start.checked_sub(attempt_offset + step) {
                    match keychain {
                        KeychainKind::Internal => change_lower = low_index,
                        KeychainKind::External => receive_lower = low_index,
                    }
                    if address == wallet.peek_address(keychain, low_index).to_string() {
                        self.meta_storage.set_last_verified_address(
                            address_type,
                            keychain,
                            low_index,
                        )?;
                        return Ok((
                            Some(low_index),
                            change_lower,
                            change_upper,
                            receive_lower,
                            receive_upper,
                        ));
                    }
                }

                if let Some(high_index) = start.checked_add(attempt_offset + step + 1) {
                    match keychain {
                        KeychainKind::Internal => change_upper = high_index,
                        KeychainKind::External => receive_upper = high_index,
                    }
                    if address == wallet.peek_address(keychain, high_index).to_string() {
                        self.meta_storage.set_last_verified_address(
                            address_type,
                            keychain,
                            high_index,
                        )?;
                        return Ok((
                            Some(high_index),
                            change_lower,
                            change_upper,
                            receive_lower,
                            receive_upper,
                        ));
                    }
                }

                // TODO: could add an error for if the whole address space is explored, although
                // this is more than 2x all IPv4 addresses, so it's unlikely
            }
        }

        Ok((
            None,
            change_lower,
            change_upper,
            receive_lower,
            receive_upper,
        ))
    }
}

impl<P: WalletPersister> NgAccount<P> {
    fn open_account_inner(
        descriptors: Vec<Descriptor<P>>,
        meta_storage: Arc<dyn MetaStorage>,
    ) -> anyhow::Result<Self>
    where
        <P as WalletPersister>::Error: Debug,
    {
        let config = meta_storage
            .get_config()
            .with_context(|| "Failed to get load account config")?
            .ok_or(anyhow::anyhow!("Account config not found"))?;

        let mut wallets: Vec<NgWallet<P>> = vec![];

        for descriptor in descriptors {
            let wallet = NgWallet::load(
                descriptor.internal,
                descriptor.external,
                meta_storage.clone(),
                descriptor.bdk_persister.clone(),
            )
            .with_context(|| "Failed to load wallet")?;
            wallets.push(wallet);
        }

        Ok(Self {
            config,
            wallets,
            meta_storage,
        })
    }

    fn read_config_inner(meta_storage: impl MetaStorage) -> Option<NgAccountConfig> {
        match meta_storage.get_config() {
            Ok(value) => value.clone(),
            Err(e) => {
                info!("Error reading config {:?}", e);
                None
            }
        }
    }
}

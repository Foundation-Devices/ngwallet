use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};

use crate::config::{AddressType, NgAccountBackup, NgAccountConfig, NgDescriptor};
use crate::db::RedbMetaStorage;
use crate::ngwallet::NgWallet;
use crate::store::MetaStorage;
use crate::transaction::{BitcoinTransaction, Output};
use crate::utils;
use crate::utils::get_address_type;
use anyhow::{Context, Error, anyhow};
use bdk_wallet::bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bdk_wallet::bitcoin::{Address, Amount, Psbt, Transaction, Txid};
#[cfg(feature = "envoy")]
use bdk_wallet::chain::spk_client::FullScanRequest;
#[cfg(feature = "envoy")]
use bdk_wallet::chain::spk_client::SyncRequest;
use bdk_wallet::{AddressInfo, Balance, KeychainKind, Update, WalletPersister};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct NgAccount<P: WalletPersister> {
    pub config: Arc<RwLock<NgAccountConfig>>,
    pub wallets: Arc<RwLock<Vec<NgWallet<P>>>>,
    pub meta_storage: Arc<dyn MetaStorage + Send>,
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
    format!("{internal_id}_{external_id}.sqlite")
}

impl<P: WalletPersister> NgAccount<P> {
    pub fn new_from_descriptors(
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
            config: Arc::new(RwLock::new(account_config)),
            wallets: Arc::new(RwLock::new(wallets)),
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
        Self::open_account(descriptors, Arc::new(meta_storage))
    }

    pub fn open_account_from_db(
        descriptors: Vec<Descriptor<P>>,
        db: redb::Database,
    ) -> anyhow::Result<Self>
    where
        <P as WalletPersister>::Error: Debug,
    {
        let meta_storage = RedbMetaStorage::from_db(db);
        Self::open_account(descriptors, Arc::new(meta_storage))
    }

    pub fn open_account(
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
            config: Arc::new(RwLock::new(config)),
            wallets: Arc::new(RwLock::new(wallets)),
            meta_storage,
        })
    }

    pub fn rename(&self, name: &str) -> Result<(), Error> {
        self.config.write().unwrap().name = name.to_string();
        self.persist()
    }

    pub fn set_preferred_address_type(&self, address_type: AddressType) -> Result<(), Error> {
        self.config.write().unwrap().preferred_address_type = address_type;
        self.persist()
    }

    pub fn persist(&self) -> Result<(), Error> {
        for wallet in self.wallets.read().unwrap().iter() {
            wallet.persist()?;
        }

        let config = self.config.read().unwrap();
        self.meta_storage
            .set_config(config.serialize().as_str())
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub fn add_new_descriptor(&self, descriptor: &Descriptor<P>) -> Result<(), Error> {
        let address_type = get_address_type(&descriptor.internal);
        {
            let mut config = self.config.write().unwrap();
            for wallet_descriptor in &config.descriptors {
                if wallet_descriptor.internal == descriptor.internal {
                    return Err(anyhow::anyhow!("Descriptor already exists"));
                }
                if address_type == wallet_descriptor.address_type {
                    return Err(anyhow::anyhow!("Address type already exists"));
                }
            }
            config.descriptors.push(NgDescriptor {
                internal: descriptor.internal.clone(),
                external: descriptor.external.clone(),
                address_type,
            });
            let wallet = NgWallet::new_from_descriptor(
                descriptor.internal.clone(),
                descriptor.external.clone(),
                config.network,
                self.meta_storage.clone(),
                descriptor.bdk_persister.clone(),
            )?;
            self.wallets.write().unwrap().push(wallet);
        }

        self.persist()?;
        Ok(())
    }

    pub fn get_backup_json(&self) -> Result<String, Error> {
        let config = {
            let mut config = self.config.read().unwrap().clone();
            if self.is_hot() {
                config.descriptors = vec![];
            }
            let last_used_index = self.get_derivation_index();
            let transactions = self.transactions()?;
            let utxos = self.utxos()?;
            let mut notes: HashMap<String, String> = HashMap::default();
            let mut tags: HashMap<String, String> = HashMap::default();
            let mut do_not_spend: HashMap<String, bool> = HashMap::default();
            for utxo in utxos {
                if utxo.do_not_spend {
                    do_not_spend.insert(utxo.get_id().to_string(), true);
                }
                if utxo.tag.is_some() {
                    tags.insert(utxo.get_id().to_string(), utxo.tag.clone().unwrap());
                }
            }
            for tx in transactions {
                if tx.note.is_some() {
                    notes.insert(tx.tx_id, tx.note.clone().unwrap());
                }
            }
            NgAccountBackup {
                ng_account_config: config,
                last_used_index,
                public_descriptors: self.get_external_public_descriptors(),
                notes,
                xfp: self.get_coordinator_wallet().get_xfp(),
                tags,
                do_not_spend,
            }
        };
        match serde_json::to_string(&config) {
            Ok(config) => Ok(config),
            Err(_) => Err(anyhow::anyhow!("Error serializing config")),
        }
    }

    pub fn next_address(&self) -> anyhow::Result<Vec<(AddressInfo, AddressType)>> {
        let mut addresses = vec![];
        for wallet in self.wallets.write().unwrap().iter_mut() {
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

        for wallet in self.wallets.read().unwrap().iter() {
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
        for wallet in self.wallets.read().unwrap().iter() {
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
        let mut transactions: Vec<BitcoinTransaction> = vec![];

        let config = self.config.read().unwrap();

        for wallet in self.wallets.read().unwrap().iter() {
            let wallet_txs = wallet.transactions().unwrap_or_default();
            for wallet_tx in wallet_txs {
                let tx = {
                    let bdk = wallet.bdk_wallet.lock().expect("Failed to lock wallet");
                    let tx = bdk
                        .get_tx(Txid::from_str(&wallet_tx.tx_id)?)
                        .with_context(|| "Failed to get transaction ".to_string())?;
                    tx.tx_node.tx
                };
                //use account level sent and received amounts (all wallets)
                let (sent, received) = self.sent_and_received(&tx);
                let mut tx = wallet_tx.clone();
                let amount: i64 = (received.to_sat() as i64) - (sent.to_sat() as i64);
                tx.amount = amount;

                //since there can be multiple wallets with the same tx_id (self spend between wallets),
                //we will keep outgoing transactions
                let exist = transactions.iter().find(|x| x.tx_id == tx.tx_id);
                if let Some(existing_tx) = exist {
                    //if the tx amount is negative, it means it's an outgoing transaction
                    if existing_tx.amount.is_negative()
                        && let Some(pos) = transactions
                            .iter()
                            .position(|x| x.tx_id == existing_tx.tx_id)
                    {
                        transactions.remove(pos);
                        transactions.push(tx.clone());
                    }
                } else {
                    transactions.push(tx)
                }
            }
        }
        //map transactions to include account_id
        transactions = transactions
            .iter()
            .map(|tx| {
                let mut tx = tx.clone();
                tx.account_id = config.id.clone();
                tx
            })
            .collect();
        // Sort transactions by date, most recent first
        transactions.sort_by(|a, b| match (a.date, b.date) {
            (Some(a_date), Some(b_date)) => b_date.cmp(&a_date),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });
        Ok(transactions)
    }

    pub fn utxos(&self) -> anyhow::Result<Vec<Output>> {
        let mut utxos = vec![];
        for wallet in self.wallets.read().unwrap().iter() {
            utxos.extend(wallet.utxos()?);
        }

        Ok(utxos)
    }

    pub fn set_note(&self, tx_id: &str, note: &str) -> anyhow::Result<bool> {
        self.meta_storage
            .set_note(tx_id, note)
            .with_context(|| "Could not set note")?;
        Ok(true)
    }

    //TODO: handle error
    pub fn get_xfp(&self) -> String {
        self.get_coordinator_wallet().get_xfp()
    }

    //if tag is empty, the tag will be removed from the output
    //else new tag will be assigned and tag name will be added to the list
    pub fn set_tag(&self, output_id: &str, tag: &str) -> anyhow::Result<bool> {
        if tag.is_empty() {
            self.meta_storage
                .remove_tag(output_id)
                .with_context(|| "Could not set tag")?;
        } else {
            self.meta_storage
                .set_tag(output_id, tag)
                .with_context(|| "Could not set tag")?;
            self.meta_storage
                .add_tag(tag.to_string().as_str())
                .with_context(|| "Could not add tag")?;
        }
        Ok(true)
    }

    pub fn set_do_not_spend(&self, output_id: &str, state: bool) -> anyhow::Result<()> {
        self.meta_storage.set_do_not_spend(output_id, state)
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
            .read()
            .unwrap()
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

    pub fn get_coordinator_wallet(&self) -> NgWallet<P> {
        let address_type = self.config.read().unwrap().preferred_address_type;
        let wallets = self.wallets.read().unwrap();
        for wallet in wallets.iter() {
            if wallet.address_type == address_type {
                return wallet.clone();
            }
        }
        wallets.first().unwrap().clone()
    }

    pub fn non_coordinator_wallets(&self) -> Vec<NgWallet<P>> {
        let address_type = self.config.read().unwrap().preferred_address_type;
        self.wallets
            .read()
            .unwrap()
            .iter()
            .filter(|wallet| wallet.address_type != address_type)
            .cloned()
            .collect()
    }

    pub fn get_derivation_index(&self) -> Vec<(AddressType, KeychainKind, u32)> {
        let mut derivation_index = vec![];
        for wallet in self.wallets.read().unwrap().iter() {
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

    //Signs serialized PSBTs. returns the signed PSBT as serialized bytes.
    pub fn sign(&self, psbt: &[u8], options: bdk_wallet::SignOptions) -> anyhow::Result<Vec<u8>> {
        let mut psbt = Psbt::deserialize(psbt).with_context(|| "Failed to deserialize PSBT")?;

        for wallet in self.wallets.read().unwrap().iter() {
            wallet.sign_psbt(&mut psbt, options.clone())?;
        }

        let encoded_psbt = psbt.serialize();
        Ok(encoded_psbt)
    }

    pub fn cancel_tx(&self, psbt: Psbt) -> anyhow::Result<Vec<u8>> {
        for wallet in self.wallets.read().unwrap().iter() {
            wallet.cancel_tx(&psbt.unsigned_tx)?;
        }
        let encoded_psbt = psbt.serialize();
        Ok(encoded_psbt)
    }

    pub fn is_hot(&self) -> bool {
        for wallet in self.wallets.read().unwrap().iter() {
            if wallet.is_hot() {
                return true;
            }
        }
        false
    }
    pub fn sent_and_received(&self, tx: &Transaction) -> (Amount, Amount) {
        let mut sent = Amount::from_sat(0);
        let mut received = Amount::from_sat(0);
        for wallet in self.wallets.read().unwrap().iter() {
            let (_send, _received) = wallet.sent_and_received(tx);
            sent += _send;
            received += _received;
        }
        (sent, received)
    }

    pub fn list_tags(&self) -> anyhow::Result<Vec<String>> {
        self.meta_storage.list_tags()
    }

    pub fn mark_utxo_as_used(&self, transaction: Transaction) {
        for wallet in self.wallets.read().unwrap().iter() {
            let mut wallet_mut = wallet.bdk_wallet.lock().unwrap();
            for txout in &transaction.output {
                if let Some((keychain, index)) =
                    wallet_mut.derivation_of_spk(txout.script_pubkey.clone())
                {
                    wallet_mut.mark_used(keychain, index);
                }
            }
        }
    }
    /// Sets a note for a transaction without checking if the transaction existence.
    pub fn set_note_unchecked(&self, tx_id: &str, note: &str) -> anyhow::Result<bool> {
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

    pub fn remove_tag(&self, target_tag: &str, rename_to: Option<&str>) -> anyhow::Result<()> {
        self.meta_storage.remove_tag(target_tag)?;
        let utxos = self.utxos()?;
        for output in utxos {
            match &output.tag {
                None => {}
                Some(existing_tag) => {
                    let new_tag = rename_to.unwrap_or("");
                    if existing_tag
                        .to_lowercase()
                        .eq(target_tag.to_lowercase().as_str())
                    {
                        self.set_tag(output.get_id().as_str(), new_tag)?;
                    }
                }
            }
        }

        Ok(())
    }

    pub fn get_external_public_descriptors(&self) -> Vec<(AddressType, String)> {
        let mut descriptors = vec![];

        for wallet in self.wallets.read().unwrap().iter() {
            let external_pubkey = wallet
                .bdk_wallet
                .lock()
                .unwrap()
                .public_descriptor(KeychainKind::External)
                .to_string();
            descriptors.push((wallet.address_type, external_pubkey));
        }

        descriptors
    }

    #[cfg(feature = "envoy")]
    pub fn fetch_fee_from_electrum(
        txid: &str,
        electrum_server: &str,
        socks_proxy: Option<&str>,
    ) -> Option<u64> {
        use bdk_wallet::bitcoin::Txid;
        use std::str::FromStr;
        let client = utils::build_electrum_client(electrum_server, socks_proxy);

        let tx_id = Txid::from_str(txid).ok()?;
        let tx = client.fetch_tx(tx_id).ok()?;

        let input_sum: u64 = tx
            .input
            .iter()
            .filter_map(|input| {
                let prev_txid = input.previous_output.txid;
                let vout = input.previous_output.vout;

                let prev_tx = client.fetch_tx(prev_txid).ok()?;
                let prev_out = prev_tx.output.get(vout as usize)?;

                Some(prev_out.value.to_sat())
            })
            .sum();

        let output_sum: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();

        let fee = input_sum.saturating_sub(output_sum);
        Some(fee)
    }

    pub fn update_fee(&self, txid: &str, fee: u64) -> anyhow::Result<()> {
        self.meta_storage
            .set_fee(txid, fee)
            .with_context(|| "Failed to set fee")
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

    pub fn update(&self, payload: Vec<u8>) -> anyhow::Result<()> {
        let update: RemoteUpdate = minicbor_serde::from_slice(&payload)?;

        for wallet_update in update.wallet_update {
            self.apply(wallet_update)?
        }

        match update.metadata {
            None => {}
            Some(m) => {
                *self.config.write().unwrap() = m;
            }
        }

        self.persist()?;
        Ok(())
    }

    pub fn get_address_script_type(&self, address: &str) -> anyhow::Result<AddressType> {
        let network = self.config.read().unwrap().network;
        let address: Address<NetworkUnchecked> =
            Address::from_str(address).map_err(|_| anyhow::anyhow!("Could not parse address"))?;
        let address: Address<NetworkChecked> = address
            .require_network(network)
            .map_err(|_| anyhow::anyhow!("Address is invalid for current network: {network}"))?;
        match address.address_type() {
            Some(t) => t.try_into(),
            None => Err(anyhow::anyhow!("Unknown address type")),
        }
    }

    pub fn get_address_verification_info(
        &self,
        address: String,
    ) -> anyhow::Result<AddressVerificationInfo> {
        let address_type = self.get_address_script_type(&address)?;

        let wallets = self.wallets.read().unwrap();
        let wallet = wallets.iter().find(|w| w.address_type == address_type);
        let wallet = match wallet {
            Some(w) => w,
            None => anyhow::bail!(
                "No wallet found with the corresponding address type: {:?}",
                address_type
            ),
        };

        let bdk_wallet = wallet.bdk_wallet.lock().unwrap();
        let external_descriptor = bdk_wallet
            .public_descriptor(KeychainKind::External)
            .to_string();
        let internal_descriptor = bdk_wallet
            .public_descriptor(KeychainKind::Internal)
            .to_string();

        let receive_start = self
            .meta_storage
            .get_last_verified_address(address_type, KeychainKind::External)?;
        let change_start = self
            .meta_storage
            .get_last_verified_address(address_type, KeychainKind::Internal)?;

        Ok(AddressVerificationInfo {
            address,
            internal_descriptor,
            external_descriptor: Some(external_descriptor),
            network: self.config.read().unwrap().network,
            address_type,
            receive_start,
            change_start,
        })
    }

    pub fn update_verification_state(
        &self,
        verification_result: &AddressVerificationResult,
    ) -> anyhow::Result<()> {
        if let (Some(found_index), Some(keychain)) = (
            verification_result.found_index,
            verification_result.keychain,
        ) {
            self.meta_storage.set_last_verified_address(
                verification_result.address_type,
                keychain,
                found_index,
            )?;
        }
        Ok(())
    }

    pub fn verify_address(
        &self,
        address: String,
        attempt_number: u32,
        chunk_size: u32,
    ) -> anyhow::Result<AddressVerificationResult> {
        let address_type = self.get_address_script_type(&address)?;

        let wallet = self
            .wallets
            .read()
            .unwrap()
            .iter()
            .find(|w| w.address_type == address_type)
            .cloned();
        let wallet = match wallet {
            Some(w) => w,
            None => anyhow::bail!(
                "No wallet found with the corresponding address type: {:?}",
                address_type
            ),
        };

        let wallet = wallet.bdk_wallet.lock().unwrap();

        let receive_start = self
            .meta_storage
            .get_last_verified_address(address_type, KeychainKind::External)?;
        let change_start = self
            .meta_storage
            .get_last_verified_address(address_type, KeychainKind::Internal)?;

        let result = search_for_address(
            &wallet,
            &address,
            attempt_number,
            chunk_size,
            receive_start,
            change_start,
            address_type,
        );

        if let (Some(index), Some(keychain)) = (result.found_index, result.keychain) {
            self.meta_storage
                .set_last_verified_address(address_type, keychain, index)?;
        }

        Ok(result)
    }

    pub fn get_bip329_data(&self) -> anyhow::Result<Vec<String>> {
        let mut result = vec![];
        let mut seen_tx_refs = HashSet::new();
        let config = self.config.read().unwrap();

        for wallet in self.wallets.read().unwrap().iter() {
            let descriptor = wallet
                .bdk_wallet
                .lock()
                .unwrap()
                .public_descriptor(KeychainKind::External)
                .to_string();

            // Add xpub entry
            let xpub = utils::extract_xpub_from_descriptor(&descriptor);
            let label_opt = (!config.name.is_empty()).then_some(config.name.as_str());
            result.push(utils::build_key_json("xpub", &xpub, label_opt, None, None));

            // Add UTXO entries
            let utxos = wallet.utxos()?;
            for utxo in utxos {
                let label_opt = utxo.tag.as_deref().filter(|s| !s.is_empty());
                let reference = format!("{}:{}", utxo.tx_id, utxo.vout);
                result.push(utils::build_key_json(
                    "output",
                    &reference,
                    label_opt,
                    None,
                    Some(!utxo.do_not_spend),
                ));
            }

            // Add TX entries, linked to correct descriptor origin
            let origin = utils::extract_descriptor_origin(&descriptor);

            let txs = wallet.transactions()?;
            for tx in txs {
                let key = format!("{}:{}", tx.tx_id, origin);
                if seen_tx_refs.insert(key) {
                    let label_opt = tx.note.as_deref().filter(|s| !s.is_empty());
                    result.push(utils::build_key_json(
                        "tx",
                        &tx.tx_id,
                        label_opt,
                        Some(&origin),
                        None,
                    ));
                }
            }
        }

        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub struct AddressVerificationResult {
    pub found_index: Option<u32>,
    pub keychain: Option<KeychainKind>,
    pub address_type: crate::config::AddressType,
    pub change_lower: u32,
    pub change_upper: u32,
    pub receive_lower: u32,
    pub receive_upper: u32,
}

#[derive(Debug, Clone)]
pub struct AddressVerificationInfo {
    pub address: String,
    pub internal_descriptor: String,
    pub external_descriptor: Option<String>,
    pub network: bdk_wallet::bitcoin::Network,
    pub address_type: crate::config::AddressType,
    pub receive_start: u32,
    pub change_start: u32,
}

pub fn search_for_address(
    wallet: &bdk_wallet::Wallet,
    address: &str,
    attempt_number: u32,
    chunk_size: u32,
    receive_start: u32,
    change_start: u32,
    address_type: AddressType,
) -> AddressVerificationResult {
    // Optimization to always check address 0, which is often used during pairing
    if address == wallet.peek_address(KeychainKind::External, 0).to_string() {
        return AddressVerificationResult {
            found_index: Some(0),
            keychain: Some(KeychainKind::External),
            address_type,
            change_lower: 0,
            change_upper: 0,
            receive_lower: 0,
            receive_upper: 0,
        };
    }

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
                    return AddressVerificationResult {
                        found_index: Some(low_index),
                        keychain: Some(keychain),
                        address_type,
                        change_lower,
                        change_upper,
                        receive_lower,
                        receive_upper,
                    };
                }
            }

            if let Some(high_index) = start.checked_add(attempt_offset + step + 1) {
                match keychain {
                    KeychainKind::Internal => change_upper = high_index,
                    KeychainKind::External => receive_upper = high_index,
                }
                if address == wallet.peek_address(keychain, high_index).to_string() {
                    return AddressVerificationResult {
                        found_index: Some(high_index),
                        keychain: Some(keychain),
                        address_type,
                        change_lower,
                        change_upper,
                        receive_lower,
                        receive_upper,
                    };
                }
            }

            // TODO: could add an error for if the whole address space is explored, although
            // this is more than 2x all IPv4 addresses, so it's unlikely
        }
    }

    AddressVerificationResult {
        found_index: None,
        keychain: None,
        address_type,
        change_lower,
        change_upper,
        receive_lower,
        receive_upper,
    }
}

#[cfg(test)]
#[cfg(feature = "envoy")]
mod tests {
    use super::*;
    use crate::config::NgAccountConfig;
    use crate::store::InMemoryMetaStorage;
    use bdk_wallet::bitcoin::Network;
    use bdk_wallet::rusqlite::Connection;
    use std::any::Any;
    #[test]
    fn test_ng_account_send() {
        // Create a dummy config
        let config = NgAccountConfig {
            name: "test".to_string(),
            color: "blue".to_string(),
            seed_has_passphrase: false,
            device_serial: None,
            date_added: None,
            preferred_address_type: crate::config::AddressType::P2pkh,
            index: 0,
            descriptors: vec![],
            date_synced: None,
            network: Network::Bitcoin,
            id: "test_id".to_string(),
            multisig: None,
            archived: false,
        };

        let account = NgAccount {
            config: Arc::new(RwLock::new(config)),
            wallets: Arc::new(RwLock::new(Vec::<NgWallet<Connection>>::new())),
            meta_storage: Arc::new(InMemoryMetaStorage::default()),
        };

        let sendable: Box<dyn Any + Send> = Box::new(account);
    }
}

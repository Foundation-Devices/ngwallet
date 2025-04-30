use std::fmt::Debug;
use std::result::Result::Ok;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use bdk_wallet::bitcoin::{Address, Network, OutPoint, Psbt, Txid};
use bdk_wallet::chain::ChainPosition::{Confirmed, Unconfirmed};
use bdk_wallet::{AddressInfo, CreateWithPersistError, PersistedWallet, SignOptions};
use bdk_wallet::{KeychainKind, WalletPersister};
use bdk_wallet::{Update, Wallet};
use miniscript::descriptor::DescriptorType;
use miniscript::ForEachKey;

#[cfg(feature = "envoy")]
use {
    crate::{BATCH_SIZE, STOP_GAP},
    bdk_electrum::BdkElectrumClient,
    bdk_electrum::bdk_core::spk_client::FullScanRequest,
    bdk_electrum::bdk_core::spk_client::FullScanResponse,
    bdk_electrum::bdk_core::spk_client::SyncRequest,
    bdk_electrum::bdk_core::spk_client::SyncResponse,
    bdk_electrum::electrum_client::Client,
    bdk_electrum::electrum_client::{Config, Socks5Config},
};

use crate::store::MetaStorage;
use crate::transaction::{BitcoinTransaction, Input, KeyChain, Output};

#[derive(Debug)]
pub struct PsbtInfo {
    pub outputs: std::collections::HashMap<u64, String>,
    pub fee: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum ExportMode {
    Qr,
    Ur2,
    File,
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum ExportTarget {
    Envoy,
    BitcoinCore,
    BitcoinKeeper,
    BlueWallet,
    BTCPay,
    Casa,
    Coinbits,
    Electrum,
    FullyNoded,
    Nunchuk,
    SimpleBitcoinWallet,
    Sparrow,
    Specter,
    Theya,
    Zeus,
}

#[derive(Debug)]
pub struct NgWallet<P: WalletPersister> {
    pub wallet: Arc<Mutex<PersistedWallet<P>>>,
    pub(crate) meta_storage: Arc<Mutex<dyn MetaStorage>>,
    bdk_persister: Arc<Mutex<P>>,
}

impl<P: WalletPersister> NgWallet<P> {
    pub fn new_from_descriptor(
        internal_descriptor: String,
        external_descriptor: Option<String>,
        network: Network,
        meta_storage: Arc<Mutex<dyn MetaStorage>>,
        bdk_persister: Arc<Mutex<P>>,
    ) -> Result<NgWallet<P>> {
        let wallet = match external_descriptor {
            None => Wallet::create_single(internal_descriptor.to_string()),
            Some(external_descriptor) => Wallet::create(external_descriptor, internal_descriptor),
        }
        .network(network)
        .create_wallet(&mut *bdk_persister.lock().unwrap())
        .map_err(|e| match e {
            CreateWithPersistError::Persist(_) => {
                anyhow::anyhow!("Could not persist wallet")
            }
            CreateWithPersistError::DataAlreadyExists(_) => {
                anyhow::anyhow!("Wallet already exist. Please use load method")
            }
            CreateWithPersistError::Descriptor(error) => {
                anyhow::anyhow!("Could not create wallet from descriptor: {:?}", error)
            }
        })?;

        Ok(Self {
            wallet: Arc::new(Mutex::new(wallet)),
            bdk_persister,
            meta_storage,
        })
    }

    pub fn persist(&mut self) -> Result<bool> {
        self.wallet
            .lock()
            .unwrap()
            .persist(&mut self.bdk_persister.lock().unwrap())
            .map_err(|_| anyhow::anyhow!("Could not persist wallet"))
    }

    pub fn load(
        meta_storage: Arc<Mutex<dyn MetaStorage>>,
        bdk_persister: Arc<Mutex<P>>,
    ) -> Result<NgWallet<P>>
    where
        <P as WalletPersister>::Error: Debug,
    {
        // #[cfg(feature = "envoy")]
        //     let mut persister = Connection::open(format!("{}/wallet.sqlite",db_path))?;

        let config = meta_storage
            .lock()
            .unwrap()
            .get_config()
            .map_err(|e| anyhow::anyhow!("Could not get config from meta storage: {:?}", e))?
            .unwrap();

        let wallet_opt = Wallet::load()
            .descriptor(KeychainKind::Internal, Some(config.internal_descriptor))
            .descriptor(KeychainKind::External, config.external_descriptor)
            .extract_keys()
            .load_wallet(&mut *bdk_persister.lock().unwrap())
            .unwrap();

        match wallet_opt {
            Some(wallet) => Ok(Self {
                wallet: Arc::new(Mutex::new(wallet)),
                bdk_persister,
                meta_storage,
            }),
            None => Err(anyhow::anyhow!("Failed to load wallet database.")),
        }
    }

    pub fn next_address(&mut self) -> Result<AddressInfo> {
        let address: AddressInfo = self
            .wallet
            .lock()
            .unwrap()
            .next_unused_address(KeychainKind::External);
        self.persist()?;
        Ok(address)
    }

    pub fn transactions(&self) -> Result<Vec<BitcoinTransaction>> {
        let wallet = self.wallet.lock().unwrap();
        let mut transactions: Vec<BitcoinTransaction> = vec![];
        let tip_height = wallet.latest_checkpoint().height();
        let storage = self.meta_storage.lock().unwrap();

        //add date to transaction
        for canonical_tx in wallet.transactions() {
            let mut date: Option<u64> = None;
            let tx = canonical_tx.tx_node.tx;
            let tx_id = canonical_tx.tx_node.txid.to_string();
            let (sent, received) = wallet.sent_and_received(tx.as_ref());
            let fee = wallet.calculate_fee(tx.as_ref()).unwrap().to_sat();
            let block_height = match canonical_tx.chain_position {
                Confirmed { anchor, .. } => {
                    //to milliseconds
                    date = Some(anchor.confirmation_time * 1000);
                    let block_height = anchor.block_id.height;
                    if block_height > 0 { block_height } else { 0 }
                }
                Unconfirmed { last_seen } => {
                    match last_seen {
                        None => {}
                        Some(last_seen) => {
                            //to milliseconds
                            date = Some(last_seen * 1000);
                        }
                    }
                    0
                }
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
                    let amount = if wallet.get_utxo(input.previous_output).is_some() {
                        wallet
                            .get_utxo(input.previous_output)
                            .unwrap()
                            .txout
                            .value
                            .to_sat()
                    } else {
                        0
                    };
                    Input {
                        tx_id: tx_id.clone(),
                        vout,
                        amount,
                        tag: storage
                            .get_tag(format!("{}{}", &tx_id, vout).as_str())
                            .unwrap_or(None),
                    }
                })
                .collect::<Vec<Input>>();

            let outputs = tx
                .output
                .clone()
                .iter()
                .enumerate()
                .map(|(index, output)| {
                    let amount = output.value;
                    let do_not_spend = storage.get_do_not_spend(&tx_id).unwrap_or(false);
                    Output {
                        tx_id: tx_id.clone(),
                        vout: index as u32,
                        amount: amount.to_sat(),
                        address: Address::from_script(&output.script_pubkey, wallet.network())
                            .unwrap()
                            .to_string(),
                        tag: storage.get_tag(&tx_id).unwrap(),
                        do_not_spend,
                        keychain: wallet
                            .derivation_of_spk(output.script_pubkey.clone())
                            .map(|x| {
                                if x.0 == KeychainKind::External {
                                    KeyChain::External
                                } else {
                                    KeyChain::Internal
                                }
                            }),
                        date,
                        is_confirmed: confirmations >= 3,
                    }
                })
                .collect::<Vec<Output>>();
            let amount: i64 = (received.to_sat() as i64) - (sent.to_sat() as i64);

            let address = {
                let mut ret = "".to_string();
                //its a sent transaction
                if amount.is_positive() {
                    tx.output
                        .clone()
                        .iter()
                        .filter(|output| !wallet.is_mine(output.script_pubkey.clone()))
                        .for_each(|output| {
                            ret = Address::from_script(&output.script_pubkey, wallet.network())
                                .unwrap()
                                .to_string();
                        });
                } else {
                    tx.output
                        .clone()
                        .iter()
                        .filter(|output| {
                            wallet
                                .derivation_of_spk(output.script_pubkey.clone())
                                .is_none()
                        })
                        .for_each(|output| {
                            ret = Address::from_script(&output.script_pubkey, wallet.network())
                                .unwrap()
                                .to_string();
                        });
                    // if the address is empty, then check for self transfer
                    if ret.is_empty() {
                        tx.output
                            .clone()
                            .iter()
                            .filter(|output| {
                                wallet
                                    .derivation_of_spk(output.script_pubkey.clone())
                                    .is_some_and(|x| x.0 == KeychainKind::External)
                            })
                            .for_each(|output| {
                                ret = Address::from_script(&output.script_pubkey, wallet.network())
                                    .unwrap()
                                    .to_string();
                            });
                    }
                }

                //possible cancel transaction that involves change address
                if ret.is_empty() && tx.output.len() == 1 {
                    tx.output
                        .clone()
                        .iter()
                        .filter(|output| {
                            wallet
                                .derivation_of_spk(output.script_pubkey.clone())
                                .is_some_and(|x| x.0 == KeychainKind::Internal)
                        })
                        .for_each(|o| {
                            ret = Address::from_script(&o.script_pubkey, wallet.network())
                                .unwrap()
                                .to_string();
                        });
                }
                ret
            };
            let vsize = tx.vsize() as f32;
            let fee_rate = if vsize > 0.0 {
                (fee as f32 / vsize) as u64
            } else {
                0
            };
            storage.get_note(&tx_id).unwrap_or(None);
            transactions.push(BitcoinTransaction {
                tx_id: tx_id.clone(),
                block_height,
                confirmations,
                is_confirmed: confirmations >= 3,
                fee,
                fee_rate,
                amount,
                inputs,
                outputs,
                address,
                date,
                vsize: tx.vsize(),
                note: storage.get_note(&tx_id).unwrap(),
            })
        }

        Ok(transactions)
    }
    #[cfg(feature = "envoy")]
    pub fn full_scan_request(&self) -> FullScanRequest<KeychainKind> {
        self.wallet.lock().unwrap().start_full_scan().build()
    }
    #[cfg(feature = "envoy")]
    pub fn sync_request(&self) -> SyncRequest<(KeychainKind, u32)> {
        self.wallet
            .lock()
            .unwrap()
            .start_sync_with_revealed_spks()
            .build()
    }

    #[cfg(feature = "envoy")]
    pub fn sync(
        request: SyncRequest<(KeychainKind, u32)>,
        electrum_server: &str,
        socks_proxy: Option<&str>,
    ) -> Result<SyncResponse> {
        let bdk_client = Self::build_electrum_client(electrum_server, socks_proxy);
        let update = bdk_client.sync(request, BATCH_SIZE, true)?;
        Ok(update)
    }

    #[cfg(feature = "envoy")]
    pub fn scan(
        request: FullScanRequest<KeychainKind>,
        electrum_server: &str,
        socks_proxy: Option<&str>,
    ) -> Result<FullScanResponse<KeychainKind>> {
        let socks5_config = match socks_proxy {
            Some(socks_proxy) => {
                let socks5_config = Socks5Config::new(socks_proxy);
                Some(socks5_config)
            }
            None => None,
        };
        let electrum_config = Config::builder().socks5(socks5_config).build();

        let client = Client::from_config(electrum_server, electrum_config)?;
        let client: BdkElectrumClient<Client> = BdkElectrumClient::new(client);
        let update = client.full_scan(request, STOP_GAP, BATCH_SIZE, true)?;
        Ok(update)
    }

    pub fn unspend_outputs(&self) -> Result<Vec<Output>> {
        let wallet = self.wallet.lock().unwrap();
        let mut unspents: Vec<Output> = vec![];
        let tip_height = wallet.latest_checkpoint().height();

        let meta_storage = self.meta_storage.lock().unwrap();
        for local_output in wallet.list_unspent() {
            let mut date: Option<u64> = None;
            let out_put_id = format!(
                "{}:{}",
                local_output.outpoint.txid, local_output.outpoint.vout,
            );
            let wallet_tx = wallet.get_tx(local_output.outpoint.txid);
            let mut confirmations = 0;
            match wallet_tx {
                None => {}
                Some(wallet_tx) => {
                    match wallet_tx.chain_position {
                        Confirmed { anchor, .. } => {
                            //to milliseconds

                            date = Some(anchor.confirmation_time * 1000);
                            let block_height = anchor.block_id.height;
                            confirmations = if block_height > 0 {
                                tip_height - block_height + 1
                            } else {
                                0
                            };
                            if block_height > 0 { block_height } else { 0 }
                        }
                        Unconfirmed { last_seen } => {
                            match last_seen {
                                None => {}
                                Some(last_seen) => {
                                    //to milliseconds
                                    date = Some(last_seen * 1000);
                                }
                            }
                            0
                        }
                    };
                }
            }

            let do_not_spend = meta_storage
                .get_do_not_spend(out_put_id.as_str())
                .unwrap_or(false);

            unspents.push(Output {
                tx_id: local_output.outpoint.txid.to_string(),
                vout: local_output.outpoint.vout,
                amount: local_output.txout.value.to_sat(),
                address: Address::from_script(&local_output.txout.script_pubkey, wallet.network())
                    .unwrap()
                    .to_string(),
                keychain: wallet
                    .derivation_of_spk(local_output.txout.script_pubkey.clone())
                    .map(|x| {
                        if x.0 == KeychainKind::External {
                            KeyChain::External
                        } else {
                            KeyChain::Internal
                        }
                    }),
                tag: meta_storage.get_tag(out_put_id.clone().as_str()).unwrap(),
                do_not_spend,
                date,
                is_confirmed: confirmations >= 3,
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

    //check if the wallet got signers,
    pub fn is_hot(&self) -> bool {
        let wallet = self.wallet.lock().unwrap();
        !wallet
            .get_signers(KeychainKind::Internal)
            .signers()
            .is_empty()
            || !wallet
                .get_signers(KeychainKind::External)
                .signers()
                .is_empty()
    }

    pub fn sign(&self, psbt: &str) -> Result<String> {
        let mut psbt = Psbt::from_str(psbt)?;
        self.wallet
            .lock()
            .unwrap()
            .sign(&mut psbt, SignOptions::default())?;
        Ok(psbt.serialize_hex())
    }

    pub fn parse_psbt(&self, psbt_str: &str) -> Result<PsbtInfo> {
        let psbt = Psbt::from_str(psbt_str)?;
        let tx = psbt.extract_tx()?;
        let wallet = self.wallet.lock().unwrap();
        let mut outputs = std::collections::HashMap::new();
        let mut fee = 0;

        for output in tx.clone().output {
            if let Ok(address) = Address::from_script(&output.script_pubkey, wallet.network()) {
                if !wallet.is_mine(output.script_pubkey) {
                    outputs.insert(output.value.to_sat(), address.to_string());
                }
            }
        }

        if let Ok(fee_amount) = wallet.calculate_fee(&tx) {
            fee = fee_amount.to_sat();
        }

        Ok(PsbtInfo { outputs, fee })
    }

    #[cfg(feature = "envoy")]
    pub fn broadcast(&mut self, psbt: Psbt, electrum_server: &str) -> Result<()> {
        let client: BdkElectrumClient<Client> =
            BdkElectrumClient::new(Client::new(electrum_server)?);

        let tx = psbt.extract_tx()?;
        client.transaction_broadcast(&tx)?;

        Ok(())
    }

    pub fn set_note(&mut self, tx_id: &str, note: &str) -> Result<bool> {
        let tx_id = Txid::from_str(tx_id).map_err(|e| anyhow::anyhow!("Invalid Txid: {:?}", e))?;
        let tx = self
            .wallet
            .lock()
            .unwrap()
            .get_tx(tx_id)
            .ok_or_else(|| anyhow::anyhow!("Transaction not found"))?
            .tx_node
            .tx
            .compute_txid();

        self.meta_storage
            .lock()
            .unwrap()
            .set_note(&tx.to_string(), note)
            .map_err(|e| anyhow::anyhow!("Could not set note: {:?}", e))?;

        Ok(true)
    }

    /// Sets a note for a transaction without checking if the transaction existence.
    pub fn set_note_unchecked(&mut self, tx_id: &str, note: &str) -> Result<bool> {
        self.meta_storage
            .lock()
            .unwrap()
            .set_note(tx_id, note)
            .map_err(|e| anyhow::anyhow!("Could not set note: {:?}", e))?;
        Ok(true)
    }

    pub fn set_tag(&mut self, output: &Output, tag: &str) -> Result<bool> {
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

    pub fn get_tag(&self, output_id: &str) -> Option<String> {
        self.meta_storage
            .lock()
            .unwrap()
            .get_tag(output_id)
            .map_err(|_| anyhow::anyhow!("Could not set tag "))
            .unwrap()
    }

    pub fn list_tags(&self) -> Result<Vec<String>> {
        self.meta_storage.lock().unwrap().list_tags()
    }
    pub fn remove_tag(&mut self, target_tag: &str, rename_to: Option<&str>) -> Result<()> {
        self.meta_storage
            .lock()
            .unwrap()
            .remove_tag(target_tag)
            .map_err(|e| anyhow::anyhow!("Error {}", e))
            .unwrap();
        self.unspend_outputs()
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
    pub fn set_do_not_spend(&mut self, output: &Output, state: bool) -> Result<bool> {
        let out_point = OutPoint::new(Txid::from_str(&output.tx_id).unwrap(), output.vout);
        self.wallet
            .lock()
            .unwrap()
            .get_utxo(out_point)
            .map(|_| {
                self.meta_storage
                    .lock()
                    .unwrap()
                    .set_do_not_spend(output.get_id().as_str(), state)
                    .map_err(|_| anyhow::anyhow!("Could not set do not spend"))
                    .unwrap();
                Ok(true)
            })
            .unwrap_or(Ok(false))
    }
    //Reveal addresses up to and including the target index and return an iterator of newly revealed addresses.
    pub fn reveal_addresses_up_to(&mut self, keychain: KeychainKind, index: u32) -> Result<()> {
        let _ = self
            .wallet
            .lock()
            .unwrap()
            .reveal_addresses_to(keychain, index);
        self.persist().unwrap();
        Ok(())
    }

    fn is_multisig(&self) -> bool {
        // TODO: if we need to detect non-sorted multisigs or taproot multisigs, we'll need to re-implement desc_type()
        match self.wallet
            .lock()
            .unwrap()
            .public_descriptor(KeychainKind::Internal).desc_type()
        {
            DescriptorType::ShSortedMulti | DescriptorType::WshSortedMulti | DescriptorType::ShWshSortedMulti => true,
            _ => false,
        }
    }

    fn get_all_xfps(&self) -> Vec<String> {
        let mut xfps: Vec<String> = Vec::new();
        self.wallet
            .lock()
            .unwrap()
            .public_descriptor(KeychainKind::Internal)
            .for_each_key(|key| {
                xfps.push(key.master_fingerprint().to_string());
                true
            });
        xfps
    }

    fn get_xfp(&self) -> String {
        // TODO: improve error handling
        self.get_all_xfps()[0].clone()
    }

    fn get_all_derivation_paths(&self) -> Vec<Option<String>> {
        let mut paths: Vec<Option<String>> = Vec::new();
        self.wallet
            .lock()
            .unwrap()
            .public_descriptor(KeychainKind::Internal)
            .for_each_key(|key| {
                paths.push(key.full_derivation_path().map(|path| path.to_string()));
                true
            });
        paths
    }

    fn get_derivation_path(&self) -> String {
        // TODO: improve error handling
        self.get_all_derivation_paths()[0].clone().unwrap()
    }

    pub fn connection_export(&self, mode: ExportMode, target: ExportTarget) -> Result<String> {
        let config = self.meta_storage
            .lock()
            .unwrap()
            .get_config()
            .map_err(|e| anyhow::anyhow!("Could not get config from meta storage: {:?}", e))?
            .unwrap();

        let wallet = self.wallet.lock().unwrap();

        let is_multisig = self.is_multisig();

        match target {
            ExportTarget::Envoy => {
                if is_multisig {
                    return Err(anyhow::anyhow!("Envoy multisig is not supported"));
                }

                Ok(config.serialize())
            }
            ExportTarget::BitcoinCore => {
                if is_multisig {
                    return Err(anyhow::anyhow!("Bitcoin Core multisig is not supported"));
                }

                if mode != ExportMode::File {
                    return Err(anyhow::anyhow!("Bitcoin Core only supports file exports"));
                }

                let xfp = self.get_xfp();

                // TODO: need to capitalize network string
                let chain = config.network.to_string();

                let mut payload: Vec<serde_json::Value> = Vec::new();

                if let Some(external_descriptor) = config.external_descriptor {
                    payload.push(serde_json::json!(
                        {
                            "desc": format!("{}#{}", external_descriptor,  wallet.descriptor_checksum(KeychainKind::External)),
                            "timestamp": "now",
                            "range": [0,1000],
                            "internal": false,
                            "keypool": true,
                            "watchonly": true
                        }
                    ));
                }

                payload.push(serde_json::json!(
                    {
                        "desc": format!("{}#{}", config.internal_descriptor,  wallet.descriptor_checksum(KeychainKind::Internal)),
                        "timestamp": "now",
                        "range": [0,1000],
                        "internal": true,
                        "keypool": true,
                        "watchonly": true
                    }
                ));

                let derivation_path = self.get_derivation_path();

                let addresses = (0..3)
                    .map(|i| format!("{}/{} => {}", derivation_path, i, wallet.peek_address(KeychainKind::External, i).to_string()))
                    .collect::<Vec<String>>()
                    .join("\n");

                Ok(format!(
"# Bitcoin Core Wallet Import File

## For wallet with master key fingerprint: {}

Wallet operates on blockchain: {}

## Bitcoin Core RPC

The following command can be entered after opening Window -> Console
in Bitcoin Core, or using bitcoin-cli:

importmulti '{}'

## Resulting Addresses (first 3)

{}", xfp, chain, serde_json::Value::Array(payload).to_string(), addresses))
            }
            _ => Err(anyhow::anyhow!("TODO")),
        }
    }
}

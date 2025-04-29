use crate::ngwallet::NgWallet;
use anyhow::Result;
use base64::prelude::*;
use bdk_electrum::bdk_core::bitcoin::OutPoint;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Psbt, ScriptBuf, Transaction, Txid};
use bdk_wallet::coin_selection::InsufficientFunds;
use bdk_wallet::error::CreateTxError::CoinSelection;
use bdk_wallet::error::{BuildFeeBumpError, CreateTxError};
use bdk_wallet::miniscript::psbt::PsbtExt;
use bdk_wallet::{KeychainKind, PersistedWallet, SignOptions, TxOrdering, WalletPersister};
use log::info;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::MutexGuard;

use crate::send::BumpFeeError::ComposeTxError;
use crate::transaction::{BitcoinTransaction, Input, KeyChain, Output};
#[cfg(feature = "envoy")]
use {
    bdk_electrum::BdkElectrumClient,
    bdk_electrum::electrum_client::Client,
    bdk_electrum::electrum_client::{Config, Socks5Config},
    bdk_wallet::psbt::PsbtUtils,
};

#[derive(Debug)]
pub enum BumpFeeError {
    InsufficientFunds,
    ComposeBumpTxError(BuildFeeBumpError),
    ComposeTxError(CreateTxError),
    ChangeOutputLocked,
    /// Happens when trying to spend an UTXO that is not in the internal database
    UnknownUtxo(OutPoint),
    /// Thrown when a tx is not found in the internal database
    TransactionNotFound(),
    /// Happens when trying to bump a transaction that is already confirmed
    TransactionConfirmed(Txid),
    /// Trying to replace a tx that has a sequence >= `0xFFFFFFFE`
    IrreplaceableTransaction(Txid),
    /// Node doesn't have data to estimate a fee rate
    FeeRateUnavailable,
}

#[derive(Debug, Clone)]
pub struct DraftTransaction {
    pub transaction: BitcoinTransaction,
    pub psbt_base64: String,
    pub change_out_put_tag: Option<String>,
    pub input_tags: Vec<String>,
    pub is_finalized: bool,
}

#[derive(Debug)]
pub struct TransactionFeeResult {
    pub max_fee_rate: u64,
    pub min_fee_rate: u64,
    pub draft_transaction: DraftTransaction,
}

#[derive(Debug, Clone)]
pub struct TransactionParams {
    pub address: String,
    pub amount: u64,
    pub fee_rate: u64,
    pub selected_outputs: Vec<Output>,
    pub note: Option<String>,
    pub tag: Option<String>,
    pub do_not_spend_change: bool,
}

// TODO: chore: cleanup duplicate code
impl<P: WalletPersister> NgWallet<P> {
    #[cfg(feature = "envoy")]
    pub fn get_max_bump_fee(
        &self,
        selected_outputs: Vec<Output>,
        bitcoin_transaction: BitcoinTransaction,
    ) -> Result<TransactionFeeResult, BumpFeeError> {
        let unspend_outputs = self.unspend_outputs().unwrap();
        let transactions = self.transactions().unwrap();

        //check if transaction is output is locked
        for unspend_output in unspend_outputs.clone() {
            if unspend_output.tx_id == bitcoin_transaction.clone().tx_id
                && unspend_output.do_not_spend
            {
                return Err(BumpFeeError::ChangeOutputLocked);
            }
        }

        let min_fee_rate = bitcoin_transaction.fee_rate + 2;

        let mature_utxos: Vec<Output> = unspend_outputs
            .clone()
            .iter()
            .filter(|output| {
                let tx = transactions
                    .clone()
                    .into_iter()
                    .find(|tx| tx.tx_id == output.tx_id);
                if let Some(tx) = tx {
                    if tx.is_confirmed {
                        return true;
                    }
                }
                false
            })
            .cloned()
            .collect();

        //do not spend
        let mut do_not_spend_utxos: Vec<Output> = vec![];
        let mut spendables: Vec<Output> = vec![];
        Self::filter_spendable_and_do_not_spendables(
            selected_outputs.clone(),
            mature_utxos.clone(),
            &mut do_not_spend_utxos,
            &mut spendables,
        );

        let mut max_fee: Option<u64> = None;

        // TODO: check if clippy is right about this one
        #[allow(unused_assignments)]
        let mut max_fee_rate = 1000;

        let mut tries = 0;
        loop {
            tries += 1;
            if tries > 8 {
                return Err(BumpFeeError::ChangeOutputLocked);
            }
            if max_fee.is_some() {
                //try creating a psbt with max fee
                match self.get_rbf_bump_psbt(
                    selected_outputs.clone(),
                    bitcoin_transaction.clone(),
                    min_fee_rate,
                    max_fee,
                ) {
                    Ok(psbt) => {
                        let mut wallet = self.wallet.lock().unwrap();

                        if let Ok(tx) = psbt.clone().extract_tx() {
                            for tx_out in tx.output {
                                let derivation = wallet.derivation_of_spk(tx_out.script_pubkey);
                                match derivation {
                                    None => {}
                                    Some(path) => {
                                        wallet.unmark_used(path.0, path.1);
                                    }
                                }
                            }
                        }
                        match psbt.fee_rate() {
                            None => {
                                return Err(BumpFeeError::ChangeOutputLocked);
                            }
                            Some(r) => {
                                max_fee_rate = r.to_sat_per_vb_floor();
                                break;
                            }
                        }
                    }
                    Err(e) => match e {
                        ComposeTxError(error) => {
                            if let CoinSelection(erorr) = error {
                                info!(
                                    "Error while composing bump tx {:?} {:?}",
                                    erorr.clone().available.to_sat(),
                                    erorr.clone().needed.to_sat()
                                );
                                max_fee = Some(erorr.available.to_sat());
                                info!("Max fee recalculated: {:?} ", max_fee);
                            } else {
                                return Err(BumpFeeError::ChangeOutputLocked);
                            }
                        }
                        _err => {
                            return Err(_err);
                        }
                    },
                }
                info!("Max fee calculated: {} ", max_fee.unwrap());
            } else {
                match self.get_rbf_bump_psbt(
                    selected_outputs.clone(),
                    bitcoin_transaction.clone(),
                    FeeRate::from_sat_per_vb(max_fee_rate)
                        .unwrap_or(FeeRate::from_sat_per_vb_unchecked(min_fee_rate))
                        .to_sat_per_vb_floor(),
                    None,
                ) {
                    Ok(psbt) => {
                        let mut wallet = self.wallet.lock().unwrap();
                        if let Ok(tx) = psbt.clone().extract_tx() {
                            for tx_out in tx.output {
                                let derivation = wallet.derivation_of_spk(tx_out.script_pubkey);
                                match derivation {
                                    None => {}
                                    Some(path) => {
                                        wallet.unmark_used(path.0, path.1);
                                    }
                                }
                            }
                        }
                        match psbt.fee_rate() {
                            None => {
                                return Err(BumpFeeError::ChangeOutputLocked);
                            }
                            Some(r) => {
                                max_fee_rate = r.to_sat_per_vb_floor();
                                break;
                            }
                        }
                    }
                    Err(e) => match e {
                        ComposeTxError(error) => {
                            if let CoinSelection(erorr) = error {
                                info!(
                                    "Error {:?} {:?}",
                                    erorr.clone().available.to_sat(),
                                    erorr.clone().needed.to_sat()
                                );
                                max_fee = Some(erorr.available.to_sat());
                                info!("max_fee: {:?} ", max_fee);
                            } else {
                                return Err(BumpFeeError::ChangeOutputLocked);
                            }
                        }
                        _err => {
                            return Err(_err);
                        }
                    },
                }
            }
        }
        let tx = self.get_rbf_draft_tx(
            selected_outputs.clone(),
            bitcoin_transaction.clone(),
            min_fee_rate,
        )?;

        Ok(TransactionFeeResult {
            max_fee_rate,
            min_fee_rate,
            draft_transaction: tx,
        })
    }

    pub fn get_rbf_draft_tx(
        &self,
        selected_outputs: Vec<Output>,
        bitcoin_transaction: BitcoinTransaction,
        fee_rate: u64,
    ) -> Result<DraftTransaction, BumpFeeError> {
        let address = bitcoin_transaction.clone().address;

        let change_out_put = bitcoin_transaction.clone().get_change_output();
        let note = bitcoin_transaction.clone().note;

        let change_out_put_tag = change_out_put
            .map(|output| output.tag.clone())
            .unwrap_or(None);
        let tag = if bitcoin_transaction.get_change_output().is_some() {
            bitcoin_transaction.get_change_output().unwrap().tag.clone()
        } else {
            None
        };

        match self.get_rbf_bump_psbt(
            selected_outputs.clone(),
            bitcoin_transaction.clone(),
            fee_rate,
            None,
        ) {
            Ok(psbt) => {
                let unspend_outputs = self.unspend_outputs().unwrap();
                let wallet = self.wallet.lock().unwrap();
                let outputs = Self::apply_meta_to_psbt_outputs(
                    &wallet,
                    selected_outputs.clone(),
                    tag.clone(),
                    false,
                    psbt.clone().unsigned_tx,
                );
                let inputs = Self::apply_meta_to_inputs(
                    &wallet,
                    psbt.clone().unsigned_tx,
                    unspend_outputs.clone(),
                );
                let transaction = Self::transform_psbt_to_bitcointx(
                    psbt.clone(),
                    address.clone().to_string(),
                    psbt.fee_rate()
                        .unwrap_or(FeeRate::from_sat_per_vb_unchecked(fee_rate)),
                    outputs.clone(),
                    inputs.clone(),
                    note.clone(),
                );

                let input_tags: Vec<String> = inputs
                    .clone()
                    .iter()
                    .map(|input| input.tag.clone().unwrap_or("untagged".to_string()))
                    .collect();
                Ok(DraftTransaction {
                    psbt_base64: BASE64_STANDARD.encode(psbt.clone().serialize()).to_string(),
                    is_finalized: psbt.extract(&Secp256k1::verification_only()).is_ok(),
                    input_tags,
                    change_out_put_tag,
                    transaction,
                })
            }
            Err(er) => Err(er),
        }
    }
    fn get_rbf_bump_psbt(
        &self,
        selected_outputs: Vec<Output>,
        bitcoin_transaction: BitcoinTransaction,
        fee_rate: u64,
        fee_absolute: Option<u64>,
    ) -> Result<Psbt, BumpFeeError> {
        let unspend_outputs = self.unspend_outputs().unwrap();
        let transactions = self.transactions().unwrap();
        let mut wallet = self.wallet.lock().unwrap();
        let tx_id = Txid::from_str(bitcoin_transaction.clone().tx_id.as_str())
            .map_err(|_| BumpFeeError::TransactionNotFound())?;
        let mut tx_builder = wallet
            .build_fee_bump(tx_id)
            .map_err(BumpFeeError::ComposeBumpTxError)?;
        let mature_utxos: Vec<Output> = unspend_outputs
            .clone()
            .iter()
            .filter(|output| {
                let tx = transactions
                    .clone()
                    .into_iter()
                    .find(|tx| tx.tx_id == output.tx_id);
                if let Some(tx) = tx {
                    if tx.is_confirmed {
                        return true;
                    }
                }
                false
            })
            .cloned()
            .collect();
        //do not spend
        let mut do_not_spend_utxos: Vec<Output> = vec![];
        let mut spendables: Vec<Output> = vec![];
        Self::filter_spendable_and_do_not_spendables(
            selected_outputs.clone(),
            mature_utxos.clone(),
            &mut do_not_spend_utxos,
            &mut spendables,
        );
        for do_not_spend_utxo in do_not_spend_utxos.clone() {
            tx_builder.add_unspendable(do_not_spend_utxo.get_outpoint());
        }

        if let Some(fee) = fee_absolute {
            tx_builder.fee_absolute(Amount::from_sat(fee));
        } else {
            tx_builder.fee_rate(FeeRate::from_sat_per_vb(fee_rate).unwrap());
        }

        match tx_builder.finish() {
            Ok(mut psbt) => {
                let sign_options = SignOptions {
                    trust_witness_utxo: true,
                    ..Default::default()
                };
                wallet.sign(&mut psbt, sign_options).unwrap_or(false);
                Ok(psbt)
            }
            Err(err) => {
                info!("Error creating PSBT: {:?}", err);
                Err(ComposeTxError(err))
            }
        }
    }
    //noinspection RsExternalLinter
    //noinspection RsExternalLinter
    #[cfg(feature = "envoy")]
    pub fn get_max_fee(
        &self,
        transaction_params: TransactionParams,
    ) -> Result<TransactionFeeResult, CreateTxError> {
        let utxos = self.unspend_outputs().unwrap();
        let mut wallet = self.wallet.lock().unwrap();
        let address = transaction_params.address;
        let tag = transaction_params.tag;
        let default_fee = transaction_params.fee_rate;
        let selected_outputs = transaction_params.selected_outputs;
        let amount = transaction_params.amount;

        let address = Address::from_str(&address)
            .unwrap()
            .require_network(wallet.network())
            .unwrap();
        let script: ScriptBuf = address.clone().into();

        //do not spend
        let mut do_not_spend_utxos: Vec<Output> = vec![];
        let mut spendables: Vec<Output> = vec![];
        Self::filter_spendable_and_do_not_spendables(
            selected_outputs,
            utxos.clone(),
            &mut do_not_spend_utxos,
            &mut spendables,
        );

        let spendable_balance: u64 = spendables.clone().iter().map(|utxo| utxo.amount).sum();

        if amount > spendable_balance {
            return Err(CoinSelection(InsufficientFunds {
                available: Amount::from_sat(spendable_balance),
                needed: Amount::from_sat(spendable_balance.checked_div(amount).unwrap_or(0)),
            }));
        }

        //clippy is wrong about max_fee unused_assignments
        #[allow(unused_assignments)]
        let mut max_fee = spendable_balance - amount;

        //clippy is wrong about  max_fee_rate unused_assignments
        #[allow(unused_assignments)]
        let mut max_fee_rate = 1;

        let mut receive_amount = amount;
        //if user is trying to sweep in order to find the max fee we set receive to min spend…
        //amount which is dust limit
        if spendable_balance == amount {
            receive_amount = 573; //dust limit
        }

        //get absolute max fee from spendable balance
        max_fee = spendable_balance
            .checked_sub(receive_amount)
            .ok_or_else(|| {
                CoinSelection(InsufficientFunds {
                    available: Amount::from_sat(spendable_balance),
                    needed: Amount::from_sat(spendable_balance.saturating_sub(amount)),
                })
            })?;

        loop {
            let psbt = Self::prepare_psbt(
                &mut wallet,
                script.clone(),
                &mut do_not_spend_utxos,
                Some(max_fee),
                None,
                receive_amount,
                false,
            );
            match psbt {
                Ok(mut psbt) => {
                    let sign_options = SignOptions {
                        trust_witness_utxo: true,
                        ..Default::default()
                    };
                    // Always try signing
                    wallet.sign(&mut psbt, sign_options).unwrap_or(false);
                    // reset indexes since this is only for fee calc
                    if let Ok(tx) = psbt.clone().extract_tx() {
                        for tx_out in tx.output {
                            let derivation = wallet.derivation_of_spk(tx_out.script_pubkey);
                            match derivation {
                                None => {}
                                Some(path) => {
                                    wallet.unmark_used(path.0, path.1);
                                }
                            }
                        }
                    }
                    match psbt.fee_rate() {
                        None => {}
                        Some(r) => {
                            max_fee_rate = r.to_sat_per_vb_floor();
                            break;
                        }
                    }
                }
                Err(e) => match e {
                    CoinSelection(erorr) => {
                        max_fee = erorr
                            .available
                            .to_sat()
                            .checked_sub(receive_amount)
                            .ok_or_else(|| {
                                CoinSelection(InsufficientFunds {
                                    available: Amount::from_sat(erorr.available.to_sat()),
                                    needed: Amount::from_sat(receive_amount),
                                })
                            })?
                    }
                    err => {
                        return Err(err);
                    }
                },
            }
        }

        let default_tx_fee = if max_fee_rate > default_fee {
            default_fee
        } else {
            1
        };

        let default_fee_rate = FeeRate::from_sat_per_vb(default_tx_fee)
            .unwrap_or(FeeRate::from_sat_per_vb_unchecked(1));

        let psbt = Self::prepare_psbt(
            &mut wallet,
            script,
            &mut do_not_spend_utxos,
            None,
            Some(default_fee_rate),
            amount,
            amount == spendable_balance,
        );

        match psbt {
            Ok(mut psbt) => {
                let sign_options = SignOptions {
                    trust_witness_utxo: true,
                    ..Default::default()
                };
                // Always try signing
                wallet.sign(&mut psbt, sign_options).unwrap_or(false);
                let outputs = Self::apply_meta_to_psbt_outputs(
                    &wallet,
                    utxos.clone(),
                    tag,
                    false,
                    psbt.clone().unsigned_tx,
                );
                let inputs =
                    Self::apply_meta_to_inputs(&wallet, psbt.clone().unsigned_tx, utxos.clone());
                let transaction = Self::transform_psbt_to_bitcointx(
                    psbt.clone(),
                    address.clone().to_string(),
                    default_fee_rate,
                    outputs.clone(),
                    inputs.clone(),
                    None,
                );
                let mut change_out_put_tag: Option<String> = None;
                for output in transaction.outputs.clone() {
                    if output.keychain == Some(KeyChain::Internal) {
                        change_out_put_tag = output.tag.clone();
                    }
                }
                let input_tags: Vec<String> = inputs
                    .clone()
                    .iter()
                    .map(|input| input.tag.clone().unwrap_or("untagged".to_string()))
                    .collect();

                Ok(TransactionFeeResult {
                    max_fee_rate,
                    min_fee_rate: 1,
                    draft_transaction: DraftTransaction {
                        psbt_base64: BASE64_STANDARD.encode(psbt.clone().serialize()).to_string(),
                        is_finalized: psbt.extract(&Secp256k1::verification_only()).is_ok(),
                        input_tags,
                        change_out_put_tag,
                        transaction,
                    },
                })
            }
            Err(e) => Err(e),
        }
    }
    pub fn compose_psbt(
        &self,
        spend_params: TransactionParams,
    ) -> Result<DraftTransaction, CreateTxError> {
        let address = spend_params.address;
        let amount = spend_params.amount;
        let fee_rate = spend_params.fee_rate;
        let selected_outputs = spend_params.selected_outputs;
        let note = spend_params.note;
        let tag = spend_params.tag;
        let do_not_spend_change = spend_params.do_not_spend_change;

        //get current utxo set and balance
        let utxos = self.unspend_outputs().unwrap();

        // The wallet will be locked for the rest of the spend method,
        // so calling other NgWallet APIs won't succeed.
        let mut wallet = self.wallet.lock().unwrap();

        let address = Address::from_str(&address)
            .unwrap()
            .require_network(wallet.network())
            .unwrap();
        let script: ScriptBuf = address.clone().into();

        //do not spend
        let mut do_not_spend_utxos: Vec<Output> = vec![];
        //spendable utxo pool, the tx builder chooses from this pool
        let mut spendables: Vec<Output> = vec![];
        Self::filter_spendable_and_do_not_spendables(
            selected_outputs,
            utxos.clone(),
            &mut do_not_spend_utxos,
            &mut spendables,
        );

        let mut do_not_spend_amount = 0;

        for do_not_spend_utxo in do_not_spend_utxos.clone() {
            do_not_spend_amount += do_not_spend_utxo.amount;
        }

        let mut spendable_balance: u64 = spendables.clone().iter().map(|utxo| utxo.amount).sum();

        //deduct do_not_spend_amount from main balance,
        //this will be the balance of spendable utxos combined
        if spendable_balance > 0 && do_not_spend_amount < spendable_balance {
            spendable_balance -= do_not_spend_amount
        }

        if amount > spendable_balance {
            return Err(CoinSelection(InsufficientFunds {
                available: Amount::from_sat(spendable_balance),
                needed: Amount::from_sat(spendable_balance.checked_div(amount).unwrap_or(0)),
            }));
        }

        let sweep = amount == spendable_balance;
        let fee_rate =
            FeeRate::from_sat_per_vb(fee_rate).unwrap_or(FeeRate::from_sat_per_vb_unchecked(1));
        let psbt = Self::prepare_psbt(
            &mut wallet,
            script.clone(),
            &mut do_not_spend_utxos,
            None,
            Some(fee_rate),
            amount,
            sweep,
        );

        match psbt {
            Ok(mut psbt) => {
                // Always try signing
                let sign_options = SignOptions {
                    trust_witness_utxo: true,
                    ..Default::default()
                };

                // Always try signing
                let _ = wallet.sign(&mut psbt, sign_options).is_ok();

                //extract outputs from tx and add tags and do_not_spend states
                let outputs = Self::apply_meta_to_psbt_outputs(
                    &wallet,
                    utxos.clone(),
                    tag.clone(),
                    do_not_spend_change,
                    psbt.clone().unsigned_tx,
                );
                let inputs =
                    Self::apply_meta_to_inputs(&wallet, psbt.clone().unsigned_tx, utxos.clone());
                let transaction = Self::transform_psbt_to_bitcointx(
                    psbt.clone(),
                    address.clone().to_string(),
                    fee_rate,
                    outputs.clone(),
                    inputs.clone(),
                    note,
                );

                let mut change_out_put_tag: Option<String> = None;
                for output in transaction.outputs.clone() {
                    if output.keychain == Some(KeyChain::Internal) {
                        change_out_put_tag = output.tag.clone();
                    }
                }

                let input_tags: Vec<String> = inputs
                    .clone()
                    .iter()
                    .map(|input| input.tag.clone().unwrap_or("untagged".to_string()))
                    .collect();

                Ok(DraftTransaction {
                    psbt_base64: BASE64_STANDARD.encode(psbt.clone().serialize()).to_string(),
                    is_finalized: psbt.extract(&Secp256k1::verification_only()).is_ok(),
                    input_tags,
                    change_out_put_tag,
                    transaction,
                })
            }
            Err(e) => {
                println!("Error creating PSBT: {:?}", e);
                info!("Error creating PSBT: {:?}", e);
                Err(e)
            }
        }
    }
    #[cfg(feature = "envoy")]
    pub fn broadcast_psbt(
        spend: DraftTransaction,
        electrum_server: &str,
        socks_proxy: Option<&str>,
    ) -> Result<String> {
        let bdk_client = Self::build_electrum_client(electrum_server, socks_proxy);
        let tx = BASE64_STANDARD
            .decode(spend.psbt_base64)
            .map_err(|e| anyhow::anyhow!("Failed to decode PSBT: {}", e))?;
        let psbt = Psbt::deserialize(tx.as_slice())
            .map_err(|er| anyhow::anyhow!("Failed to deserialize PSBT: {}", er))?;

        let transaction = psbt
            .extract_tx()
            .map_err(|e| anyhow::anyhow!("Failed to extract transaction: {}", e))?;

        let tx_id = bdk_client
            .transaction_broadcast(&transaction)
            .map_err(|e| anyhow::anyhow!("Failed to broadcast transaction: {}", e))?;

        //let tx = spend.transaction;
        Ok(tx_id.to_string())
    }
    #[cfg(feature = "envoy")]
    pub(crate) fn build_electrum_client(
        electrum_server: &str,
        socks_proxy: Option<&str>,
    ) -> BdkElectrumClient<Client> {
        let socks5_config = match socks_proxy {
            Some(socks_proxy) => {
                let socks5_config = Socks5Config::new(socks_proxy);
                Some(socks5_config)
            }
            None => None,
        };
        let electrum_config = Config::builder().socks5(socks5_config.clone()).build();
        let client = Client::from_config(electrum_server, electrum_config).unwrap();
        let bdk_client: BdkElectrumClient<Client> = BdkElectrumClient::new(client);
        bdk_client
    }
    pub fn decode_psbt(
        draft_transaction: DraftTransaction,
        psbt_base64: &str,
    ) -> Result<DraftTransaction> {
        let psbt_bytes = BASE64_STANDARD
            .decode(psbt_base64)
            .map_err(|e| anyhow::anyhow!("Failed to decode PSBT: {}", e))?;
        let psbt = Psbt::deserialize(psbt_bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("Failed to deserialize PSBT: {}", e))?;
        let psbt_finalized = psbt
            .finalize(&Secp256k1::verification_only())
            .map_err(|(_, _)| anyhow::anyhow!("Failed to finalize PSBT"))?;
        Ok(DraftTransaction {
            psbt_base64: BASE64_STANDARD
                .encode(psbt_finalized.clone().serialize())
                .to_string(),
            is_finalized: psbt_finalized
                .extract(&Secp256k1::verification_only())
                .is_ok(),
            input_tags: draft_transaction.input_tags,
            change_out_put_tag: draft_transaction.change_out_put_tag,
            transaction: draft_transaction.transaction,
        })
    }
    pub fn create_send(&mut self, address: String, amount: u64) -> Result<Psbt> {
        let mut wallet = self.wallet.lock().unwrap();
        let address = Address::from_str(&address)
            .unwrap()
            .require_network(wallet.network())
            .unwrap();
        let script: ScriptBuf = address.into();
        let mut builder = wallet.build_tx();
        builder.add_recipient(script.clone(), Amount::from_sat(amount));

        let psbt = builder.finish()?;
        Ok(psbt)
    }

    fn filter_spendable_and_do_not_spendables(
        selected_outputs: Vec<Output>,
        utxos: Vec<Output>,
        do_not_spend_utxos: &mut Vec<Output>,
        spendables: &mut Vec<Output>,
    ) {
        for output in utxos {
            //choose all output that are not selected by the user,
            //this will create a pool of available utxo for tx builder.
            for selected_outputs in selected_outputs.clone() {
                if output.get_id() == selected_outputs.get_id() {
                    spendables.push(output.clone());
                    break;
                }
            }
            if selected_outputs.is_empty() && !output.do_not_spend {
                spendables.push(output.clone());
            }

            if !spendables.contains(&output) {
                do_not_spend_utxos.push(output.clone());
            }
        }
    }

    fn transform_psbt_to_bitcointx(
        psbt: Psbt,
        address: String,
        fee_rate: FeeRate,
        outputs: Vec<Output>,
        inputs: Vec<Input>,
        note: Option<String>,
    ) -> BitcoinTransaction {
        let transaction = psbt.clone().unsigned_tx;

        let mut amount = 0;
        for outputs in outputs.clone() {
            if outputs.address == address {
                amount = -(outputs.amount as i64);
            }
        }

        BitcoinTransaction {
            tx_id: transaction.clone().compute_txid().to_string(),
            block_height: 0,
            confirmations: 0,
            is_confirmed: false,
            fee: psbt.fee().unwrap_or(Amount::from_sat(0)).to_sat(),
            fee_rate: fee_rate.to_sat_per_vb_floor(),
            amount,
            inputs,
            address,
            outputs,
            note,
            date: None,
            vsize: 0,
        }
    }

    fn apply_meta_to_psbt_outputs(
        wallet: &MutexGuard<PersistedWallet<P>>,
        utxos: Vec<Output>,
        tag: Option<String>,
        do_not_spend_change: bool,
        transaction: Transaction,
    ) -> Vec<Output> {
        let change_tag = if tag.is_none() {
            let tags: Vec<String> = transaction
                .input
                .clone()
                .iter()
                .map(|input| {
                    let tx_id = input.clone().previous_output.txid.to_string();
                    let utxo_id = format!("{}:{}", tx_id, input.previous_output.vout).to_string();
                    wallet.get_utxo(input.previous_output).unwrap();
                    let mut tag = "untagged".to_string();
                    for utxo in utxos.clone() {
                        if utxo.get_id() == utxo_id {
                            tag = utxo.tag.unwrap_or("untagged".to_string());
                        }
                    }
                    tag
                })
                .collect();
            let is_input_comes_from_same_tag =
                tags.clone().iter().rev().collect::<HashSet<_>>().len() == 1;

            if is_input_comes_from_same_tag {
                Some(tags[0].clone())
            } else {
                None
            }
        } else {
            tag.clone()
        };
        let outputs = transaction
            .output
            .clone()
            .iter()
            .enumerate()
            .map(|(index, tx_out)| {
                let script = tx_out.script_pubkey.clone();
                let derivation = wallet.derivation_of_spk(script.clone());
                let address = Address::from_script(&script, wallet.network())
                    .unwrap()
                    .to_string();

                let mut out_put_tag: Option<String> = None;
                let mut out_put_do_not_spend_change = false;

                if derivation.is_some() {
                    let path = derivation.unwrap();
                    //if the output belongs to change keychain,
                    if path.0 == KeychainKind::Internal {
                        out_put_tag = change_tag.clone();
                        out_put_do_not_spend_change = do_not_spend_change;
                    }
                }
                //if the output belongs to the wallet
                Output {
                    tx_id: transaction.compute_txid().to_string(),
                    vout: index as u32,
                    address,
                    amount: tx_out.value.to_sat(),
                    tag: out_put_tag,
                    date: None,
                    is_confirmed: false,
                    keychain: derivation.map(|x| {
                        if x.0 == KeychainKind::External {
                            KeyChain::External
                        } else {
                            KeyChain::Internal
                        }
                    }),
                    do_not_spend: out_put_do_not_spend_change,
                }
            })
            .clone()
            .collect::<Vec<Output>>();
        outputs
    }
    fn apply_meta_to_inputs(
        wallet: &MutexGuard<PersistedWallet<P>>,
        transaction: Transaction,
        utxos: Vec<Output>,
    ) -> Vec<Input> {
        transaction
            .input
            .clone()
            .iter()
            .map(|input| {
                let tx_id = input.clone().previous_output.txid.to_string();
                let v_index = input.clone().previous_output.vout;
                let amount = if wallet.get_utxo(input.previous_output).is_some() {
                    wallet
                        .get_utxo(input.previous_output)
                        .unwrap()
                        .txout
                        .value
                        .to_sat()
                } else {
                    let wallet_tx = wallet.get_tx(Txid::from_str(tx_id.clone().as_str()).unwrap());
                    let mut amount = 0;
                    if wallet_tx.is_some() {
                        let tx_node = wallet_tx.unwrap().tx_node;
                        for (index, out) in tx_node.output.iter().enumerate() {
                            if index as u32 == v_index {
                                amount = out.value.to_sat();
                            }
                        }
                    }
                    amount
                };
                let mut tag: Option<String> = None;
                for utxo in utxos.clone() {
                    if utxo.get_id() == format!("{}:{}", tx_id, input.previous_output.vout) {
                        tag = utxo.tag;
                    }
                }

                Input {
                    tx_id,
                    vout: input.previous_output.vout,
                    amount,
                    tag,
                }
            })
            .collect()
    }

    fn prepare_psbt(
        wallet: &mut MutexGuard<PersistedWallet<P>>,
        script: ScriptBuf,
        do_not_spend_utxos: &mut [Output],
        fee_absolute: Option<u64>,
        fee_rate: Option<FeeRate>,
        receive_amount: u64,
        sweep: bool,
    ) -> Result<Psbt, CreateTxError> {
        let mut builder = wallet.build_tx();
        builder.ordering(TxOrdering::Shuffle);
        for do_not_spend_utxo in do_not_spend_utxos.iter().clone() {
            builder.add_unspendable(do_not_spend_utxo.get_outpoint());
        }
        if sweep {
            info!("drain_to ");
            builder.drain_wallet();
            builder.drain_to(script.clone());
        } else {
            info!("add_recipient ");
            builder.add_recipient(script.clone(), Amount::from_sat(receive_amount));
        }

        if let Some(fee_absolute) = fee_absolute {
            builder.fee_absolute(Amount::from_sat(fee_absolute));
        }

        if let Some(fee_rate) = fee_rate {
            builder.fee_rate(fee_rate);
        }

        builder.finish()
    }
}

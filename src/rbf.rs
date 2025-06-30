use crate::account::NgAccount;
use crate::ngwallet::NgWallet;
use crate::rbf::BumpFeeError::ComposeTxError;
use anyhow::Result;
use bdk_electrum::bdk_core::bitcoin::{Network, ScriptBuf};
use bdk_wallet::bitcoin::policy::DEFAULT_INCREMENTAL_RELAY_FEE;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, OutPoint, Psbt, Txid};
use bdk_wallet::error::CreateTxError::CoinSelection;
use bdk_wallet::error::{BuildFeeBumpError, CreateTxError};
use bdk_wallet::miniscript::psbt::PsbtExt;
use bdk_wallet::psbt::PsbtUtils;
use bdk_wallet::{AddForeignUtxoError, AddressInfo, KeychainKind, SignOptions, WalletPersister};
use log::info;
use std::str::FromStr;

use crate::send::{DraftTransaction, TransactionFeeResult};
use crate::transaction::{BitcoinTransaction, Input, KeyChain, Output};

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
    UnableToAccessWallet,
    UnableToAddForeignUtxo(AddForeignUtxoError),
}

// TODO: chore: cleanup duplicate code
impl<P: WalletPersister> NgAccount<P> {
    fn get_address(&self, key_chain: KeychainKind) -> AddressInfo {
        self.get_coordinator_wallet()
            .bdk_wallet
            .lock()
            .unwrap()
            .reveal_next_address(key_chain)
    }

    #[cfg(feature = "envoy")]
    pub fn compose_cancellation_tx(
        &self,
        original_transaction: BitcoinTransaction,
    ) -> Result<DraftTransaction, BumpFeeError> {
        let unspend_outputs = self.utxos().unwrap();
        let transactions = self.transactions().unwrap();
        let tx_id = Txid::from_str(original_transaction.tx_id.as_str())
            .map_err(|_| BumpFeeError::TransactionNotFound())?;

        let cancel_destination_address = self.get_address(KeychainKind::Internal);

        let original_utxos: Vec<OutPoint> = vec![];

        let wallet_index = Self::find_outgoing_wallet_index(&self.wallets, tx_id);
        let Ok(mut wallet) = self
            .wallets
            .get(wallet_index)
            .ok_or(BumpFeeError::UnableToAccessWallet)?
            .bdk_wallet
            .lock()
        else {
            return Err(BumpFeeError::UnableToAccessWallet);
        };

        let Some(original_local_tx) = wallet.get_tx(tx_id) else {
            return Err(BumpFeeError::TransactionNotFound());
        };
        let original_tx_weight_vb = original_local_tx.tx_node.vsize();

        let mut builder = wallet
            .build_fee_bump(tx_id)
            .map_err(BumpFeeError::ComposeBumpTxError)?;

        builder.add_utxos(&original_utxos).map_err(|_| {
            BumpFeeError::UnknownUtxo(OutPoint {
                txid: Txid::from_str(original_transaction.tx_id.as_str()).unwrap(),
                vout: 0,
            })
        })?;

        let unconfirmed_utxos: Vec<Output> = unspend_outputs
            .clone()
            .iter()
            .filter(|output| {
                let tx = transactions
                    .clone()
                    .into_iter()
                    .find(|tx| tx.tx_id == output.tx_id);
                if let Some(tx) = tx {
                    if !tx.is_confirmed {
                        return true;
                    }
                }
                false
            })
            .cloned()
            .collect();

        //all the unconfirmed utxos that are not part of the transaction
        //these utxos will be marked as unspendable,
        //so the builder wont pick any inputs from unconfirmed utxos
        for unconfirmed_utxo in unconfirmed_utxos {
            if unconfirmed_utxo.tx_id != original_transaction.tx_id {
                builder.add_unspendable(unconfirmed_utxo.get_outpoint());
            }
        }
        //remove all existing outputs from the RBF transaction
        builder.set_recipients(vec![]);

        //add internal address as a recipient, all the inputs will be
        //drained to this address
        builder.drain_to(cancel_destination_address.script_pubkey());

        let rbf_fee =
            ((original_tx_weight_vb as u64) * (DEFAULT_INCREMENTAL_RELAY_FEE as u64)) / 1000;
        //higher fee and fee_absolute rate to replace original transaction
        builder.fee_absolute(Amount::from_sat(original_transaction.fee + rbf_fee));

        match builder.finish() {
            Ok(mut psbt) => {
                wallet
                    .sign(&mut psbt, SignOptions::default())
                    .unwrap_or(false);
                //reset indexes, indexes will be updated once user broadcasts the tx
                wallet.cancel_tx(&psbt.unsigned_tx);

                let inputs = Self::apply_meta_to_inputs(
                    &wallet,
                    &self.non_coordinator_wallets(),
                    psbt.clone().unsigned_tx,
                    unspend_outputs.clone(),
                );

                let transaction = psbt
                    .clone()
                    .extract_tx()
                    .map_err(|_| BumpFeeError::TransactionNotFound())?;

                let new_outputs: Vec<Output> = transaction
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
                        let out_put_tag: Option<String> =
                            original_transaction.clone().get_change_tag();
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
                            do_not_spend: false,
                        }
                    })
                    .collect::<Vec<Output>>();
                let transaction = BitcoinTransaction {
                    tx_id: transaction.clone().compute_txid().to_string(),
                    block_height: 0,
                    confirmations: 0,
                    is_confirmed: false,
                    fee: psbt.fee().unwrap_or(Amount::from_sat(0)).to_sat(),
                    fee_rate: psbt.fee_rate().unwrap().to_sat_per_vb_floor(),
                    //amount will be zero for cancellation.
                    amount: 0,
                    inputs,
                    address: cancel_destination_address.address.to_string(),
                    outputs: new_outputs,
                    note: original_transaction.note.clone(),
                    date: None,
                    vsize: 0,
                };

                Ok(DraftTransaction {
                    psbt: psbt.clone().serialize(),
                    is_finalized: psbt.extract(&Secp256k1::verification_only()).is_ok(),
                    input_tags: vec![],
                    change_out_put_tag: None,
                    transaction,
                })
            }
            Err(err) => {
                info!("Error creating PSBT: {:?}", err);
                Err(ComposeTxError(err))
            }
        }
    }

    #[cfg(feature = "envoy")]
    pub fn get_max_bump_fee(
        &self,
        selected_outputs: Vec<Output>,
        bitcoin_transaction: BitcoinTransaction,
    ) -> Result<TransactionFeeResult, BumpFeeError> {
        let unspend_outputs = self.utxos().unwrap();
        //check if transaction is output is locked
        for unspend_output in unspend_outputs.clone() {
            if unspend_output.tx_id == bitcoin_transaction.clone().tx_id
                && unspend_output.do_not_spend
            {
                return Err(BumpFeeError::ChangeOutputLocked);
            }
        }

        let min_fee_rate = bitcoin_transaction.fee_rate + 2;

        //do not spend
        let mut max_fee: Option<u64> = None;

        // TODO: check if clippy is right about this one
        #[allow(unused_assignments)]
        let mut max_fee_rate = 1000;

        let mut tries = 0;
        loop {
            tries += 1;
            if tries > 8 {
                return Err(BumpFeeError::FeeRateUnavailable);
            }
            if max_fee.is_some() {
                //try creating a psbt with max fee
                match self.get_rbf_bump_psbt(
                    selected_outputs.clone(),
                    bitcoin_transaction.clone(),
                    min_fee_rate,
                    max_fee,
                ) {
                    Ok(psbt) => match psbt.fee_rate() {
                        None => {
                            return Err(BumpFeeError::ChangeOutputLocked);
                        }
                        Some(r) => {
                            max_fee_rate = r.to_sat_per_vb_floor();
                            break;
                        }
                    },
                    Err(e) => match e {
                        ComposeTxError(error) => {
                            if let CoinSelection(error) = error {
                                info!(
                                    "Error while composing bump tx {:?} {:?}",
                                    error.clone().available.to_sat(),
                                    error.clone().needed.to_sat()
                                );
                                max_fee = Some(
                                    error.available.to_sat()
                                        - (bitcoin_transaction.amount.unsigned_abs()),
                                );
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
                    Ok(psbt) => match psbt.fee_rate() {
                        None => {
                            return Err(BumpFeeError::ChangeOutputLocked);
                        }
                        Some(r) => {
                            max_fee_rate = r.to_sat_per_vb_floor();
                            break;
                        }
                    },
                    Err(e) => match e {
                        ComposeTxError(error) => {
                            if let CoinSelection(error) = error {
                                info!(
                                    "Error {:?} {:?}",
                                    error.clone().available.to_sat(),
                                    error.clone().needed.to_sat()
                                );
                                max_fee = Some(error.available.to_sat());
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
            None,
            None,
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
        current_transaction: BitcoinTransaction,
        fee_rate: u64,
        note: Option<String>,
        tag: Option<String>,
    ) -> Result<DraftTransaction, BumpFeeError> {
        let address = current_transaction.clone().address;
        let change_out_put = current_transaction.clone().get_change_output();
        let mut rbf_note = current_transaction.clone().note;
        if note.is_some() {
            rbf_note = note.clone();
        }

        let mut change_out_put_tag = change_out_put
            .map(|output| output.tag.clone())
            .unwrap_or(None);
        if tag.is_some() {
            change_out_put_tag = tag.clone()
        }
        match self.get_rbf_bump_psbt(
            selected_outputs.clone(),
            current_transaction.clone(),
            fee_rate,
            None,
        ) {
            Ok(psbt) => {
                let transactions = self.transactions().unwrap();

                let transaction = psbt
                    .clone()
                    .extract_tx()
                    .map_err(|_| BumpFeeError::TransactionNotFound())?;

                //map new outputs to the transaction
                let new_outputs: Vec<Output> = transaction
                    .output
                    .clone()
                    .iter()
                    .enumerate()
                    .map(|(index, tx_out)| {
                        let script = tx_out.script_pubkey.clone();
                        let derivation = self.derivation_of_spk(script.clone());
                        let address = Address::from_script(&script, self.network())
                            .unwrap()
                            .to_string();
                        let mut out_put_tag: Option<String> = change_out_put_tag.clone();
                        let mut out_put_do_not_spend_change = false;
                        if derivation.is_some() {
                            let path = derivation.unwrap();
                            //if the output belongs to change keychain,
                            if path.0 == KeychainKind::Internal {
                                out_put_tag = current_transaction.get_change_tag();
                                out_put_do_not_spend_change = false;
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
                    .collect::<Vec<Output>>();

                let inputs = transaction
                    .input
                    .clone()
                    .iter()
                    .map(|input| {
                        let utxo_tx = transactions
                            .clone()
                            .into_iter()
                            .find(|tx| tx.tx_id == input.previous_output.txid.to_string())
                            .unwrap();
                        let out = utxo_tx
                            .outputs
                            .clone()
                            .into_iter()
                            .find(|tx| tx.vout == input.previous_output.vout)
                            .unwrap();

                        let script = input.script_sig.clone();
                        let derivation = self.derivation_of_spk(script.clone());
                        let mut input_tag: Option<String> = None;
                        if derivation.is_some() {
                            let path = derivation.unwrap();
                            //if the output belongs to change keychain,
                            if path.0 == KeychainKind::Internal {
                                input_tag = current_transaction.get_change_tag();
                            }
                        }
                        Input {
                            tx_id: input.previous_output.txid.to_string(),
                            vout: input.previous_output.vout,
                            amount: out.amount,
                            tag: input_tag,
                        }
                    })
                    .collect::<Vec<Input>>();

                let transaction = Self::transform_psbt_to_bitcointx(
                    psbt.clone(),
                    address.clone().to_string(),
                    psbt.fee_rate()
                        .unwrap_or(FeeRate::from_sat_per_vb_unchecked(fee_rate)),
                    new_outputs.clone(),
                    inputs.clone(),
                    rbf_note.clone(),
                );

                let input_tags: Vec<String> = inputs
                    .clone()
                    .iter()
                    .map(|input| input.tag.clone().unwrap_or("untagged".to_string()))
                    .collect();

                Ok(DraftTransaction {
                    psbt: psbt.clone().serialize(),
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
        let unspend_outputs = self.utxos().unwrap();
        let transactions = self.transactions().unwrap();
        let tx_id = Txid::from_str(bitcoin_transaction.clone().tx_id.as_str())
            .map_err(|_| BumpFeeError::TransactionNotFound())?;

        let wallet_index = Self::find_outgoing_wallet_index(&self.wallets, tx_id);

        let psbt = {
            let coordinator_wallet = self
                .wallets
                .get(wallet_index)
                .ok_or(BumpFeeError::UnableToAccessWallet)?;
            let mut bdk_wallet = coordinator_wallet
                .bdk_wallet
                .lock()
                .map_err(|_| BumpFeeError::UnableToAccessWallet)?;
            let mut tx_builder = bdk_wallet
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
                        return tx.is_confirmed;
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

            for spendable_utxo in spendables {
                let outpoint = spendable_utxo.get_outpoint();
                //find all wallets that doesnt include current tx_id
                let non_coordinator_wallets: Vec<&NgWallet<P>> = self
                    .wallets
                    .iter()
                    .enumerate()
                    .filter(|(idx, _)| *idx != wallet_index)
                    .map(|(_, w)| w)
                    .collect();

                match self.get_utxo_input(&spendable_utxo, non_coordinator_wallets) {
                    None => {}
                    Some((input, weight)) => {
                        tx_builder
                            .add_foreign_utxo(outpoint, input, weight)
                            .map_err(BumpFeeError::UnableToAddForeignUtxo)?;
                    }
                }
            }
            if let Some(fee) = fee_absolute {
                tx_builder.fee_absolute(Amount::from_sat(fee));
            } else {
                tx_builder.fee_rate(FeeRate::from_sat_per_vb(fee_rate).unwrap());
            }
            tx_builder.finish()
        };
        match psbt {
            Ok(mut psbt) => {
                let sign_options = SignOptions {
                    trust_witness_utxo: true,
                    ..Default::default()
                };
                Self::sign_psbt(self.wallets.iter().collect(), &mut psbt, sign_options);
                self.cancel_tx(psbt.clone()).unwrap();
                Ok(psbt)
            }
            Err(err) => {
                info!("Error creating PSBT: {:?}", err);
                Err(ComposeTxError(err))
            }
        }
    }

    fn derivation_of_spk(&self, script_buf: ScriptBuf) -> Option<(KeychainKind, u32)> {
        for ng_wallets in self.wallets.iter() {
            let wallet = ng_wallets.bdk_wallet.lock().unwrap();
            if let Some(derivation) = wallet.derivation_of_spk(script_buf.clone()) {
                return Some(derivation);
            }
        }
        None
    }
    fn network(&self) -> Network {
        for ng_wallets in self.wallets.iter() {
            if let Ok(bdk_wallet) = ng_wallets.bdk_wallet.lock() {
                return bdk_wallet.network();
            }
        }
        Network::Bitcoin
    }

    //finds the wallet index that has sent the transaction
    //user can make self-transfers with internal wallets
    //for fee bump, wallet that sent the transaction is used
    fn find_outgoing_wallet_index(wallets: &[NgWallet<P>], tx_id: Txid) -> usize {
        let mut wallet_index = 0;
        for (index, wallet) in wallets.iter().enumerate() {
            let wallet = wallet.bdk_wallet.lock().unwrap();
            let tx = wallet.get_tx(tx_id);
            if let Some(tx) = tx {
                let (sent, received) = wallet.sent_and_received(&tx.tx_node.tx);
                let amount: i64 = (received.to_sat() as i64) - (sent.to_sat() as i64);
                if amount < 0 {
                    wallet_index = index;
                }
                break;
            }
        }
        wallet_index
    }
}

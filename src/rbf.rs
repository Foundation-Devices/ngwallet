use crate::account::NgAccount;
use crate::ngwallet::NgWallet;
use crate::rbf::BumpFeeError::ComposeTxError;
use crate::send::DraftTransaction;
#[cfg(feature = "envoy")]
use crate::send::TransactionFeeResult;
use crate::transaction::{BitcoinTransaction, Input, KeyChain, Output};
use anyhow::Result;
#[cfg(feature = "envoy")]
use bdk_core::bitcoin::policy::DEFAULT_INCREMENTAL_RELAY_FEE;
use bdk_core::bitcoin::{Network, ScriptBuf};
#[cfg(feature = "envoy")]
use bdk_wallet::AddressInfo;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, OutPoint, Psbt, Sequence, Txid};
#[cfg(feature = "envoy")]
use bdk_wallet::error::CreateTxError::CoinSelection;
use bdk_wallet::error::{BuildFeeBumpError, CreateTxError};
use bdk_wallet::miniscript::psbt::PsbtExt;
use bdk_wallet::psbt::PsbtUtils;
use bdk_wallet::{AddForeignUtxoError, KeychainKind, SignOptions, WalletPersister};
use log::info;
use std::str::FromStr;

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
    #[cfg(feature = "envoy")]
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
        let cancel_destination_address = self.get_address(KeychainKind::Internal);
        let unspend_outputs = self.utxos().unwrap();
        //check if transaction is output is locked
        for unspend_output in unspend_outputs.clone() {
            if unspend_output.tx_id == original_transaction.clone().tx_id
                && unspend_output.do_not_spend
            {
                return Err(BumpFeeError::ChangeOutputLocked);
            }
        }
        let min_sats_per_vb = Self::get_minimum_rbf_fee_rate(&original_transaction);
        self.get_rbf_draft_tx(
            vec![],
            original_transaction.clone(),
            min_sats_per_vb,
            None,
            Some(cancel_destination_address.clone().address),
            original_transaction.clone().get_change_tag(),
            original_transaction.clone().note.clone(),
        )
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

        let min_sats_per_vb = Self::get_minimum_rbf_fee_rate(&bitcoin_transaction);

        let mut receive_amount = bitcoin_transaction.amount.unsigned_abs();

        //self spend
        if bitcoin_transaction.fee == (bitcoin_transaction.amount.unsigned_abs()) {
            for output in bitcoin_transaction.clone().outputs {
                match output.keychain {
                    None => {}
                    Some(keychain) => {
                        if keychain == KeyChain::External {
                            receive_amount = output.amount;
                        }
                    }
                }
            }
        }

        // will keep updating until the maximum fee boundary is found
        let mut max_fee: Option<u64> = None;

        // sets max fee rate to 1000 sats/vB.
        // this will eventually fail, and the error will reveal the available amount.
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
                    //placeholder since max_fee will be used
                    1,
                    max_fee,
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
                        ComposeTxError(error) => match error {
                            CreateTxError::FeeTooLow { required } => {
                                max_fee = Some(required.to_sat());
                            }
                            CreateTxError::FeeRateTooLow { required } => {
                                max_fee_rate = required.to_sat_per_vb_ceil() + 1;
                                max_fee = None;
                            }
                            CoinSelection(error) => {
                                info!(
                                    "Error while composing bump tx {:?} {:?}",
                                    error.clone().available.to_sat(),
                                    error.clone().needed.to_sat()
                                );
                                max_fee = Some(error.available.to_sat() - (receive_amount));
                            }
                            _ => {
                                return Err(ComposeTxError(error));
                            }
                        },
                        _err => {
                            return Err(_err);
                        }
                    },
                }
                info!("Max fee set to: {} ", max_fee.unwrap());
            } else {
                //use minimum
                match self.get_rbf_bump_psbt(
                    selected_outputs.clone(),
                    bitcoin_transaction.clone(),
                    FeeRate::from_sat_per_vb(max_fee_rate)
                        .unwrap_or(FeeRate::from_sat_per_vb_unchecked(min_sats_per_vb))
                        .to_sat_per_vb_floor(),
                    None,
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
                        ComposeTxError(error) => match error {
                            CreateTxError::FeeTooLow { required } => {
                                max_fee = Some(required.to_sat());
                            }
                            CreateTxError::FeeRateTooLow { required } => {
                                max_fee_rate = required.to_sat_per_vb_ceil() + 1;
                                max_fee = None;
                            }
                            CoinSelection(error) => {
                                max_fee = Some(
                                    error.available.to_sat()
                                        - (receive_amount + bitcoin_transaction.fee),
                                );
                                info!("Max fee set to: {} ", max_fee.unwrap());
                            }
                            _ => {
                                return Err(ComposeTxError(error));
                            }
                        },
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
            min_sats_per_vb,
            None,
            None,
            bitcoin_transaction.get_change_tag(),
            bitcoin_transaction.note.clone(),
        )?;

        Ok(TransactionFeeResult {
            max_fee_rate,
            min_fee_rate: tx.transaction.fee_rate,
            draft_transaction: tx,
        })
    }

    //Todo: grouping parameters to RBFParams?
    #[allow(clippy::too_many_arguments)]
    pub fn get_rbf_draft_tx(
        &self,
        selected_outputs: Vec<Output>,
        current_transaction: BitcoinTransaction,
        fee_rate: u64,
        fee_absolute: Option<u64>,
        drain_to: Option<Address>,
        tag: Option<String>,
        note: Option<String>,
    ) -> Result<DraftTransaction, BumpFeeError> {
        let address = if drain_to.is_some() {
            drain_to.clone().unwrap().to_string()
        } else {
            current_transaction.clone().address
        };

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
            fee_absolute,
            drain_to.clone(),
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
                        if let Some(path) = derivation {
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
                        if let Some(path) = derivation {
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
                    current_transaction.account_id.clone(),
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
        drain_to: Option<Address>,
    ) -> Result<Psbt, BumpFeeError> {
        let unspend_outputs = self.utxos().unwrap();
        let transactions = self.transactions().unwrap();
        let tx_id = Txid::from_str(bitcoin_transaction.clone().tx_id.as_str())
            .map_err(|_| BumpFeeError::TransactionNotFound())?;

        let wallets = self.wallets.read().unwrap();
        let wallet_index = Self::find_outgoing_wallet_index(&wallets, tx_id);

        let psbt = {
            let coordinator_wallet = wallets
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
            let draining = drain_to.is_some();

            if draining {
                info!("Draining to address: {:?}", drain_to.clone());
                tx_builder.set_recipients(vec![]);
                tx_builder.drain_to(drain_to.clone().unwrap().script_pubkey());
            }
            //if user trying to drain inputs to a specific address
            if !draining {
                for spendable_utxo in spendables {
                    let outpoint = spendable_utxo.get_outpoint();
                    //find all wallets that doesnt include current tx_id
                    let non_coordinator_wallets: Vec<NgWallet<P>> = wallets
                        .iter()
                        .enumerate()
                        .filter(|(idx, _)| *idx != wallet_index)
                        .map(|(_, w)| w.clone())
                        .collect();

                    match self.get_utxo_input(&spendable_utxo, non_coordinator_wallets) {
                        None => {}
                        Some((input, weight)) => {
                            tx_builder
                                .add_foreign_utxo_with_sequence(
                                    outpoint,
                                    input,
                                    weight,
                                    Sequence::ENABLE_RBF_NO_LOCKTIME,
                                )
                                .map_err(BumpFeeError::UnableToAddForeignUtxo)?;
                        }
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
                Self::sign_psbt(self.wallets.read().unwrap().clone(), &mut psbt, sign_options);
                self.cancel_tx(psbt.clone()).unwrap();
                Ok(psbt)
            }
            Err(err) => {
                info!("Error creating PSBT: {err:?}");
                Err(ComposeTxError(err))
            }
        }
    }

    fn derivation_of_spk(&self, script_buf: ScriptBuf) -> Option<(KeychainKind, u32)> {
        for ng_wallets in self.wallets.read().unwrap().iter() {
            let wallet = ng_wallets.bdk_wallet.lock().unwrap();
            if let Some(derivation) = wallet.derivation_of_spk(script_buf.clone()) {
                return Some(derivation);
            }
        }
        None
    }
    fn network(&self) -> Network {
        for ng_wallets in self.wallets.read().unwrap().iter() {
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

    #[cfg(feature = "envoy")]
    fn get_minimum_rbf_fee_rate(transaction: &BitcoinTransaction) -> u64 {
        let original_fee = transaction.fee; // fee is sats
        let original_vsize = transaction.vsize as u64;
        let relay_fee_per_vb = (DEFAULT_INCREMENTAL_RELAY_FEE / 1000) as u64; // 1 sats/vb

        // calculate the minimum additional fee for RBF
        let min_additional_fee = original_vsize * relay_fee_per_vb;
        let min_replacement_fee = original_fee + min_additional_fee;
        let mut min_sats_per_vb = min_replacement_fee.div_ceil(original_vsize);

        // Sanity check: ensure the fee rate meets or exceeds the network minimum
        // If the transaction paid 1 sat/vb,
        // the replacement should be at least 2 (relay_fee_per_vb + 2),
        min_sats_per_vb = min_sats_per_vb.max(relay_fee_per_vb + 2);

        // maybe if there is edge cases. the final RBF size can
        // very if the builder includes too many inputs to cover the RBF
        // min_sats_per_vb +=1;

        min_sats_per_vb
    }
}

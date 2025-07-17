use crate::ngwallet::NgWallet;
use crate::transaction::{BitcoinTransaction, Input, KeyChain, Output};
use anyhow::{Context, Result};
use bdk_core::bitcoin::Sequence;
use bdk_wallet::bitcoin::psbt::ExtractTxError;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{
    Address, Amount, FeeRate, Psbt, ScriptBuf, Transaction, TxIn, Txid, Weight, psbt,
};
use bdk_wallet::coin_selection::InsufficientFunds;
use bdk_wallet::error::CreateTxError;
use bdk_wallet::error::CreateTxError::CoinSelection;
use bdk_wallet::miniscript::psbt::PsbtExt;
use bdk_wallet::psbt::PsbtUtils;
use bdk_wallet::{KeychainKind, PersistedWallet, SignOptions, TxOrdering, WalletPersister};
use core::fmt;
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::MutexGuard;

use crate::account::NgAccount;
#[cfg(feature = "envoy")]
use crate::utils;
#[cfg(feature = "envoy")]
use bdk_electrum::electrum_client::Error;

/// from bdk_wallet
/// From [`FeeRate`], the maximum fee rate that is used for extracting transactions.
/// The default `max_fee_rate` value used for extracting transactions with [`extract_tx`]
///
/// As of 2023, even the biggest overpayers during the highest fee markets only paid around
/// 1000 sats/vByte. 25k sats/vByte is obviously a mistake at this point.
pub const DEFAULT_MAX_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(25_000);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DraftTransaction {
    pub transaction: BitcoinTransaction,
    pub psbt: Vec<u8>,
    pub change_out_put_tag: Option<String>,
    pub input_tags: Vec<String>,
    pub is_finalized: bool,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug)]
pub enum TransactionComposeError {
    CreateTxError(CreateTxError),
    WalletError(String),
    Error(String),
}

impl fmt::Display for TransactionComposeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionComposeError::CreateTxError(e) => write!(f, "CreateTxError: {e}"),
            TransactionComposeError::WalletError(e) => write!(f, "WalletError: {e}"),
            TransactionComposeError::Error(e) => write!(f, "Error: {e}"),
        }
    }
}

// TODO: chore: cleanup duplicate code
impl<P: WalletPersister> NgAccount<P> {
    //noinspection RsExternalLinter
    pub fn get_max_fee(
        &self,
        transaction_params: TransactionParams,
    ) -> Result<TransactionFeeResult, TransactionComposeError> {
        let utxos = self
            .utxos()
            .map_err(|e| TransactionComposeError::Error(format!("Failed to get UTXOs: {e:?}")))?;
        let mut coordinator_wallet = self
            .get_coordinator_wallet()
            .bdk_wallet
            .lock()
            .map_err(|_| TransactionComposeError::WalletError("Failed to lock wallet".into()))?;
        let param = transaction_params.clone();
        let address = param.address;
        let default_fee = param.fee_rate;
        let selected_outputs = param.selected_outputs;
        let amount = param.amount;

        let address = Address::from_str(&address)
            .map_err(|_| TransactionComposeError::Error("Invalid address format".into()))?
            .require_network(coordinator_wallet.network())
            .map_err(|_| TransactionComposeError::Error("Address network mismatch".into()))?;
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

        if spendables.is_empty() {
            return Err(TransactionComposeError::Error(
                "No spendable outputs available".into(),
            ));
        }

        let spendable_balance: u64 = spendables.clone().iter().map(|utxo| utxo.amount).sum();

        if amount > spendable_balance {
            return Err(TransactionComposeError::CreateTxError(CoinSelection(
                InsufficientFunds {
                    available: Amount::from_sat(spendable_balance),
                    needed: Amount::from_sat(amount),
                },
            )));
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

        // Fix 4: Use saturating_sub to prevent underflow
        max_fee = spendable_balance.saturating_sub(receive_amount);
        if max_fee == 0 {
            return Err(TransactionComposeError::Error(
                "Insufficient funds for fee calculation".into(),
            ));
        }

        // Add a maximum iteration count to prevent infinite loops
        let mut iterations = 0;
        let max_iterations = 20;

        loop {
            iterations += 1;
            if iterations > max_iterations {
                return Err(TransactionComposeError::Error(
                    "Failed to calculate maximum fee rate after maximum iterations".into(),
                ));
            }

            let psbt = self.prepare_psbt(
                &mut coordinator_wallet,
                script.clone(),
                &mut spendables,
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
                        try_finalize: true,
                        ..Default::default()
                    };
                    // Always try signing
                    let _ = coordinator_wallet
                        .sign(&mut psbt, sign_options.clone())
                        .is_ok();
                    coordinator_wallet.cancel_tx(&psbt.clone().unsigned_tx);
                    Self::sign_psbt(
                        self.non_coordinator_wallets(),
                        &mut psbt,
                        sign_options.clone(),
                    );

                    match psbt.clone().extract_tx_fee_rate_limit() {
                        Ok(..) => {
                            max_fee_rate = psbt
                                .fee_rate()
                                .unwrap_or(FeeRate::from_sat_per_vb_unchecked(1))
                                .to_sat_per_vb_floor();
                            if max_fee_rate < 1 {
                                max_fee_rate = 1;
                            }
                            break;
                        }
                        Err(error) => match error {
                            ExtractTxError::AbsurdFeeRate { .. } => {
                                max_fee_rate = DEFAULT_MAX_FEE_RATE.to_sat_per_vb_floor();
                                break;
                            }
                            ExtractTxError::MissingInputValue { .. } => {
                                max_fee_rate = psbt
                                    .fee_rate()
                                    .unwrap_or(FeeRate::from_sat_per_vb_unchecked(1))
                                    .to_sat_per_vb_floor();
                                break;
                            }
                            ExtractTxError::SendingTooMuch { psbt } => {
                                max_fee_rate = psbt
                                    .fee_rate()
                                    .unwrap_or(FeeRate::from_sat_per_vb_unchecked(1))
                                    .to_sat_per_vb_floor();
                                break;
                            }
                            _er => {
                                info!("Error calculating fee rate: {_er:?}");
                                max_fee = max_fee.saturating_sub(receive_amount);
                                if max_fee == 0 {
                                    return Err(TransactionComposeError::Error(
                                        "Cannot calculate fee: available amount too low".into(),
                                    ));
                                }
                            }
                        },
                    }
                    if let Some(r) = psbt.fee_rate() {
                        max_fee_rate = r.to_sat_per_vb_floor();
                        // Fix 6: Ensure max_fee_rate is at least 1
                        if max_fee_rate < 1 {
                            max_fee_rate = 1;
                        }
                        break;
                    }
                }
                Err(e) => match e {
                    CoinSelection(error) => {
                        max_fee = error.available.to_sat().saturating_sub(receive_amount);
                        if max_fee == 0 {
                            return Err(TransactionComposeError::Error(
                                "Cannot calculate fee: available amount too low".into(),
                            ));
                        }
                    }
                    err => {
                        info!("Create tx error: {err:?}");
                        return Err(TransactionComposeError::CreateTxError(err));
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

        let psbt = self.prepare_psbt(
            &mut coordinator_wallet,
            script,
            &mut spendables,
            &mut do_not_spend_utxos,
            None,
            Some(default_fee_rate),
            amount,
            amount == spendable_balance,
        );

        match psbt {
            Ok(psbt) => {
                let draft_transaction = self.prepare_draft_transaction(
                    psbt,
                    &mut coordinator_wallet,
                    utxos.clone(),
                    transaction_params.clone(),
                    default_fee_rate,
                );

                Ok(TransactionFeeResult {
                    max_fee_rate,
                    min_fee_rate: 1,
                    draft_transaction,
                })
            }
            Err(e) => Err(TransactionComposeError::CreateTxError(e)),
        }
    }

    pub fn compose_psbt(
        &self,
        spend_params: TransactionParams,
    ) -> Result<DraftTransaction, TransactionComposeError> {
        let params = spend_params.clone();
        let address = params.address;
        let amount = params.amount;
        let fee_rate = params.fee_rate;
        let selected_outputs = params.selected_outputs;

        //get current utxo set and balance
        let utxos = self.utxos().unwrap();

        // The wallet will be locked for the rest of the spend method,
        // so calling other NgWallet APIs won't succeed.
        let mut coordinator_wallet = self
            .get_coordinator_wallet()
            .bdk_wallet
            .lock()
            .map_err(|_| TransactionComposeError::WalletError("Failed to lock wallet".into()))?;

        let address = Address::from_str(&address)
            .unwrap()
            .require_network(coordinator_wallet.network())
            .map_err(|_| TransactionComposeError::Error("Address network mismatch".into()))?;
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

        for do_not_spend_utxo in &do_not_spend_utxos {
            do_not_spend_amount += do_not_spend_utxo.amount;
        }

        let mut spendable_balance: u64 = spendables.clone().iter().map(|utxo| utxo.amount).sum();

        //deduct do_not_spend_amount from main balance,
        //this will be the balance of spendable utxos combined
        if spendable_balance > 0 && do_not_spend_amount < spendable_balance {
            spendable_balance -= do_not_spend_amount
        }

        if amount > spendable_balance {
            return Err(TransactionComposeError::CreateTxError(CoinSelection(
                InsufficientFunds {
                    available: Amount::from_sat(spendable_balance),
                    needed: Amount::from_sat(spendable_balance.checked_div(amount).unwrap_or(0)),
                },
            )));
        }

        let sweep = amount == spendable_balance;
        let fee_rate =
            FeeRate::from_sat_per_vb(fee_rate).unwrap_or(FeeRate::from_sat_per_vb_unchecked(1));
        let psbt = self.prepare_psbt(
            &mut coordinator_wallet,
            script.clone(),
            &mut spendables,
            &mut do_not_spend_utxos,
            None,
            Some(fee_rate),
            amount,
            sweep,
        );

        match psbt {
            Ok(psbt) => Ok(self.prepare_draft_transaction(
                psbt,
                &mut coordinator_wallet,
                utxos.clone(),
                spend_params,
                fee_rate,
            )),
            Err(e) => Err(TransactionComposeError::CreateTxError(e)),
        }
    }

    #[cfg(feature = "envoy")]
    pub fn broadcast_psbt(
        spend: DraftTransaction,
        electrum_server: &str,
        socks_proxy: Option<&str>,
    ) -> std::result::Result<Txid, Error> {
        let bdk_client = utils::build_electrum_client(electrum_server, socks_proxy);
        let psbt = Psbt::deserialize(&spend.psbt).expect("Failed to deserialize PSBT:");

        let transaction = psbt
            .extract_tx()
            .expect("Failed to extract transaction from PSBT");

        bdk_client.transaction_broadcast(&transaction)
    }

    pub fn decode_psbt(
        draft_transaction: DraftTransaction,
        psbt: &[u8],
    ) -> Result<DraftTransaction> {
        let mut psbt = Psbt::deserialize(psbt)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize PSBT: {}", e))?;
        if psbt.extract(&Secp256k1::verification_only()).is_err() {
            psbt = psbt
                .clone()
                .finalize(&Secp256k1::verification_only())
                .map_err(|(_, err)| anyhow::anyhow!("Failed to finalize PSBT {err:?}"))?;
        }
        Ok(DraftTransaction {
            psbt: psbt.clone().serialize(),
            is_finalized: psbt.extract(&Secp256k1::verification_only()).is_ok(),
            input_tags: draft_transaction.input_tags,
            change_out_put_tag: draft_transaction.change_out_put_tag,
            transaction: draft_transaction.transaction,
        })
    }

    pub(crate) fn filter_spendable_and_do_not_spendables(
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

    pub(crate) fn transform_psbt_to_bitcointx(
        psbt: Psbt,
        address: String,
        fee_rate: FeeRate,
        outputs: Vec<Output>,
        inputs: Vec<Input>,
        note: Option<String>,
        account_id: String,
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
            account_id,
        }
    }

    pub(crate) fn apply_meta_to_psbt_outputs(
        wallet: &MutexGuard<PersistedWallet<P>>,
        non_coordinator_wallets: &Vec<&NgWallet<P>>,
        utxos: Vec<Output>,
        tag: Option<String>,
        do_not_spend_change: bool,
        transaction: Transaction,
    ) -> Vec<Output> {
        let need_to_find_change = tag.as_ref().is_none_or(|t| t.is_empty());

        let change_tag = if need_to_find_change {
            let mut tags = Vec::new();
            for input in &transaction.input {
                let tx_id = input.previous_output.txid.to_string();
                let utxo_id = format!("{}:{}", tx_id, input.previous_output.vout);
                let mut input_tag = "untagged".to_string();
                for utxo in &utxos {
                    if utxo.get_id() == utxo_id {
                        input_tag = utxo.tag.clone().unwrap_or_else(|| "untagged".to_string());
                        break; // Found the matching utxo, no need to continue
                    }
                }
                tags.push(input_tag);
            }

            let unique_tags: HashSet<&String> = tags.iter().collect();

            if !tags.is_empty() && unique_tags.len() == 1 {
                Some(tags[0].clone())
            } else {
                None
            }
        } else {
            tag.clone()
        };

        let mut outputs = Vec::with_capacity(transaction.output.len());

        for (index, tx_out) in transaction.output.iter().enumerate() {
            let script = tx_out.script_pubkey.clone();
            let mut derivation = wallet.derivation_of_spk(script.clone());
            let address = match Address::from_script(&script, wallet.network()) {
                Ok(addr) => addr.to_string(),
                Err(_) => continue, // Skip invalid addresses
            };

            let mut out_put_tag: Option<String> = None;
            let mut out_put_do_not_spend_change = false;

            if let Some(path) = derivation {
                // If the output belongs to change keychain
                if path.0 == KeychainKind::Internal {
                    out_put_tag = change_tag.clone();
                    out_put_do_not_spend_change = do_not_spend_change;
                }
            } else {
                // Check if the change output belongs to the non-coordinator wallets
                for wallet in non_coordinator_wallets.iter() {
                    if let Ok(wallet_lock) = wallet.bdk_wallet.lock() {
                        derivation = wallet_lock.derivation_of_spk(script.clone());
                        if let Some(path) = derivation {
                            if path.0 == KeychainKind::Internal {
                                out_put_tag = change_tag.clone();
                                out_put_do_not_spend_change = do_not_spend_change;
                                break; // Found the wallet, no need to continue
                            }
                        }
                    }
                }
            }

            // If the output belongs to the wallet
            outputs.push(Output {
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
            });
        }

        outputs
    }

    pub(crate) fn apply_meta_to_inputs(
        wallet: &MutexGuard<PersistedWallet<P>>,
        non_coordinator_wallets: &Vec<&NgWallet<P>>,
        transaction: Transaction,
        utxos: Vec<Output>,
    ) -> Vec<Input> {
        let mut inputs = Vec::with_capacity(transaction.input.len());

        for input in &transaction.input {
            let tx_id = input.previous_output.txid.to_string();
            let v_index = input.previous_output.vout;
            let mut amount = Self::get_amount_from_tx_in(wallet, input, &tx_id, v_index);

            if amount == 0 {
                for wallet in non_coordinator_wallets {
                    let wallet = wallet.bdk_wallet.lock().unwrap_or_else(|poisoned| {
                        info!("Mutex poisoned, recovering...");
                        poisoned.into_inner() // Recover from poisoned mutex
                    });
                    amount = Self::get_amount_from_tx_in(&wallet, input, &tx_id, v_index);
                    if amount > 0 {
                        break; // Found the amount, no need to check other wallets
                    }
                }
            }

            let utxo_id = format!("{tx_id}:{v_index}");
            let mut tag: Option<String> = None;

            for utxo in &utxos {
                if utxo.get_id() == utxo_id {
                    tag = utxo.tag.clone();
                    break; // Found the matching utxo, no need to continue
                }
            }

            inputs.push(Input {
                tx_id,
                vout: v_index,
                amount,
                tag,
            });
        }

        inputs
    }

    fn get_amount_from_tx_in(
        wallet: &MutexGuard<PersistedWallet<P>>,
        input: &TxIn,
        tx_id: &str,
        v_index: u32,
    ) -> u64 {
        if wallet.get_utxo(input.previous_output).is_some() {
            wallet
                .get_utxo(input.previous_output)
                .unwrap()
                .txout
                .value
                .to_sat()
        } else {
            let wallet_tx = wallet.get_tx(Txid::from_str(tx_id).unwrap());
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
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_psbt(
        &self,
        wallet: &mut MutexGuard<PersistedWallet<P>>,
        script: ScriptBuf,
        spendable_utxos: &mut [Output],
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
        for spendable_utxo in spendable_utxos {
            let outpoint = spendable_utxo.get_outpoint();
            match self.get_utxo_input(spendable_utxo, self.non_coordinator_wallets()) {
                None => {}
                Some((input, weight)) => {
                    builder
                        .add_foreign_utxo_with_sequence(
                            outpoint,
                            input,
                            weight,
                            Sequence::ENABLE_RBF_NO_LOCKTIME,
                        )
                        .map_err(|_| CreateTxError::NoUtxosSelected)?;
                }
            }
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
        builder.set_exact_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME);

        builder.finish()
    }

    pub(crate) fn get_utxo_input(
        &self,
        output: &Output,
        wallets: Vec<&NgWallet<P>>,
    ) -> Option<(psbt::Input, Weight)> {
        let mut input_for_fore: Option<(psbt::Input, Weight)> = None;
        for wallet in wallets.iter() {
            let wallet = wallet.bdk_wallet.lock().unwrap();
            let local_output = wallet.get_utxo(output.get_outpoint());
            match local_output {
                None => {}
                Some(local_output) => {
                    let input = wallet.get_psbt_input(local_output, None, false);
                    match input {
                        Ok(input) => {
                            for (_, descriptor) in wallet.keychains() {
                                match descriptor.max_weight_to_satisfy() {
                                    Ok(weight) => {
                                        input_for_fore = Some((input.clone(), weight));
                                    }
                                    Err(e) => {
                                        info!("Error getting max weight to satisfy: {e:?}");
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            info!("Error getting max weight to satisfy: {e:?}");
                        }
                    }
                }
            }
        }
        input_for_fore
    }

    pub fn sign_psbt(wallets: Vec<&NgWallet<P>>, psbt: &mut Psbt, sign_options: SignOptions) {
        for wallet in wallets {
            let mut wallet = wallet.bdk_wallet.lock().unwrap();
            wallet.sign(psbt, sign_options.clone()).unwrap_or(false);
            //Why cancel? Canceling will reset the index.
            //We only increment the index if the transaction is broadcasted.
            wallet.cancel_tx(&psbt.clone().unsigned_tx);
        }
    }

    ///TODO, verify inputs belongs to the wallet
    pub fn get_bitcoin_tx_from_psbt(&self, psbt: &[u8]) -> Result<BitcoinTransaction> {
        let psbt = Psbt::deserialize(psbt).with_context(|| "Failed to deserialize PSBT")?;
        let account_id = self.config.id.clone();
        let transaction = psbt.clone().unsigned_tx;
        let mut amount = 0;
        let mut address = "".to_string();
        for outputs in transaction.output.iter() {
            let script = outputs.script_pubkey.clone();
            for wallet in self.wallets.iter() {
                let bdk_wallet = wallet.bdk_wallet.lock().unwrap();
                let derivation = bdk_wallet.derivation_of_spk(script.clone());
                if derivation.is_none() {
                    address = Address::from_script(&script, bdk_wallet.network())
                        .unwrap()
                        .to_string();
                    amount = outputs.value.to_sat();
                }
            }
            //check for self spends
            if address.is_empty() {
                for wallet in self.wallets.iter() {
                    let bdk_wallet = wallet.bdk_wallet.lock().unwrap();
                    let derivation = bdk_wallet.derivation_of_spk(script.clone());
                    match derivation {
                        None => {}
                        Some((kind, _)) => {
                            if kind == KeychainKind::External {
                                address = Address::from_script(&script, bdk_wallet.network())
                                    .unwrap()
                                    .to_string();
                                amount = outputs.value.to_sat();
                            }
                        }
                    }
                }
            }
        }

        Ok(BitcoinTransaction {
            tx_id: transaction.clone().compute_txid().to_string(),
            block_height: 0,
            confirmations: 0,
            is_confirmed: false,
            fee: psbt.fee().unwrap_or(Amount::from_sat(0)).to_sat(),
            fee_rate: psbt
                .fee_rate()
                .unwrap_or(FeeRate::from_sat_per_vb_unchecked(1))
                .to_sat_per_vb_floor(),
            amount: amount as i64,
            inputs: vec![],
            address,
            outputs: vec![],
            note: None,
            date: None,
            vsize: 0,
            account_id,
        })
    }

    pub(crate) fn prepare_draft_transaction(
        &self,
        mut psbt: Psbt,
        coordinator_wallet: &mut MutexGuard<PersistedWallet<P>>,
        utxos: Vec<Output>,
        transaction_params: TransactionParams,
        fee_rate: FeeRate,
    ) -> DraftTransaction {
        // Always try signing
        let sign_options = SignOptions {
            trust_witness_utxo: true,
            ..Default::default()
        };
        // Always try signing
        let _ = coordinator_wallet
            .sign(&mut psbt, sign_options.clone())
            .is_ok();
        //reset index,
        coordinator_wallet.cancel_tx(&psbt.clone().unsigned_tx);
        Self::sign_psbt(
            self.non_coordinator_wallets(),
            &mut psbt,
            sign_options.clone(),
        );
        //extract outputs from tx and add tags and do_not_spend states
        let outputs = Self::apply_meta_to_psbt_outputs(
            coordinator_wallet,
            &self.non_coordinator_wallets(),
            utxos.clone(),
            transaction_params.tag,
            transaction_params.do_not_spend_change,
            psbt.clone().unsigned_tx,
        );
        let inputs = Self::apply_meta_to_inputs(
            coordinator_wallet,
            &self.non_coordinator_wallets(),
            psbt.clone().unsigned_tx,
            utxos,
        );
        let transaction = Self::transform_psbt_to_bitcointx(
            psbt.clone(),
            transaction_params.address,
            fee_rate,
            outputs.clone(),
            inputs.clone(),
            transaction_params.note,
            self.config.id.clone(),
        );

        let mut change_out_put_tag: Option<String> = None;
        for output in transaction.outputs.clone() {
            if output.keychain == Some(KeyChain::Internal) {
                change_out_put_tag = output.tag.clone();
            }
        }

        info!("Send::Change output : {:?}", change_out_put_tag.clone());
        let input_tags: Vec<String> = inputs
            .iter()
            .map(|input| input.tag.clone().unwrap_or("untagged".to_string()))
            .collect();

        DraftTransaction {
            psbt: psbt.serialize(),
            is_finalized: psbt.extract(&Secp256k1::verification_only()).is_ok(),
            input_tags,
            change_out_put_tag,
            transaction,
        }
    }
}

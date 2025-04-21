use crate::ngwallet::NgWallet;
use anyhow::Result;
use base64::prelude::*;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Psbt, ScriptBuf, Transaction};
use bdk_wallet::coin_selection::InsufficientFunds;
use bdk_wallet::error::CreateTxError;
use bdk_wallet::error::CreateTxError::CoinSelection;
use bdk_wallet::miniscript::psbt::PsbtExt;
use bdk_wallet::{KeychainKind, PersistedWallet, SignOptions, TxOrdering, WalletPersister};
use log::info;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{MutexGuard};

use crate::transaction::{BitcoinTransaction, Input, KeyChain, Output};
#[cfg(feature = "envoy")]
use {
    bdk_electrum::BdkElectrumClient,
    bdk_electrum::electrum_client::Client,
    bdk_electrum::electrum_client::{Config, Socks5Config},
    bdk_wallet::psbt::PsbtUtils,

};

#[derive(Debug, Clone)]
pub struct PreparedTransaction {
    pub transaction: BitcoinTransaction,
    pub psbt_base64: String,
    pub change_out_put_tag: Option<String>,
    pub input_tags: Vec<String>,
    pub is_finalized: bool,
}

pub struct TransactionFeeResult {
    pub max_fee_rate: u64,
    pub min_fee_rate: u64,
    pub prepared_transaction: PreparedTransaction,
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
    //noinspection RsExternalLinter
    //noinspection RsExternalLinter
    #[cfg(feature = "envoy")]
    pub fn get_max_fee(
        &self,
        transaction_params: TransactionParams,
    ) -> Result<TransactionFeeResult, CreateTxError> {
        let utxos = self.unspend_outputs().unwrap();
        let balance = self.balance().unwrap().total().to_sat();
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
        Self::extract_spendable_do_not_spendable(
            selected_outputs,
            utxos.clone(),
            &mut do_not_spend_utxos,
            &mut spendables,
        );

        let mut do_not_spend_amount = 0;

        for do_not_spend_utxo in do_not_spend_utxos.clone() {
            do_not_spend_amount += do_not_spend_utxo.amount;
        }

        let mut spendable_balance = balance;
        //deduct do_not_spend_amount from main balance,
        //this will be the balance of spendable utxos combined
        if balance > 0 && do_not_spend_amount < balance {
            spendable_balance = balance - do_not_spend_amount;
        }

        if amount > spendable_balance {
            return Err(CoinSelection(InsufficientFunds {
                available: Amount::from_sat(spendable_balance),
                needed: Amount::from_sat(spendable_balance.checked_div(amount).unwrap_or(0)),
            }));
        }

        let mut max_fee = spendable_balance - amount;

        // TODO: check if clippy is right about this one
        #[allow(unused_assignments)]
        let mut max_fee_rate = 1;

        let mut receive_amount = amount;
        //if user is trying to sweep in order to find the max fee we set receive to min spend…
        //amount which is dust limit
        if spendable_balance == amount {
            receive_amount = 573; //dust limit
            max_fee = spendable_balance - receive_amount;
        }

        if max_fee == 0 {
            max_fee = 1;
        }

        loop {
            let psbt = Self::prepare_psbt(
                &mut wallet,
                script.clone(),
                &mut do_not_spend_utxos,
                Some(max_fee),
                None,
                receive_amount,
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
                        max_fee = erorr.available.to_sat() - receive_amount;
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
            receive_amount,
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
                    amount as i64,
                    outputs.clone(),
                    inputs.clone(),
                    None,
                    default_fee_rate,
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
                    .map(|input| input.tag.clone().unwrap_or("".to_string()))
                    .filter(|x| !x.is_empty())
                    .collect();

                Ok(TransactionFeeResult {
                    max_fee_rate,
                    min_fee_rate: 1,
                    prepared_transaction: PreparedTransaction {
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
    ) -> Result<PreparedTransaction, CreateTxError> {
        let address = spend_params.address;
        let amount = spend_params.amount;
        let fee_rate = spend_params.fee_rate;
        let selected_outputs = spend_params.selected_outputs;
        let note = spend_params.note;
        let tag = spend_params.tag;
        let do_not_spend_change = spend_params.do_not_spend_change;

        //get current utxo set and balance
        let utxos = self.unspend_outputs().unwrap();
        let balance = self.balance().unwrap().total().to_sat();

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
        Self::extract_spendable_do_not_spendable(
            selected_outputs,
            utxos.clone(),
            &mut do_not_spend_utxos,
            &mut spendables,
        );

        let mut do_not_spend_amount = 0;

        for do_not_spend_utxo in do_not_spend_utxos.clone() {
            do_not_spend_amount += do_not_spend_utxo.amount;
        }

        let mut spendable_balance = balance;
        //deduct do_not_spend_amount from main balance,
        //this will be the balance of spendable utxos combined
        if balance > 0 && do_not_spend_amount < balance {
            spendable_balance = balance - do_not_spend_amount;
        }

        if amount > spendable_balance {
            return Err(CoinSelection(InsufficientFunds {
                available: Amount::from_sat(spendable_balance),
                needed: Amount::from_sat(spendable_balance.checked_div(amount).unwrap_or(0)),
            }));
        }

        let mut receive_amount = amount;
        // If the user is trying to sweep in order to find the maximum fee,
        // we set the receive amount to the minimum spendable amount,
        // which is the dust limit.
        if spendable_balance == amount {
            receive_amount = 573; //dust limit
        }

        let fee_rate =
            FeeRate::from_sat_per_vb(fee_rate).unwrap_or(FeeRate::from_sat_per_vb_unchecked(1));
        let psbt = Self::prepare_psbt(
            &mut wallet,
            script.clone(),
            &mut do_not_spend_utxos,
            None,
            Some(fee_rate),
            receive_amount,
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
                    tag,
                    do_not_spend_change,
                    psbt.clone().unsigned_tx,
                );
                let inputs =
                    Self::apply_meta_to_inputs(&wallet, psbt.clone().unsigned_tx, utxos.clone());
                let transaction = Self::transform_psbt_to_bitcointx(
                    psbt.clone(),
                    address.clone().to_string(),
                    amount as i64,
                    outputs.clone(),
                    inputs.clone(),
                    note,
                    fee_rate,
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
                    .map(|input| input.tag.clone().unwrap_or("".to_string()))
                    .filter(|x| !x.is_empty())
                    .collect();

                Ok(PreparedTransaction {
                    psbt_base64: BASE64_STANDARD.encode(psbt.clone().serialize()).to_string(),
                    is_finalized: psbt.extract(&Secp256k1::verification_only()).is_ok(),
                    input_tags,
                    change_out_put_tag,
                    transaction,
                })
            }
            Err(e) => {
                info!("Error creating PSBT: {:?}", e);
                Err(e)
            }
        }
    }

    #[cfg(feature = "envoy")]
    pub fn broadcast_psbt(
        spend: PreparedTransaction,
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

    fn extract_spendable_do_not_spendable(
        selected_outputs: Vec<Output>,
        utxos: Vec<Output>,
        do_not_spend_utxos: &mut Vec<Output>,
        spendables: &mut Vec<Output>,
    ) {
        for output in utxos {
            //choose all output that are not selected by the user,
            //this will create a pool of available utxo for tx builder.
            for selected_outputs in selected_outputs.clone() {
                if output.get_id() != selected_outputs.get_id() {
                    do_not_spend_utxos.push(output.clone())
                }
            }
            //any out put that are already user marked as do not spend
            if output.do_not_spend && !do_not_spend_utxos.contains(&output.clone()) {
                do_not_spend_utxos.push(output.clone())
            }
            if !do_not_spend_utxos.contains(&output.clone()) {
                spendables.push(output)
            }
        }
    }

    fn transform_psbt_to_bitcointx(
        psbt: Psbt,
        address: String,
        amount: i64,
        outputs: Vec<Output>,
        inputs: Vec<Input>,
        note: Option<String>,
        fee_rate: FeeRate,
    ) -> BitcoinTransaction {
        let transaction = psbt.clone().unsigned_tx;

        BitcoinTransaction {
            tx_id: transaction.clone().compute_txid().to_string(),
            block_height: 0,
            confirmations: 0,
            is_confirmed: false,
            fee: psbt.fee().unwrap_or(Amount::from_sat(0)).to_sat(),
            fee_rate: fee_rate.to_sat_per_vb_floor(),
            amount: -amount,
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
                    let mut tag = "".to_string();
                    for utxo in utxos.clone() {
                        if utxo.get_id() == utxo_id {
                            tag = utxo.tag.unwrap_or("".to_string());
                        }
                    }
                    tag
                })
                .filter(|x| !x.is_empty())
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
    ) -> Result<Psbt, CreateTxError> {
        let mut builder = wallet.build_tx();
        builder.ordering(TxOrdering::Shuffle);
        for do_not_spend_utxo in do_not_spend_utxos {
            builder.add_unspendable(do_not_spend_utxo.get_outpoint());
        }
        builder.add_recipient(script.clone(), Amount::from_sat(receive_amount));

        if let Some(fee_absolute) = fee_absolute {
            builder.fee_absolute(Amount::from_sat(fee_absolute));
        }

        if let Some(fee_rate) = fee_rate {
            builder.fee_rate(fee_rate);
        }

        builder.finish()
    }
}

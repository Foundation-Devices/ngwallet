use crate::ngwallet::NgWallet;
use anyhow::Result;
use base64::prelude::*;
use bdk_electrum::bdk_core::bitcoin::{Weight, psbt};
use bdk_wallet::bitcoin::psbt::IndexOutOfBoundsError::TxInput;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Psbt, ScriptBuf, Transaction, Txid};
use bdk_wallet::coin_selection::InsufficientFunds;
use bdk_wallet::error::CreateTxError;
use bdk_wallet::error::CreateTxError::CoinSelection;
use bdk_wallet::miniscript::psbt::PsbtExt;
use bdk_wallet::psbt::PsbtUtils;
use bdk_wallet::{
    KeychainKind, LocalOutput, PersistedWallet, SignOptions, TxOrdering, WalletPersister,
};
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::MutexGuard;

use crate::account::NgAccount;
use crate::transaction::{BitcoinTransaction, Input, KeyChain, Output};
#[cfg(feature = "envoy")]
use {
    bdk_electrum::BdkElectrumClient,
    bdk_electrum::electrum_client::Client,
    bdk_electrum::electrum_client::Error,
    bdk_electrum::electrum_client::{Config, Socks5Config},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DraftTransaction {
    pub transaction: BitcoinTransaction,
    pub psbt_base64: String,
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

// TODO: chore: cleanup duplicate code
impl<P: WalletPersister> NgAccount<P> {
    //noinspection RsExternalLinter
    pub fn get_max_fee(
        &self,
        transaction_params: TransactionParams,
    ) -> Result<TransactionFeeResult, CreateTxError> {
        let utxos = self.utxos().unwrap();
        let mut coordinator_wallet = self.get_coordinator_wallet().bdk_wallet.lock().unwrap();
        let address = transaction_params.address;
        let tag = transaction_params.tag;
        let default_fee = transaction_params.fee_rate;
        let selected_outputs = transaction_params.selected_outputs;
        let amount = transaction_params.amount;

        let address = Address::from_str(&address)
            .unwrap()
            .require_network(coordinator_wallet.network())
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
            Ok(mut psbt) => {
                let sign_options = SignOptions {
                    trust_witness_utxo: true,
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

                let outputs = Self::apply_meta_to_psbt_outputs(
                    &coordinator_wallet,
                    utxos.clone(),
                    tag,
                    false,
                    psbt.clone().unsigned_tx,
                );
                let inputs = Self::apply_meta_to_inputs(
                    &coordinator_wallet,
                    psbt.clone().unsigned_tx,
                    utxos.clone(),
                );
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
        let utxos = self.utxos().unwrap();

        // The wallet will be locked for the rest of the spend method,
        // so calling other NgWallet APIs won't succeed.
        let mut coordinator_wallet = self.get_coordinator_wallet().bdk_wallet.lock().unwrap();

        let address = Address::from_str(&address)
            .unwrap()
            .require_network(coordinator_wallet.network())
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

        println!("spendable_balance: {}", spendable_balance);
        println!("do_not_spend_amount: {}", do_not_spend_amount);
        if amount > spendable_balance {
            return Err(CoinSelection(InsufficientFunds {
                available: Amount::from_sat(spendable_balance),
                needed: Amount::from_sat(spendable_balance.checked_div(amount).unwrap_or(0)),
            }));
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
            Ok(mut psbt) => {
                // Always try signing
                let sign_options = SignOptions {
                    trust_witness_utxo: true,
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
                //extract outputs from tx and add tags and do_not_spend states
                let outputs = Self::apply_meta_to_psbt_outputs(
                    &coordinator_wallet,
                    utxos.clone(),
                    tag.clone(),
                    do_not_spend_change,
                    psbt.clone().unsigned_tx,
                );
                let inputs = Self::apply_meta_to_inputs(
                    &coordinator_wallet,
                    psbt.clone().unsigned_tx,
                    utxos.clone(),
                );
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

    //mark utxo as used, this must called after transaction is broadcast
    pub fn mark_utxo_as_used(&self, transaction: Transaction) {
        for wallet in &self.wallets {
            let mut wallet = wallet.bdk_wallet.lock().unwrap();
            wallet.cancel_tx(&transaction.clone());
        }
    }

    #[cfg(feature = "envoy")]
    pub fn broadcast_psbt(
        spend: DraftTransaction,
        electrum_server: &str,
        socks_proxy: Option<&str>,
    ) -> std::result::Result<Txid, Error> {
        let bdk_client = Self::build_electrum_client(electrum_server, socks_proxy);
        let tx = BASE64_STANDARD
            .decode(spend.psbt_base64)
            .expect("Failed to decode PSBT");
        let psbt = Psbt::deserialize(tx.as_slice()).expect("Failed to deserialize PSBT:");

        let transaction = psbt
            .extract_tx()
            .expect("Failed to extract transaction from PSBT");

        bdk_client.transaction_broadcast(&transaction)
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

    pub(crate) fn apply_meta_to_psbt_outputs(
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

    pub(crate) fn apply_meta_to_inputs(
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
            match self.get_utxo_input(spendable_utxo) {
                None => {}
                Some((input, weight)) => {
                    println!("Adding foreign UTXO: {:?}", outpoint);
                    builder
                        .add_foreign_utxo(outpoint, input, weight)
                        .map_err(|e| {
                            println!("Error adding foreign UTXO: {:?}", e);
                            CreateTxError::NoUtxosSelected
                        })?;
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

        builder.finish()
    }

    fn get_utxo_input(&self, output: &Output) -> Option<(psbt::Input, Weight)> {
        let mut input_for_fore: Option<(psbt::Input, Weight)> = None;
        for wallet in self.non_coordinator_wallets() {
            let  wallet = wallet.bdk_wallet.lock().unwrap();
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
                                        println!("Error getting max weight to satisfy: {:?}", e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            println!("Error getting max weight to satisfy: {:?}", e);
                        }
                    }
                }
            }
        }
        input_for_fore
    }



    fn sign_psbt(wallets: Vec<&NgWallet<P>>, psbt: &mut Psbt, sign_options: SignOptions) {
        for wallet in wallets {
            let mut wallet = wallet.bdk_wallet.lock().unwrap();
            wallet.sign(psbt, sign_options.clone()).unwrap_or(false);
            //why cancel? cancel will resets index, we increment index only
            //if tx is broadcast
            wallet.cancel_tx(&psbt.clone().unsigned_tx);
        }
    }
}

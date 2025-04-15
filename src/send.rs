use crate::ngwallet::NgWallet;
use anyhow::{Error, Result};
use base64::prelude::*;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Psbt, ScriptBuf};
use bdk_wallet::error::CreateTxError::CoinSelection;
use bdk_wallet::{KeychainKind, SignOptions, TxOrdering, WalletPersister};
use std::str::FromStr;

use crate::transaction::{BitcoinTransaction, Input, Output};
#[cfg(feature = "envoy")]
use {
    bdk_electrum::BdkElectrumClient, bdk_electrum::electrum_client::Client,
    bdk_wallet::psbt::PsbtUtils,
};

#[derive(Debug, Clone)]
pub struct Spend {
    pub transaction: BitcoinTransaction,
    pub psbt_base64: String,
}

impl Spend {
    fn from(
        psbt: Psbt,
        address: String,
        amount: i64,
        outputs: Vec<Output>,
        note: Option<String>,
    ) -> Self {
        let transaction = psbt.clone().unsigned_tx;
        let fee = psbt.fee().unwrap_or(Amount::from_sat(0)).to_sat();
        let vsize = transaction.vsize() as f32;
        let fee_rate = if vsize > 0.0 {
            fee.checked_div(vsize as u64).unwrap_or(0)
        } else {
            0
        };
        let bitcoin_tx = BitcoinTransaction {
            tx_id: transaction.clone().compute_txid().to_string(),
            block_height: 0,
            confirmations: 0,
            is_confirmed: false,
            fee: psbt.fee().unwrap_or(Amount::from_sat(0)).to_sat(),
            fee_rate,
            amount,
            inputs: transaction
                .input
                .iter()
                .map(|input| Input {
                    tx_id: input.previous_output.txid.to_string(),
                    vout: input.previous_output.vout,
                })
                .collect(),
            address,
            outputs,
            note,
            date: None,
            vsize: 0,
        };
        Self {
            transaction: bitcoin_tx,
            psbt_base64: BASE64_STANDARD.encode(&psbt.serialize()).to_string(),
        }
    }
}

impl<P: WalletPersister> NgWallet<P> {
    #[cfg(feature = "envoy")]
    pub fn get_max_fee(
        &mut self,
        address: String,
        amount: u64,
        selected_outputs: Vec<Output>,
    ) -> Result<u64> {
        let utxos = self.unspend_outputs().unwrap();
        let balance = self.balance().unwrap().total().to_sat();
        let mut wallet = self.wallet.lock().unwrap();

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
            utxos,
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
            return Err(Error::msg("Insufficient balance".to_string()));
        }

        let mut max_fee = spendable_balance - amount;
        let mut max_fee_rate = 1;

        let mut receive_amount = amount;
        //if user is trying to sweep in order to find the max fee we set receive to min spend…
        //amount which is dust limit
        if spendable_balance == amount {
            receive_amount = 573; //dust limit
            max_fee = spendable_balance - receive_amount.clone();
        }

        if max_fee == 0 {
            max_fee = 1;
        }
        loop {
            let mut builder = wallet.build_tx();
            builder.ordering(TxOrdering::Shuffle).only_witness_utxo();
            for do_not_spend_utxo in do_not_spend_utxos.clone() {
                builder.add_unspendable(do_not_spend_utxo.get_outpoint());
            }
            builder.add_recipient(script.clone(), Amount::from_sat(receive_amount.clone()));
            builder.fee_absolute(Amount::from_sat(max_fee));
            let mut psbt = builder.finish();
            match psbt {
                Ok(mut psbt) => {
                    let sign_options = SignOptions {
                        ..Default::default()
                    };
                    // Always try signing
                    let finalized = wallet.sign(&mut psbt, sign_options).unwrap_or(false);
                    // reset indexes since this is only for fee calc
                    match psbt.clone().extract_tx() {
                        Ok(tx) => {
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
                        Err(_) => {}
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
                        return Err(err.into());
                    }
                },
            }
        }
        println!("\n\n<<<--DEBUG-->>>");
        println!("--->      Amount              -> {}", amount.clone());
        println!("--->      Address             -> {:?}", address.clone());
        println!(
            "--->      ReceiveAmount       -> {:?}",
            receive_amount.clone()
        );
        println!(
            "--->      DonotSpendAmount    -> {:?}",
            do_not_spend_amount.clone()
        );
        println!(
            "--->      SpendableAmount     -> {:?}",
            spendable_balance.clone()
        );
        println!("--->      MaxFeeFound         -> {:?}", max_fee.clone());
        println!(
            "--->      MaxFeeRateFound     -> {:?}",
            max_fee_rate.clone()
        );
        println!("<<<--DEBUG-->>>\n\n");
        Ok(max_fee_rate)
    }

    pub fn compose_psbt(
        &mut self,
        address: String,
        amount: u64,
        fee_rate: u64,
        selected_outputs: Vec<Output>,
        note: Option<String>,
        tag: Option<String>,
        do_not_spend_change: bool,
    ) -> Result<Spend> {
        let utxos = self.unspend_outputs().unwrap();
        let balance = self.balance().unwrap().total().to_sat();
        let mut wallet = self.wallet.lock().unwrap();

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
            utxos,
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
            return Err(Error::msg("Insufficient balance".to_string()));
        }

        let mut receive_amount = amount;
        //if user is trying to sweep in order to find the max fee we set receive to min spend…
        //amount which is dust limit
        if spendable_balance == amount {
            receive_amount = 573; //dust limit
        }
        let mut builder = wallet.build_tx();
        builder.ordering(TxOrdering::Shuffle);
        for do_not_spend_utxo in do_not_spend_utxos.clone() {
            builder.add_unspendable(do_not_spend_utxo.get_outpoint());
        }
        builder.add_recipient(script.clone(), Amount::from_sat(receive_amount.clone()));
        builder.fee_rate(
            FeeRate::from_sat_per_vb(fee_rate).unwrap_or(FeeRate::from_sat_per_vb_unchecked(1)),
        );
        let mut psbt = builder.finish();
        match psbt {
            Ok(mut psbt) => {
                // Always try signing
                let transaction = psbt.clone().extract_tx().unwrap();

                let sign_options = SignOptions {
                    ..Default::default()
                };
                // Always try signing
                match wallet.sign(&mut psbt, sign_options) {
                    Ok(_) => {}
                    Err(_) => {}
                }
                let outputs = transaction
                    .output
                    .clone()
                    .iter()
                    .enumerate()
                    .map(|(index, tx_out)| {
                        let derivation = wallet.derivation_of_spk(tx_out.clone().script_pubkey);
                        let address = Address::from_script(&tx_out.script_pubkey, wallet.network())
                            .unwrap()
                            .to_string();

                        let mut out_put_tag: Option<String> = None;
                        let mut out_put_do_not_spend_change = false;

                        if derivation.is_some() {
                            let path = derivation.unwrap();
                            if path.0 == KeychainKind::Internal {
                                out_put_tag = tag.clone();
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
                            do_not_spend: out_put_do_not_spend_change,
                        }
                    })
                    .clone()
                    .collect::<Vec<Output>>();

                Ok(Spend::from(
                    psbt,
                    address.to_string(),
                    receive_amount as i64,
                    outputs,
                    note.clone(),
                ))
            }
            Err(e) => match e {
                CoinSelection(erorr) => Err(erorr.into()),
                err => Err(err.into()),
            },
        }
    }

    #[cfg(feature = "envoy")]
    pub fn broadcast_psbt(&mut self, spend: Spend, electrum_server: &str) -> Result<String> {
        let client: BdkElectrumClient<Client> = BdkElectrumClient::new(
            Client::new(electrum_server).map_err(|e| anyhow::anyhow!("{}", e))?,
        );
        let tx = BASE64_STANDARD
            .decode(spend.psbt_base64)
            .map_err(|e| anyhow::anyhow!("Failed to decode PSBT: {}", e))?;
        let mut psbt = Psbt::deserialize(tx.as_slice())
            .map_err(|er| anyhow::anyhow!("Failed to deserialize PSBT: {}", er))?;
        let account = self.wallet.lock().unwrap();

        let sign = account
            .sign(&mut psbt, SignOptions::default())
            .map_err(|e| anyhow::anyhow!("Failed to sign PSBT: {}", e))?;
        let transaction = psbt
            .extract_tx()
            .map_err(|e| anyhow::anyhow!("Failed to extract transaction: {}", e))?;

        let tx_id = client
            .transaction_broadcast(&transaction)
            .map_err(|e| anyhow::anyhow!("Failed to broadcast transaction: {}", e))?;
        Ok(tx_id.to_string())
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
}

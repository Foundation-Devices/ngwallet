use crate::ngwallet::NgWallet;
use anyhow::Result;
use bdk_wallet::WalletPersister;
use bdk_wallet::bitcoin::{Address, Amount, Psbt, ScriptBuf};
use std::str::FromStr;

#[cfg(feature = "envoy")]
use {
    crate::transaction::Output,
    bdk_electrum::electrum_client::bitcoin::consensus::encode::serialize_hex,
    bdk_wallet::error::CreateTxError::CoinSelection,
    bdk_wallet::psbt::PsbtUtils,
    bdk_wallet::{SignOptions, TxOrdering},
};

impl<P: WalletPersister> NgWallet<P> {
    #[cfg(feature = "envoy")]
    pub fn get_max_fee(
        &mut self,
        address: String,
        amount: u64,
        selected_outputs: Vec<Output>,
    ) -> anyhow::Result<u64> {
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
        for output in utxos {
            println!("loop[ing ${}", output.do_not_spend);
            //choose all output that are not selected by the user,
            //this will create a pool of available utxo for tx builder.
            for selected_outputs in selected_outputs.clone() {
                if output.get_id() != selected_outputs.get_id() {
                    println!("Pushing to ");
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

        let mut do_not_spend_amount = 0;

        for do_not_spend_utxo in do_not_spend_utxos.clone() {
            do_not_spend_amount += do_not_spend_utxo.amount;
        }

        let mut spendable_balance = balance;
        if balance > 0 && do_not_spend_amount < balance {
            spendable_balance = balance - do_not_spend_amount;
        }

        let mut max_fee = spendable_balance - amount;
        let mut max_fee_rate = 1;

        let mut receive_amount = amount;
        if spendable_balance == amount {
            receive_amount = 573; //dust limit
            max_fee = spendable_balance - receive_amount.clone();
        }
        if max_fee == 0 {
            max_fee = 1;
        }
        println!("\n\n<<<---->>>");
        println!("--->      Amount              -> {}", amount.clone());
        println!("--->      Address             -> {:?}", address.clone());
        println!("--->      MaxFee              -> {:?}", max_fee.clone());
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
        println!("<<<---->>>\n\n");
        loop {
            let mut builder = wallet.build_tx();
            builder.ordering(TxOrdering::Shuffle).only_witness_utxo();
            for do_not_spend_utxo in do_not_spend_utxos.clone() {
                builder.add_unspendable(do_not_spend_utxo.get_outpoint());
            }
            builder.add_recipient(script.clone(), Amount::from_sat(receive_amount.clone()));
            builder.fee_absolute(Amount::from_sat(max_fee));
            // builder.fee_rate(FeeRate::from_sat_per_vb(104).unwrap());
            let mut psbt = builder.finish();
            match psbt {
                Ok(mut psbt) => {
                    let sign_options = SignOptions {
                        trust_witness_utxo: true,
                        ..Default::default()
                    };
                    // Always try signing
                    wallet.sign(&mut psbt, sign_options).unwrap_or(false);

                    match psbt.fee_rate() {
                        None => {}
                        Some(r) => {
                            println!(
                                "Serialized {:?}\n\n",
                                serialize_hex(&psbt.extract_tx().unwrap())
                            );
                            max_fee_rate = r.to_sat_per_vb_floor();
                            break;
                        }
                    }
                }
                Err(e) => match e {
                    CoinSelection(erorr) => {
                        max_fee = erorr.available.to_sat() - receive_amount.clone();
                    }
                    _ => {
                        break;
                    }
                },
            }
        }
        println!("\n\n<<<---->>>");
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
        println!("<<<---->>>\n\n");
        Ok(max_fee)
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
}

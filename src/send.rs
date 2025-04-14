use crate::ngwallet::NgWallet;
use crate::transaction::Output;
use anyhow::Result;
use bdk_electrum::bdk_core::bitcoin::{Address, Amount, Psbt, ScriptBuf};
use bdk_wallet::{KeychainKind, WalletPersister};
use std::str::FromStr;

impl<P: WalletPersister> NgWallet<P> {
    pub fn get_max_fee(
        &mut self,
        address: String,
        amount: u64,
        selected_outputs: Vec<Output>,
    ) -> Result<Psbt> {
        let mut wallet = self.wallet.lock().unwrap();
        let address = Address::from_str(&address)
            .unwrap()
            .require_network(wallet.network())
            .unwrap();
        let script: ScriptBuf = address.into();
        let mut builder = wallet.build_tx();
        builder.add_recipient(script.clone(), Amount::from_sat(amount));

        // //do not spend
        let mut do_not_spend_utxos: Vec<Output> = vec![];
        for output in self.unspend_outputs().unwrap() {
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
        }

        let mut available_balance = 0;
        for do_not_spend_utxo in do_not_spend_utxos.clone() {
            available_balance += do_not_spend_utxo.amount;
        }
        for do_not_spend_utxo in do_not_spend_utxos {
            builder.add_unspendable(do_not_spend_utxo.get_outpoint());
        }

        let psbt = builder
            .finish()
            .map_err(|e| anyhow::anyhow!("error {}", e))
            .unwrap();

        Ok(psbt)
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

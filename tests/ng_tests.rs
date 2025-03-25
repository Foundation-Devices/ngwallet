const EXTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAjWytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/0/*)#g9xn7wf9";
const INTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAjWytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/1/*)#e3rjrmea";
const ELECTRUM_SERVER: &str = "ssl://mempool.space:60602";

// TODO: make this unique to the descriptor
#[cfg(test)]
mod tests {
    use std::env;
    use std::path::PathBuf;
    use std::str::FromStr;
    use bdk_wallet::{AddressInfo, Update};
    use ngwallet::account::NgAccount;
    use ngwallet::ngwallet::NgWallet;

    use crate::*;
    
    #[test]
    #[cfg(feature = "envoy")]
    fn new_wallet() {
        let mut account = NgAccount::new_from_descriptor(
            "Passport Prime".to_string(),
            "red".to_string(),
            None,
            None,
            "Signet".to_string(),
            "Taproot".to_string(),
            EXTERNAL_DESCRIPTOR.to_string(),
            None,
            0,
            None,);
        let address: AddressInfo = account.wallet.next_address().unwrap();
        println!(
            "Generated address {} at index {}",
            address.address, address.index
        );
    
        let request = account.wallet.scan_request();
        let update = NgWallet::scan(request,ELECTRUM_SERVER).unwrap();
        account.wallet.apply(Update::from(update)).unwrap();
    
        let balance = account.wallet.balance().unwrap();
        println!("Wallet balance: {} sat\n", balance.total().to_sat());
    
        let transactions = account.wallet.transactions();
        for tx in transactions {
            println!("Transaction: {:?}", tx);
        }
    
        let utxos = account.wallet.unspend_outputs();
        utxos.unwrap().iter().for_each(|utxo| {
            println!("Utxo: {:?}", utxo);
        });
    
        let transactions = account.wallet.transactions().unwrap();
    
        if !transactions.is_empty() {
            let message = "Test Message".to_string();
            println!("\nSetting note: {:?}", message);
            account.wallet.set_note(&transactions[0].tx_id, &message.clone())
                .unwrap();
            let transactions = account.wallet.transactions().unwrap();
            let firs_tx = transactions[0].note.clone().unwrap_or("".to_string());
            println!("Transaction note: {:?}", firs_tx);
            assert_eq!(firs_tx, message);
        }
    
        let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
        if !utxos.is_empty() {
            let tag = "Test Tag".to_string();
            println!("\nSetting tag: {:?}", tag);
            let first_utxo = &utxos[0];
            account.wallet.set_tag(first_utxo, tag.as_str()).unwrap();
            let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
            let utxo_tag = utxos[0].tag.clone().unwrap_or("".to_string());
            println!("Utxo tag: {:?}", utxo_tag);
            assert_eq!(utxo_tag, tag);
    
            println!("\nSetting do not spend : {:?}", false);
    
            account.wallet.set_do_not_spend(first_utxo, false).unwrap();
    
            let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
            let utxo_tag = &utxos[0];
            println!("Utxo After Do not Spend: {:?}", utxo_tag);
    
            println!("\nSetting do not spend : {:?}", true);
            account.wallet.set_do_not_spend(first_utxo, false).unwrap();
    
            let utxos = account.wallet.unspend_outputs().unwrap_or(vec![]);
            let utxo_tag = &utxos[0];
            println!("Utxo After Do not Spend: {:?}", utxo_tag);
        }
        account.wallet.persist().unwrap();
    }

    #[test]
    #[cfg(feature = "envoy")]
    fn open_wallet() {
        // let dir = env::current_dir().unwrap();
        // let mut account = NgAccount::open_wallet(
        //     None
        // );
        // let address: AddressInfo = account.wallet.next_address().unwrap();
        // println!(
        //     "Generated address {} at index {}",
        //     address.address, address.index
        // );
        // let transactions = account.wallet.transactions();
        // for tx in transactions {
        //     println!("Transaction: {:?}", tx);
        // }
        // let balance = account.wallet.balance().unwrap();
        // println!("Wallet balance: {} sat\n", balance.total().to_sat());

    }


    // #[test]
    // #[cfg(feature = "envoy")]
    // fn check_watch_only() {
    //     // let mut wallet = NgWallet::new_from_descriptor(Some(DB_PATH.to_string()), EXTERNAL_DESCRIPTOR.to_string()).unwrap_or(NgWallet::load(DB_PATH).unwrap());
    //     //
    //     // let address: AddressInfo = wallet.next_address().unwrap();
    //     // println!(
    //     //     "Generated address {} at index {}",
    //     //     address.address, address.index
    //     // );
    //     //
    //     // let request = wallet.scan_request();
    //     // let update = NgWallet::scan(request).unwrap();
    //     // wallet.apply(Update::from(update)).unwrap();
    //     //
    //     // let balance = wallet.balance().unwrap().total().to_sat();
    //     // println!("Wallet balance: {} sat", balance);
    //     //
    //     // let transactions = wallet.transactions();
    //     //
    //     // for tx in transactions {
    //     //     println!("Transaction: {:?}", tx);
    //     // }
    //     // let unspends = wallet.unspend_outputs();
    //     //
    //     // for utxo in unspends {
    //     //     println!("Utxo: {:?}", utxo);
    //     // }
    //
    //     //println!("Wallet balance: {:?} sat", wallet.transactions());
    // }
}

use bdk_electrum::bdk_core::bitcoin::Amount;
use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::{OutPoint, Psbt, Txid};
use std::str::FromStr;

// #[derive(Debug)]
// struct RampTransaction {
//     pub ramp_id: String,
//     pub ramp_fee: u32,
//     pub currency_amount: String,
//     pub currency: String,
// }
//
// #[derive(Debug)]
// struct BtcPayVoucher {
//     pub btc_pay_voucher_uri: String,
//     pub payout_id: String,
// }
//
// #[derive(Debug)]
// pub enum TransactionPlaceholder {
//     Ramp(RampTransaction),
//     BtcPayVoucher(BtcPayVoucher),
//     BroadcastPending,
//     Azteco,
// }

#[derive(Debug, Clone)]
pub struct Input {
    pub tx_id: String,
    pub vout: u32,
    pub amount: u64,
    pub tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum KeyChain {
    External,
    Internal,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Output {
    pub tx_id: String,
    pub vout: u32,
    pub amount: u64,
    pub tag: Option<String>,
    pub date: Option<u64>,
    pub is_confirmed: bool,
    pub address: String,
    pub do_not_spend: bool,
    pub keychain: Option<KeyChain>,
}

impl Output {
    pub fn get_id(&self) -> String {
        format!("{}:{}", self.tx_id, self.vout)
    }
    pub fn get_outpoint(&self) -> OutPoint {
        let tx_id = Txid::from_str(self.tx_id.as_str()).unwrap();
        OutPoint::new(tx_id, self.vout)
    }
}

#[derive(Debug, Clone)]
pub struct BitcoinTransaction {
    pub tx_id: String,
    pub block_height: u32,
    pub confirmations: u32,
    pub is_confirmed: bool,
    pub fee: u64,
    pub fee_rate: u64,
    pub amount: i64,
    pub inputs: Vec<Input>,
    pub address: String,
    pub outputs: Vec<Output>,
    pub note: Option<String>,
    pub date: Option<u64>,
    pub vsize: usize,
}

// #[derive(Debug)]
// pub struct NgTransaction {
//     pub placeholder: Option<TransactionPlaceholder>,
//     pub output: Option<BitcoinTransaction>,
// }

#[derive(Debug)]
struct RampTransaction {
    pub ramp_id: String,
    pub ramp_fee: u32,
    pub currency_amount: String,
    pub currency: String,
}

#[derive(Debug)]
struct BtcPayVoucher {
    pub btc_pay_voucher_uri: String,
    pub payout_id: String,
}

#[derive(Debug)]
pub enum TransactionPlaceholder {
    Ramp(RampTransaction),
    BtcPayVoucher(BtcPayVoucher),
    BroadcastPending,
    Azteco,
}

#[derive(Debug)]
pub struct Input {
    pub tx_id: String,
    pub vout: u32,
}

#[derive(Debug)]
pub struct Output {
    pub tx_id: String,
    pub vout: u32,
    pub amount: u64,
    pub tag: Option<String>,
    pub do_not_spend: Option<bool>,
}

impl Output {
    pub fn get_id(&self) -> String {
        format!("{}:{}", self.tx_id, self.vout)
    }
}

#[derive(Debug)]
pub struct BitcoinTransaction {
    pub tx_id: String,
    pub block_height: u32,
    pub confirmations: u32,
    pub fee: u64,
    pub amount: u64,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub note: Option<String>,
}

#[derive(Debug)]
pub struct NgTransaction {
    pub placeholder: Option<TransactionPlaceholder>,
    pub output: Option<BitcoinTransaction>,
}

#[derive(Debug)]
pub struct Utxo {
    pub tx_id: String,
    pub vout: u32,
    pub amount: u64,
}

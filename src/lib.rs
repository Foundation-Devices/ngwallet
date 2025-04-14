pub mod account;
pub mod config;
pub mod ngwallet;
pub mod send;
mod store;
pub mod transaction;
pub mod utxo;

pub use bdk_wallet;
pub use redb;

mod db;
pub mod bip39;

const STOP_GAP: usize = 100;
const BATCH_SIZE: usize = 5;

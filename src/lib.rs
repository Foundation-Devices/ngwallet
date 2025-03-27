pub mod account;
pub mod ngwallet;
mod store;
pub mod transaction;
pub mod utxo;
pub mod config;

pub use bdk_wallet;
pub use redb;

mod db;

const STOP_GAP: usize = 100;
const BATCH_SIZE: usize = 5;

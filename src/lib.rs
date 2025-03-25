pub mod account;
pub mod ngwallet;
mod store;
pub mod transaction;
pub mod utxo;
pub mod config;

mod db;
mod keyos;

const STOP_GAP: usize = 1000;
const BATCH_SIZE: usize = 5;

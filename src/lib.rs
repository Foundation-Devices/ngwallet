pub mod account;
pub mod config;
pub mod ngwallet;
pub mod rbf;
pub mod send;
mod store;
pub mod transaction;
pub mod utxo;

pub use bdk_wallet;
pub use redb;

pub mod bip39;
mod db;
pub mod utils;

#[cfg(feature = "envoy")]
pub use bdk_electrum;
#[cfg(feature = "envoy")]
const STOP_GAP: usize = 100;

#[cfg(feature = "envoy")]
const BATCH_SIZE: usize = 5;

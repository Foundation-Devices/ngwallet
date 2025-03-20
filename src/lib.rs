pub mod account;
pub mod ngwallet;
mod store;
pub mod transaction;
pub mod utxo;

mod keyos;

use anyhow::{Ok, Result};
use std::str::FromStr;

const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;

const EXTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAjWytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/0/*)#g9xn7wf9";
const INTERNAL_DESCRIPTOR: &str = "tr(tprv8ZgxMBicQKsPdrjwWCyXqqJ4YqcyG4DmKtjjsRt29v1PtD3r3PuFJAjWytzcvSTKnZAGAkPSmnrdnuHWxCAwy3i1iPhrtKAfXRH7dVCNGp6/86'/1'/0'/1/*)#e3rjrmea";
const ELECTRUM_SERVER: &str = "ssl://mempool.space:60602";
const DB_PATH: &str = "test_wallet.sqlite3";

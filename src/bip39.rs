use bdk_wallet::bip39::Language;
use std::cmp::min;

pub fn get_seedword_suggestions(input: &str, nr_of_suggestions: usize) -> Vec<&str> {
    let list = Language::English.words_by_prefix(input);
    let count = min(nr_of_suggestions, list.len());
    list[..count].to_vec()
}

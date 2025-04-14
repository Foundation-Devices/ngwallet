use bdk_wallet::bip39::Language;

pub fn get_seedword_suggestions(input: &str, nr_of_suggestions: usize) -> Vec<&str> {
    let list = Language::English.words_by_prefix(input);
    list[..nr_of_suggestions].to_vec()
}

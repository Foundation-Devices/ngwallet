use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::keys::bip39::{Language, Mnemonic};
use bdk_wallet::template::{Bip84, Bip86, DescriptorTemplate};
use std::cmp::min;

pub enum DescriptorType {
    Bip84,
    Bip86,
}

pub struct Descriptors {
    descriptor_xprv: String,
    change_descriptor_xprv: String,
    descriptor_xpub: String,
    change_descriptor_xpub: String,
}

impl Descriptors {
    pub fn descriptor_xprv(&self) -> &str {
        &self.descriptor_xprv
    }

    pub fn change_descriptor_xprv(&self) -> &str {
        &self.change_descriptor_xprv
    }

    pub fn descriptor_xpub(&self) -> &str {
        &self.descriptor_xpub
    }

    pub fn change_descriptor_xpub(&self) -> &str {
        &self.change_descriptor_xpub
    }
}

pub fn get_seedword_suggestions(input: &str, nr_of_suggestions: usize) -> Vec<&str> {
    let list = Language::English.words_by_prefix(input);
    let count = min(nr_of_suggestions, list.len());
    list[..count].to_vec()
}

pub fn get_random_seed() -> anyhow::Result<String> {
    let mnemonic = Mnemonic::generate_in(Language::English, 12)?;
    Ok(mnemonic.to_string())
}

pub fn get_descriptors(
    seed: String,
    descriptor_type: DescriptorType,
    network: Network,
    passphrase: Option<String>,
) -> anyhow::Result<Descriptors> {
    let mnemonic = Mnemonic::parse(seed)?;
    let seed = mnemonic.to_seed(passphrase.unwrap_or("".to_owned()));

    let xprv: Xpriv = Xpriv::new_master(network, &seed)?;

    let (descriptor, key_map, change_descriptor, change_key_map) = {
        match descriptor_type {
            DescriptorType::Bip84 => {
                let external = Bip84(xprv, KeychainKind::External).build(network)?;
                let internal = Bip84(xprv, KeychainKind::Internal).build(network)?;

                (external.0, external.1, internal.0, internal.1)
            }
            DescriptorType::Bip86 => {
                let external = Bip86(xprv, KeychainKind::External).build(network)?;
                let internal = Bip86(xprv, KeychainKind::Internal).build(network)?;

                (external.0, external.1, internal.0, internal.1)
            }
        }
    };

    Ok(Descriptors {
        descriptor_xprv: descriptor.to_string_with_secret(&key_map),
        change_descriptor_xprv: change_descriptor.to_string_with_secret(&change_key_map),
        descriptor_xpub: descriptor.to_string(),
        change_descriptor_xpub: change_descriptor.to_string(),
    })
}

#[cfg(test)]
mod test {
    use crate::bip39::DescriptorType::Bip84;
    use crate::bip39::{get_descriptors, get_random_seed};
    use bdk_wallet::bitcoin::Network;

    #[test]
    fn test_get_descriptor_from_seed() {
        let mnemonic =
            "aim bunker wash balance finish force paper analyst cabin spoon stable organ"
                .to_owned();
        
        let descriptors = get_descriptors(mnemonic, Bip84, Network::Bitcoin, None).unwrap();

        assert_eq!(descriptors.descriptor_xprv, "wpkh(xprv9s21ZrQH143K2v9ABLJujuoqaJoMuazgoH6Yg4CceWQr86hPGbE5g6ivqRnPPGTnt6GqZVTFecYEUzkB9rzj79jGenWLW9GVsG5i6CKmMAE/84'/0'/0'/0/*)#5aaucexa".to_owned());
        assert_eq!(descriptors.change_descriptor_xprv, "wpkh(xprv9s21ZrQH143K2v9ABLJujuoqaJoMuazgoH6Yg4CceWQr86hPGbE5g6ivqRnPPGTnt6GqZVTFecYEUzkB9rzj79jGenWLW9GVsG5i6CKmMAE/84'/0'/0'/1/*)#9fca9vk9".to_owned());
        assert_eq!(descriptors.descriptor_xpub, "wpkh([be83839f/84'/0'/0']xpub6DMcCzuF7QuZJwR7XxqukyLf7rsVvN2wESKFjduCBwGXAHeFufQUJAMnA2h3Fey1KVHDCbiXsXiGgbk2YpsdFPH9sJetbGzYGrhN8VhDTQG/0/*)#wvlf8l45".to_owned());
        assert_eq!(descriptors.change_descriptor_xpub, "wpkh([be83839f/84'/0'/0']xpub6DMcCzuF7QuZJwR7XxqukyLf7rsVvN2wESKFjduCBwGXAHeFufQUJAMnA2h3Fey1KVHDCbiXsXiGgbk2YpsdFPH9sJetbGzYGrhN8VhDTQG/1/*)#lc6g629v".to_owned());
    }
    

    #[test]
    fn test_get_random_seed() {
        assert_eq!(
            get_random_seed()
                .unwrap()
                .split(' ')
                .collect::<Vec<_>>()
                .len(),
            12
        );
    }
}

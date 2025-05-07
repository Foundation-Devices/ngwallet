use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::keys::bip39::{Language, Mnemonic};
use bdk_wallet::template::{Bip44, Bip49, Bip84, Bip86, DescriptorTemplate};
use serde::{Deserialize, Serialize};
use std::cmp::min;

#[derive(Debug, Serialize, Deserialize)]
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
    network: Network,
    passphrase: Option<String>,
) -> anyhow::Result<Vec<Descriptors>> {
    let mnemonic = Mnemonic::parse(seed)?;
    let seed = mnemonic.to_seed(passphrase.unwrap_or("".to_owned()));

    let xprv: Xpriv = Xpriv::new_master(network, &seed)?;

    let mut descriptors = vec![];

    let descriptor_templates = vec![
        (
            Bip49(xprv, KeychainKind::External).build(network)?,
            Bip49(xprv, KeychainKind::Internal).build(network)?,
        ),
        (
            Bip44(xprv, KeychainKind::External).build(network)?,
            Bip49(xprv, KeychainKind::Internal).build(network)?,
        ),
        (
            Bip84(xprv, KeychainKind::External).build(network)?,
            Bip49(xprv, KeychainKind::Internal).build(network)?,
        ),
        (
            Bip86(xprv, KeychainKind::External).build(network)?,
            Bip49(xprv, KeychainKind::Internal).build(network)?,
        ),
    ];

    for template in descriptor_templates {
        let (descriptor, key_map, change_descriptor, change_key_map) =
            (template.0.0, template.0.1, template.1.0, template.1.1);

        descriptors.push(Descriptors {
            descriptor_xprv: descriptor.to_string_with_secret(&key_map),
            change_descriptor_xprv: change_descriptor.to_string_with_secret(&change_key_map),
            descriptor_xpub: descriptor.to_string(),
            change_descriptor_xpub: change_descriptor.to_string(),
        });
    }

    Ok(descriptors)
}

#[cfg(test)]
mod test {
    use crate::bip39::{get_descriptors, get_random_seed};
    use bdk_wallet::bitcoin::Network;

    #[test]
    fn test_get_descriptor_from_seed() {
        let mnemonic =
            "aim bunker wash balance finish force paper analyst cabin spoon stable organ"
                .to_owned();

        let descriptors = get_descriptors(mnemonic, Network::Bitcoin, None).unwrap();

        assert_eq!(descriptors[0].descriptor_xprv, "sh(wpkh(xprv9s21ZrQH143K2v9ABLJujuoqaJoMuazgoH6Yg4CceWQr86hPGbE5g6ivqRnPPGTnt6GqZVTFecYEUzkB9rzj79jGenWLW9GVsG5i6CKmMAE/49'/0'/0'/0/*))#a63aag5e".to_owned());
        assert_eq!(descriptors[0].change_descriptor_xprv, "sh(wpkh(xprv9s21ZrQH143K2v9ABLJujuoqaJoMuazgoH6Yg4CceWQr86hPGbE5g6ivqRnPPGTnt6GqZVTFecYEUzkB9rzj79jGenWLW9GVsG5i6CKmMAE/49'/0'/0'/1/*))#meecx9ld".to_owned());
        assert_eq!(descriptors[0].descriptor_xpub, "sh(wpkh([be83839f/49'/0'/0']xpub6DVS1Y45d3QdMLPGT8U1sRRe5XRQJx89xPY7MMqRUzjD7euk63KCKvq4Nxzu9mHdQGLcBmhM8A3nSprmMQLZqQaciMEQUVxBm4hU7H3z35x/0/*))#z0v4lv5h".to_owned());
        assert_eq!(descriptors[0].change_descriptor_xpub, "sh(wpkh([be83839f/49'/0'/0']xpub6DVS1Y45d3QdMLPGT8U1sRRe5XRQJx89xPY7MMqRUzjD7euk63KCKvq4Nxzu9mHdQGLcBmhM8A3nSprmMQLZqQaciMEQUVxBm4hU7H3z35x/1/*))#hwzr8npg".to_owned());
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

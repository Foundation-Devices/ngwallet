use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::keys::bip39::{Language, Mnemonic};
use bdk_wallet::keys::{DerivableKey, DescriptorKey};
use bdk_wallet::miniscript::descriptor::DescriptorType;
use bdk_wallet::template::{Bip44, Bip48Member, Bip49, Bip84, Bip86, DescriptorTemplate, DescriptorTemplateOut};
use std::cmp::min;
use std::str::FromStr;

#[derive(Debug)]
pub struct Descriptors {
    pub bip: String,
    pub descriptor_xprv: String,
    pub change_descriptor_xprv: String,
    pub descriptor_xpub: String,
    pub change_descriptor_xpub: String,
    pub descriptor_type: DescriptorType,
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

#[derive(Debug)]
pub struct NgDescriptorTemplate {
    pub bip: String,
    pub receive_template: DescriptorTemplateOut,
    pub change_template: DescriptorTemplateOut,
}

pub fn get_seedword_suggestions(input: &str, nr_of_suggestions: usize) -> Vec<&str> {
    let list = Language::English.words_by_prefix(input);
    let count = min(nr_of_suggestions, list.len());
    list[..count].to_vec()
}

#[cfg(feature = "envoy")]
pub fn get_random_seed() -> anyhow::Result<String> {
    let mnemonic = Mnemonic::generate_in(Language::English, 12)?;
    Ok(mnemonic.to_string())
}

pub fn get_seed_string(prime_master_seed: [u8; 72]) -> anyhow::Result<String> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &prime_master_seed[0..32])?;
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
        NgDescriptorTemplate {
            bip: String::from("49"),
            receive_template: Bip49(xprv, KeychainKind::External).build(network)?,
            change_template: Bip49(xprv, KeychainKind::Internal).build(network)?,
        },
        NgDescriptorTemplate {
            bip: String::from("44"),
            receive_template: Bip44(xprv, KeychainKind::External).build(network)?,
            change_template: Bip44(xprv, KeychainKind::Internal).build(network)?,
        },
        NgDescriptorTemplate {
            bip: String::from("84"),
            receive_template: Bip84(xprv, KeychainKind::External).build(network)?,
            change_template: Bip84(xprv, KeychainKind::Internal).build(network)?,
        },
        NgDescriptorTemplate {
            bip: String::from("86"),
            receive_template: Bip86(xprv, KeychainKind::External).build(network)?,
            change_template: Bip86(xprv, KeychainKind::Internal).build(network)?,
        },
        NgDescriptorTemplate {
            bip: String::from("48_1"),
            receive_template: Bip48Member(xprv, KeychainKind::External, 1).build(network)?,
            change_template: Bip48Member(xprv, KeychainKind::Internal, 1).build(network)?,
        },
        NgDescriptorTemplate {
            bip: String::from("48_2"),
            receive_template: Bip48Member(xprv, KeychainKind::External, 2).build(network)?,
            change_template: Bip48Member(xprv, KeychainKind::Internal, 2).build(network)?,
        },
    ];

    for template in descriptor_templates {
        let (bip, descriptor, key_map, change_descriptor, change_key_map) =
            (template.bip, template.receive_template.0, template.receive_template.1, template.change_template.0, template.change_template.1);

        descriptors.push(Descriptors {
            bip,
            descriptor_xprv: descriptor.to_string_with_secret(&key_map),
            change_descriptor_xprv: change_descriptor.to_string_with_secret(&change_key_map),
            descriptor_xpub: descriptor.to_string(),
            change_descriptor_xpub: change_descriptor.to_string(),
            descriptor_type: descriptor.desc_type(),
        });
    }

    Ok(descriptors)
}

#[cfg(test)]
mod test {
    use crate::bip39::get_descriptors;

    #[cfg(feature = "envoy")]
    use crate::bip39::get_random_seed;

    use bdk_wallet::bitcoin::Network;

    #[test]
    fn test_get_descriptor_from_seed() {
        let mnemonic =
            "axis minimum please frozen option smooth alone identify term fatigue crisp entry"
                .to_owned();

        let descriptors = get_descriptors(mnemonic, Network::Bitcoin, None).unwrap();

        assert_eq!(descriptors[0].descriptor_xprv, "sh(wpkh(xprv9s21ZrQH143K4EyEi77g3rpPu5byQ3EnnMJ4Y2KRNFp5Z4hin7er2j1VEtW92DfDyLGaXvv7LAnMbeHLwWSkv3WJjNhXDhjV7up579LwqWK/49'/0'/0'/0/*))#ujfh5d2y".to_owned());
        assert_eq!(descriptors[0].change_descriptor_xprv, "sh(wpkh(xprv9s21ZrQH143K4EyEi77g3rpPu5byQ3EnnMJ4Y2KRNFp5Z4hin7er2j1VEtW92DfDyLGaXvv7LAnMbeHLwWSkv3WJjNhXDhjV7up579LwqWK/49'/0'/0'/1/*))#63pj0qps".to_owned());
        assert_eq!(descriptors[0].descriptor_xpub, "sh(wpkh([ab88de89/49'/0'/0']xpub6CpdbYf1vdUMh5ryZWEQBoBVvmTTFYdi92VvknfMeVsgjiXXnmyDrCdkUKLzvEUYgBJrvyb3pmW488dctFrfJ1RaVNPa1T1nmraemfFCbuY/0/*))#k4daxnp5".to_owned());
        assert_eq!(descriptors[0].change_descriptor_xpub, "sh(wpkh([ab88de89/49'/0'/0']xpub6CpdbYf1vdUMh5ryZWEQBoBVvmTTFYdi92VvknfMeVsgjiXXnmyDrCdkUKLzvEUYgBJrvyb3pmW488dctFrfJ1RaVNPa1T1nmraemfFCbuY/1/*))#r5rt7v5t".to_owned());

        assert_eq!(descriptors[4].descriptor_xpub, "pkh([ab88de89/48'/0'/0'/1']xpub6EPJuK8Ejz82itf1fRUaHE3VXoPfVCJbW6MndSdcAzcxTMnixnWHJeMAVLw7iEMSJd1GmHUinhDEHoNKXAWwdhmTvgQiDTkHprTvmnE4AcB/0/*)#w4yvp7z8".to_owned());
        assert_eq!(descriptors[4].change_descriptor_xpub, "pkh([ab88de89/48'/0'/0'/1']xpub6EPJuK8Ejz82itf1fRUaHE3VXoPfVCJbW6MndSdcAzcxTMnixnWHJeMAVLw7iEMSJd1GmHUinhDEHoNKXAWwdhmTvgQiDTkHprTvmnE4AcB/1/*)#lppdutjl".to_owned());

        assert_eq!(descriptors[5].descriptor_xpub, "pkh([ab88de89/48'/0'/0'/2']xpub6EPJuK8Ejz82nKc7PsRgcYqdcQH9G1ZikCTasr9i79CbXxMMiPfxEyA14S6HPTHufmcQR7x8t5L3BP9tRfm9EBRBPic2xV892j9z4ePESae/0/*)#7gv8p6fu".to_owned());
        assert_eq!(descriptors[5].change_descriptor_xpub, "pkh([ab88de89/48'/0'/0'/2']xpub6EPJuK8Ejz82nKc7PsRgcYqdcQH9G1ZikCTasr9i79CbXxMMiPfxEyA14S6HPTHufmcQR7x8t5L3BP9tRfm9EBRBPic2xV892j9z4ePESae/1/*)#0ufxu0ey".to_owned());
    }

    #[cfg(feature = "envoy")]
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

use bdk_wallet::KeychainKind;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::bitcoin::bip32;
use bdk_wallet::bitcoin::bip32::{Fingerprint, Xpriv};
use bdk_wallet::bitcoin::secp256k1::{Secp256k1, Signing};
use bdk_wallet::descriptor::ExtendedDescriptor;
use bdk_wallet::keys::KeyMap;
use bdk_wallet::keys::bip39;
use bdk_wallet::keys::bip39::{Language, Mnemonic};
use bdk_wallet::miniscript::descriptor::DescriptorType;
use bdk_wallet::template::{
    Bip44, Bip48Member, Bip49, Bip84, Bip86, DescriptorTemplateOut,
};
use std::cmp::min;
use thiserror::Error;
use zeroize::ZeroizeOnDrop;
use crate::config::AddressType;

/// A master key for a given BIP-0039 mnemonic seed.
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct MasterKey {
    /// The mnemonic itself.
    pub mnemonic: String,
    /// The BIP-0032 master key.
    pub key: Key,
    /// The computed fingerprint from `xpriv`.
    #[zeroize(skip)]
    pub fingerprint: Fingerprint,
}

impl MasterKey {
    /// Compute the master key from the entropy.
    pub fn from_entropy<C>(
        secp: &Secp256k1<C>,
        network: impl Into<Network>,
        entropy: &[u8],
        passphrase: &str,
        bip85: Option<(WordCount, u32)>,
    ) -> Result<Self, Error>
    where
        C: Signing,
    {
        let network = network.into();
        let mnemonic = Mnemonic::from_entropy(entropy)?;
        let key = mnemonic.to_seed(passphrase);
        let xpriv = Xpriv::new_master(network, &key)?;
        let fingerprint = xpriv.fingerprint(secp);

        if let Some((word_count, index)) = bip85 {
            // Once the bip85 crate implements std::error::Error add
            // #[from] in the error enum.
            let bip85_mnemonic = bip85::to_mnemonic(secp, &xpriv, word_count.into(), index)
                .map_err(|_| Error::Bip85)?;
            let bip85_key = bip85_mnemonic.to_seed("");
            let bip85_xpriv = Xpriv::new_master(network, &bip85_key)?;
            let bip85_fingerprint = bip85_xpriv.fingerprint(secp);

            Ok(Self {
                mnemonic: bip85_mnemonic.to_string(),
                key: Key(bip85_key),
                fingerprint: bip85_fingerprint,
            })
        } else {
            Ok(Self {
                mnemonic: mnemonic.to_string(),
                key: Key(key),
                fingerprint,
            })
        }
    }
}

pub const KEY_LEN: usize = 64;

#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct Key(pub [u8; KEY_LEN]);

/// The word count of a mnemonic seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordCount {
    /// 12.
    Twelve,
    /// 18.
    Eighteen,
    /// 24.
    TwentyFour,
}

impl From<WordCount> for u32 {
    fn from(v: WordCount) -> u32 {
        match v {
            WordCount::Twelve => 12,
            WordCount::Eighteen => 18,
            WordCount::TwentyFour => 24,
        }
    }
}

/// Errors that can occur when computing the master key.
#[derive(Debug, Error)]
pub enum Error {
    #[error("couldn't derive key: {0}")]
    Bip32(#[from] bip32::Error),

    #[error("couldn't create mnemonic: {0}")]
    Bip39(#[from] bip39::Error),

    #[error("couldn't derive seed")]
    Bip85,
}

#[derive(Debug, PartialEq)]
pub struct Descriptors {
    pub bip: String,
    pub export_addr_hint: AddressType,
    pub descriptor: (ExtendedDescriptor, KeyMap),
    pub change_descriptor: (ExtendedDescriptor, KeyMap),
    pub descriptor_type: DescriptorType,
}

impl Descriptors {
    pub fn bip(&self) -> &str {
        &self.bip
    }

    pub fn descriptor_xprv(&self) -> String {
        let (desc, map) = &self.descriptor;
        desc.to_string_with_secret(map)
    }

    pub fn change_descriptor_xprv(&self) -> String {
        let (desc, map) = &self.change_descriptor;
        desc.to_string_with_secret(map)
    }

    pub fn descriptor_xpub(&self) -> String {
        self.descriptor.0.to_string()
    }

    pub fn change_descriptor_xpub(&self) -> String {
        self.change_descriptor.0.to_string()
    }
}

#[derive(Debug)]
pub struct NgDescriptorTemplate {
    pub bip: String,
    pub export_addr_hint: AddressType,
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

pub fn get_descriptors(seed: &[u8], network: Network, account_index: u32) -> anyhow::Result<Vec<Descriptors>> {
    let xprv: Xpriv = Xpriv::new_master(network, seed)?;

    let mut descriptors = vec![];

    let descriptor_templates = vec![
        NgDescriptorTemplate {
            bip: String::from("49"),
            export_addr_hint: AddressType::P2ShWpkh,
            receive_template: Bip49(xprv, KeychainKind::External).build_account(network, account_index)?,
            change_template: Bip49(xprv, KeychainKind::Internal).build_account(network, account_index)?,
        },
        NgDescriptorTemplate {
            bip: String::from("44"),
            export_addr_hint: AddressType::P2pkh,
            receive_template: Bip44(xprv, KeychainKind::External).build_account(network, account_index)?,
            change_template: Bip44(xprv, KeychainKind::Internal).build_account(network, account_index)?,
        },
        NgDescriptorTemplate {
            bip: String::from("84"),
            export_addr_hint: AddressType::P2wpkh,
            receive_template: Bip84(xprv, KeychainKind::External).build_account(network, account_index)?,
            change_template: Bip84(xprv, KeychainKind::Internal).build_account(network, account_index)?,
        },
        NgDescriptorTemplate {
            bip: String::from("86"),
            export_addr_hint: AddressType::P2tr,
            receive_template: Bip86(xprv, KeychainKind::External).build_account(network, account_index)?,
            change_template: Bip86(xprv, KeychainKind::Internal).build_account(network, account_index)?,
        },
        NgDescriptorTemplate {
            bip: String::from("48_1"),
            export_addr_hint: AddressType::P2ShWsh,
            receive_template: Bip48Member(xprv, KeychainKind::External, 1).build_account(network, account_index)?,
            change_template: Bip48Member(xprv, KeychainKind::Internal, 1).build_account(network, account_index)?,
        },
        NgDescriptorTemplate {
            bip: String::from("48_2"),
            export_addr_hint: AddressType::P2wsh,
            receive_template: Bip48Member(xprv, KeychainKind::External, 2).build_account(network, account_index)?,
            change_template: Bip48Member(xprv, KeychainKind::Internal, 2).build_account(network, account_index)?,
        },
        NgDescriptorTemplate {
            bip: String::from("48_3"),
            export_addr_hint: AddressType::P2sh,
            receive_template: Bip48Member(xprv, KeychainKind::External, 3).build_account(network, account_index)?,
            change_template: Bip48Member(xprv, KeychainKind::Internal, 3).build_account(network, account_index)?,
        },
    ];

    for template in descriptor_templates {
        let (bip, export_addr_hint, descriptor, key_map, change_descriptor, change_key_map) = (
            template.bip,
            template.export_addr_hint,
            template.receive_template.0,
            template.receive_template.1,
            template.change_template.0,
            template.change_template.1,
        );

        descriptors.push(Descriptors {
            descriptor_type: descriptor.desc_type(),
            bip,
            export_addr_hint,
            descriptor: (descriptor, key_map),
            change_descriptor: (change_descriptor, change_key_map),
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
    use bip85::bip39::Mnemonic;

    #[test]
    fn test_get_descriptor_from_seed() {
        let seed = Mnemonic::parse(
            "axis minimum please frozen option smooth alone identify term fatigue crisp entry",
        )
        .unwrap()
        .to_seed("");

        let descriptors = get_descriptors(&seed, Network::Bitcoin, 0).unwrap();

        assert_eq!(descriptors[0].descriptor_xprv(), "sh(wpkh(xprv9s21ZrQH143K4EyEi77g3rpPu5byQ3EnnMJ4Y2KRNFp5Z4hin7er2j1VEtW92DfDyLGaXvv7LAnMbeHLwWSkv3WJjNhXDhjV7up579LwqWK/49'/0'/0'/0/*))#ujfh5d2y".to_owned());
        assert_eq!(descriptors[0].change_descriptor_xprv(), "sh(wpkh(xprv9s21ZrQH143K4EyEi77g3rpPu5byQ3EnnMJ4Y2KRNFp5Z4hin7er2j1VEtW92DfDyLGaXvv7LAnMbeHLwWSkv3WJjNhXDhjV7up579LwqWK/49'/0'/0'/1/*))#63pj0qps".to_owned());
        assert_eq!(descriptors[0].descriptor_xpub(), "sh(wpkh([ab88de89/49'/0'/0']xpub6CpdbYf1vdUMh5ryZWEQBoBVvmTTFYdi92VvknfMeVsgjiXXnmyDrCdkUKLzvEUYgBJrvyb3pmW488dctFrfJ1RaVNPa1T1nmraemfFCbuY/0/*))#k4daxnp5".to_owned());
        assert_eq!(descriptors[0].change_descriptor_xpub(), "sh(wpkh([ab88de89/49'/0'/0']xpub6CpdbYf1vdUMh5ryZWEQBoBVvmTTFYdi92VvknfMeVsgjiXXnmyDrCdkUKLzvEUYgBJrvyb3pmW488dctFrfJ1RaVNPa1T1nmraemfFCbuY/1/*))#r5rt7v5t".to_owned());

        assert_eq!(descriptors[4].descriptor_xpub(), "pkh([ab88de89/48'/0'/0'/1']xpub6EPJuK8Ejz82itf1fRUaHE3VXoPfVCJbW6MndSdcAzcxTMnixnWHJeMAVLw7iEMSJd1GmHUinhDEHoNKXAWwdhmTvgQiDTkHprTvmnE4AcB/0/*)#w4yvp7z8".to_owned());
        assert_eq!(descriptors[4].change_descriptor_xpub(), "pkh([ab88de89/48'/0'/0'/1']xpub6EPJuK8Ejz82itf1fRUaHE3VXoPfVCJbW6MndSdcAzcxTMnixnWHJeMAVLw7iEMSJd1GmHUinhDEHoNKXAWwdhmTvgQiDTkHprTvmnE4AcB/1/*)#lppdutjl".to_owned());

        assert_eq!(descriptors[5].descriptor_xpub(), "pkh([ab88de89/48'/0'/0'/2']xpub6EPJuK8Ejz82nKc7PsRgcYqdcQH9G1ZikCTasr9i79CbXxMMiPfxEyA14S6HPTHufmcQR7x8t5L3BP9tRfm9EBRBPic2xV892j9z4ePESae/0/*)#7gv8p6fu".to_owned());
        assert_eq!(descriptors[5].change_descriptor_xpub(), "pkh([ab88de89/48'/0'/0'/2']xpub6EPJuK8Ejz82nKc7PsRgcYqdcQH9G1ZikCTasr9i79CbXxMMiPfxEyA14S6HPTHufmcQR7x8t5L3BP9tRfm9EBRBPic2xV892j9z4ePESae/1/*)#0ufxu0ey".to_owned());
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
